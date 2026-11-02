//! A Locksmith stand-in for tests and rehearsals: an in-process server that applies every
//! rule upstream's `locksmithd` applies to a share submission, over a synthetic attestation.
//!
//! Only a Nitro enclave can produce a real attestation (QEMU has no NSM), so the document here
//! is signed with a public test leaf certificate under a test root, both from bootproof's
//! historical-verification fixtures; a client verifies it with [`Verifier::with_root`] at a
//! time inside the leaf's validity ([`TEST_TIME`]). Everything else is the real protocol:
//! the frames, the session key, the holder signature and its clock rule, the hex and AEAD
//! failures that close the socket, each rejection with upstream's reason text, the share count
//! and the recovered secret's check. The module also generates quorums in keyfork's shardfile
//! layout, so the decoder is exercised against an independent encoder as well as against the
//! sequoia-made fixture.

use crate::bundle::{Bundle, Metadata};
use crate::holder::verify_detached;
use crate::nitro::PCR_LEN;
use crate::protocol::{
    read_frame, write_frame, AttestationResponse, EncryptedRequest, NonceRequest, Reply, Session,
    ShareRequest, SignedRequest, FIRST_FRAME_TIMEOUT,
};
use ciborium::value::Value;
use coset::{iana, CborSerializable, CoseSign1Builder, HeaderBuilder};
use pgp::composed::{MessageBuilder, SignedPublicKey, SignedSecretKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::ser::Serialize as _;
use pgp::types::{KeyDetails, Password};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use x25519_dalek::{EphemeralSecret, PublicKey};

/// bootproof's synthetic P-384 root (valid 2020-01-01 to 2040-01-01) and the leaf it issued
/// (valid 2025-12-23 17:06:00 to 20:06:03 UTC), with the leaf's PKCS#8 key: public test data,
/// never trusted by [`Verifier::aws`].
pub const TEST_ROOT: &[u8] =
    include_bytes!("../tests/fixtures/attestation/historical-test-root.der");
pub const TEST_LEAF: &[u8] =
    include_bytes!("../tests/fixtures/attestation/historical-test-leaf.der");
pub const TEST_KEY: &[u8] = include_bytes!("../tests/fixtures/attestation/historical-test-key.pk8");
/// A time inside the test leaf's validity, for the client's live check and the document's
/// timestamp.
pub const TEST_TIME: Duration = Duration::from_secs(1_766_510_000);
/// The PCRs the test server attests by default.
pub const TEST_PCRS: [[u8; PCR_LEN]; 3] = [[0xab; PCR_LEN], [0xcd; PCR_LEN], [0xef; PCR_LEN]];

/// Shamir's secret sharing over GF(2^8) as `sharks` (and its fork `blahaj`, which Locksmith
/// and keyfork use) define it: the field is reduced by the primitive polynomial 0x11d
/// (x^8 + x^4 + x^3 + x^2 + 1, Reed-Solomon's, not AES's 0x11b), and a share is the coordinate
/// `x` followed by one polynomial evaluation per secret byte. The fixture test pins the field
/// against a bundle blahaj dealt.
pub mod shamir {
    fn mul(mut a: u8, mut b: u8) -> u8 {
        let mut p = 0u8;
        while b != 0 {
            if b & 1 != 0 {
                p ^= a;
            }
            let carry = a & 0x80 != 0;
            a <<= 1;
            if carry {
                a ^= 0x1d;
            }
            b >>= 1;
        }
        p
    }

    fn inv(a: u8) -> u8 {
        // a^254 in GF(2^8).
        let mut result = 1u8;
        let mut base = a;
        let mut exp = 254u32;
        while exp > 0 {
            if exp & 1 != 0 {
                result = mul(result, base);
            }
            base = mul(base, base);
            exp >>= 1;
        }
        result
    }

    /// Deal `n` shares of a 32-byte secret with threshold `k`: coordinates 1..=n.
    pub fn deal(secret: &[u8; 32], k: u8, n: u8) -> Vec<[u8; 33]> {
        assert!(k >= 1 && n >= k);
        let coefficients: Vec<Vec<u8>> = (0..32)
            .map(|_| (1..k).map(|_| rand::random::<u8>()).collect())
            .collect();
        (1..=n)
            .map(|x| {
                let mut share = [0u8; 33];
                share[0] = x;
                for (i, byte) in secret.iter().enumerate() {
                    let mut y = *byte;
                    let mut power = x;
                    for c in &coefficients[i] {
                        y ^= mul(*c, power);
                        power = mul(power, x);
                    }
                    share[i + 1] = y;
                }
                share
            })
            .collect()
    }

    /// Recover the secret from exactly `k` distinct shares (Lagrange interpolation at 0).
    pub fn recover(shares: &[[u8; 33]], k: u8) -> Option<[u8; 32]> {
        if shares.len() < usize::from(k) || k == 0 {
            return None;
        }
        let shares = &shares[..usize::from(k)];
        let mut secret = [0u8; 32];
        for (i, share) in shares.iter().enumerate() {
            let xi = share[0];
            let mut weight = 1u8;
            for (j, other) in shares.iter().enumerate() {
                if i == j {
                    continue;
                }
                let xj = other[0];
                if xi == xj {
                    return None;
                }
                weight = mul(weight, mul(xj, inv(xi ^ xj)));
            }
            for b in 0..32 {
                secret[b] ^= mul(weight, share[b + 1]);
            }
        }
        Some(secret)
    }
}

/// A generated quorum: the raw V0 bundle, every holder's secret key, the dealt secret.
pub struct Fixture {
    pub bundle_json: String,
    pub holders: Vec<SignedSecretKey>,
    pub holder_certs: Vec<SignedPublicKey>,
    pub signer: SignedSecretKey,
    pub secret: [u8; 32],
    pub threshold: u8,
}

fn armor(packets: &[u8], typ: pgp::armor::BlockType) -> String {
    struct Raw<'a>(&'a [u8]);
    impl pgp::ser::Serialize for Raw<'_> {
        fn to_writer<W: std::io::Write>(&self, w: &mut W) -> pgp::errors::Result<()> {
            w.write_all(self.0)?;
            Ok(())
        }
        fn write_len(&self) -> usize {
            self.0.len()
        }
    }
    let mut out = Vec::new();
    pgp::armor::write(&Raw(packets), typ, &mut out, None, true).expect("armor");
    String::from_utf8(out).expect("armor is ASCII")
}

fn storage_key(cert: &SignedPublicKey) -> &pgp::packet::PublicSubkey {
    &cert
        .public_subkeys
        .iter()
        .find(|s| {
            s.signatures
                .iter()
                .any(|sig| sig.key_flags().encrypt_storage())
        })
        .expect("a storage-encryption subkey")
        .key
}

/// Generate a quorum of `names.len()` holders with threshold `threshold`, in keyfork's layout.
pub fn make_fixture(names: &[&str], threshold: u8) -> Fixture {
    let mut rng = rand::rngs::OsRng;
    let holders: Vec<SignedSecretKey> = names
        .iter()
        .map(|n| crate::test_keys::generate(n))
        .collect();
    let holder_certs: Vec<SignedPublicKey> =
        holders.iter().map(SignedSecretKey::to_public_key).collect();
    let signer = crate::test_keys::generate("keyfork-sss");
    let quorum = crate::test_keys::generate("Keymaker-generated key");
    let secret: [u8; 32] = rand::random();
    let shares = shamir::deal(&secret, threshold, names.len() as u8);

    let mut metadata = vec![1u8, threshold];
    metadata.extend(signer.to_public_key().to_bytes().expect("serialize"));
    for cert in &holder_certs {
        metadata.extend(cert.to_bytes().expect("serialize"));
    }
    let mut builder =
        MessageBuilder::from_bytes("", metadata).seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
    for cert in &holder_certs {
        builder
            .encrypt_to_key_anonymous(&mut rng, storage_key(cert))
            .expect("encrypt");
    }
    let mut shardfile = builder.to_vec(rng).expect("metadata message");
    for (cert, share) in holder_certs.iter().zip(&shares) {
        let mut builder = MessageBuilder::from_bytes("", share.to_vec())
            .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        builder
            .encrypt_to_key_anonymous(&mut rng, storage_key(cert))
            .expect("encrypt");
        builder.sign(
            &signer.primary_key,
            Password::empty(),
            HashAlgorithm::Sha512,
        );
        shardfile.extend(builder.to_vec(rng).expect("share message"));
    }
    let shardfile = armor(&shardfile, pgp::armor::BlockType::Message);

    // keymaker v0 wrote the keyring in whatever order its key discovery produced: not shard
    // order. Reverse it here so a decoder that assumed file order would fail the tests.
    let mut keyring_packets = Vec::new();
    for cert in holder_certs.iter().rev() {
        keyring_packets.extend(cert.to_bytes().expect("serialize"));
    }
    let keyring = armor(&keyring_packets, pgp::armor::BlockType::PublicKey);
    let bundle = serde_json::json!({
        "label": {"name": "rose-petal test quorum"},
        "keyring": keyring,
        "keyring_hash": Sha256::digest(keyring.as_bytes()).to_vec(),
        "shardfile": shardfile,
        "public_key": quorum.to_public_key().to_armored_string(Default::default()).expect("armor"),
        "necroproof": [],
    });
    Fixture {
        bundle_json: serde_json::to_string_pretty(&bundle).expect("json"),
        holders,
        holder_certs,
        signer,
        secret,
        threshold,
    }
}

/// A synthetic attestation document over the test leaf: the fields a real one has, with
/// `cabundle` holding the test root as AWS's documents hold theirs.
pub fn attest(
    pcrs: &[[u8; PCR_LEN]; 3],
    user_data: &[u8],
    nonce: &[u8],
    timestamp: Duration,
) -> Vec<u8> {
    let rng = ring::rand::SystemRandom::new();
    let key = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
        TEST_KEY,
        &rng,
    )
    .expect("test key");
    let text = |s: &str| Value::Text(s.to_string());
    let payload = Value::Map(vec![
        (
            text("module_id"),
            text("i-0test0000000000-enc0123456789abcdef"),
        ),
        (text("digest"), text("SHA384")),
        (
            text("timestamp"),
            Value::Integer((timestamp.as_millis() as u64).into()),
        ),
        (
            text("pcrs"),
            Value::Map(
                pcrs.iter()
                    .enumerate()
                    .map(|(i, p)| (Value::Integer((i as u8).into()), Value::Bytes(p.to_vec())))
                    .collect(),
            ),
        ),
        (text("certificate"), Value::Bytes(TEST_LEAF.to_vec())),
        (
            text("cabundle"),
            Value::Array(vec![Value::Bytes(TEST_ROOT.to_vec())]),
        ),
        (text("public_key"), Value::Null),
        (text("user_data"), Value::Bytes(user_data.to_vec())),
        (text("nonce"), Value::Bytes(nonce.to_vec())),
    ]);
    let mut bytes = Vec::new();
    ciborium::into_writer(&payload, &mut bytes).expect("cbor");
    CoseSign1Builder::new()
        .protected(
            HeaderBuilder::new()
                .algorithm(iana::Algorithm::ES384)
                .build(),
        )
        .payload(bytes)
        .create_signature(&[], |message| {
            key.sign(&rng, message).expect("sign").as_ref().to_vec()
        })
        .build()
        .to_vec()
        .expect("cose")
}

/// What the server enforces: upstream's `Recovery`, with the synthetic attestation's inputs.
#[derive(Clone)]
pub struct ServerOptions {
    /// The holders in shard order (what the daemon has from the bundle).
    pub holders: Vec<SignedPublicKey>,
    pub threshold: u8,
    /// The bundle's content hash, when the daemon's bundle has one.
    pub bundle_hash: Option<String>,
    /// The secret the recovered shares must yield (the daemon derives the quorum certificate
    /// from it and compares fingerprints; here the secret itself is known).
    pub expected_secret: Option<[u8; 32]>,
    /// The server's clock, for the signature skew rule; `None` is the real clock.
    pub clock: Option<Duration>,
    pub pcrs: [[u8; PCR_LEN]; 3],
    pub attestation_time: Duration,
}

impl ServerOptions {
    pub fn for_fixture(fixture: &Fixture) -> Self {
        Self {
            holders: fixture.holder_certs.clone(),
            threshold: fixture.threshold,
            bundle_hash: None,
            expected_secret: Some(fixture.secret),
            clock: None,
            pcrs: TEST_PCRS,
            attestation_time: TEST_TIME,
        }
    }

    /// From a parsed bundle whose metadata a test has decrypted.
    pub fn for_bundle(
        bundle: &Bundle,
        metadata: &Metadata,
        expected_secret: Option<[u8; 32]>,
    ) -> Self {
        Self {
            holders: metadata.holders.clone(),
            threshold: metadata.threshold,
            bundle_hash: bundle.content_hash().expect("hash"),
            expected_secret,
            clock: None,
            pcrs: TEST_PCRS,
            attestation_time: TEST_TIME,
        }
    }
}

struct State {
    shares: Vec<[u8; 33]>,
    holders: HashSet<usize>,
    outcome: Option<Result<[u8; 32], String>>,
}

/// The running server.
pub struct TestServer {
    pub addr: SocketAddr,
    state: Arc<Mutex<State>>,
    task: tokio::task::JoinHandle<()>,
}

const MAX_SIGNATURE_FUTURE_SKEW_SECS: u64 = 60;

enum Outcome {
    Reply(Reply),
    Close,
}

async fn handle(
    mut stream: tokio::net::TcpStream,
    options: Arc<ServerOptions>,
    state: Arc<Mutex<State>>,
) -> Result<(), String> {
    let frame1 = tokio::time::timeout(FIRST_FRAME_TIMEOUT, read_frame(&mut stream))
        .await
        .map_err(|_| "first frame timeout")?
        .map_err(|e| e.to_string())?;
    let request: NonceRequest = serde_json::from_slice(&frame1).map_err(|e| e.to_string())?;
    let secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let public = PublicKey::from(&secret).to_bytes();
    let attestation = attest(
        &options.pcrs,
        &public,
        request.nonce.as_bytes(),
        options.attestation_time,
    );
    write_frame(
        &mut stream,
        &serde_json::to_vec(&AttestationResponse { attestation }).expect("json"),
    )
    .await
    .map_err(|e| e.to_string())?;
    let frame3 = read_frame(&mut stream).await.map_err(|e| e.to_string())?;
    let signed: SignedRequest = serde_json::from_slice(&frame3).map_err(|e| e.to_string())?;
    match submission(&signed, secret, &options, &state).await {
        Outcome::Reply(reply) => {
            write_frame(&mut stream, &serde_json::to_vec(&reply).expect("json"))
                .await
                .map_err(|e| e.to_string())?;
            Ok(())
        }
        Outcome::Close => Ok(()),
    }
}

fn authenticate(
    options: &ServerOptions,
    data: &str,
    signature: &str,
) -> Result<usize, &'static str> {
    let now = options
        .clock
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
        })
        .as_secs();
    let mut matched = None;
    let mut skew = false;
    for (index, cert) in options.holders.iter().enumerate() {
        let Ok(created) = verify_detached(cert, data, signature) else {
            continue;
        };
        if u64::from(created.as_secs()) < u64::from(cert.primary_key.created_at().as_secs()) {
            continue;
        }
        if u64::from(created.as_secs()).saturating_sub(now) > MAX_SIGNATURE_FUTURE_SKEW_SECS {
            skew = true;
            continue;
        }
        if matched.is_some() {
            return Err("Signature matches multiple bundle holders");
        }
        matched = Some(index);
    }
    match (matched, skew) {
        (Some(index), _) => Ok(index),
        (None, true) => Err("Signature is more than 60 seconds ahead of the enclave clock; check signer and enclave clocks"),
        (None, false) => Err("Signature did not verify for any bundle holder"),
    }
}

async fn submission(
    signed: &SignedRequest,
    secret: EphemeralSecret,
    options: &ServerOptions,
    state: &Mutex<State>,
) -> Outcome {
    let holder = match authenticate(options, &signed.signed_payload, &signed.signature) {
        Ok(h) => h,
        Err(reason) => {
            return Outcome::Reply(Reply::Rejected {
                reason: reason.into(),
            })
        }
    };
    let Ok(encrypted) = serde_json::from_str::<EncryptedRequest>(&signed.signed_payload) else {
        return Outcome::Close;
    };
    let Ok(session) = Session::server(secret, encrypted.public_key) else {
        return Outcome::Close;
    };
    let Ok(ciphertext) = hex::decode(&encrypted.encrypted_payload) else {
        return Outcome::Close;
    };
    let Some(plaintext) = session.decrypt(&ciphertext) else {
        return Outcome::Close;
    };
    let Ok(request) = serde_json::from_slice::<ShareRequest>(&plaintext) else {
        return Outcome::Reply(Reply::Rejected {
            reason: "Malformed share request".into(),
        });
    };
    let mut state = state.lock().await;
    if state.outcome.is_some() {
        return Outcome::Close;
    }
    let reason = if options.bundle_hash.is_some()
        && request.bundle_hash.is_some()
        && request.bundle_hash != options.bundle_hash
    {
        Some("Share was dealt from a different bundle")
    } else if request.threshold != options.threshold {
        Some("Threshold does not match the verified bundle")
    } else if holder >= options.holders.len() {
        Some("Unknown holder")
    } else if request.shard.len() != 33 || request.shard[0] == 0 {
        Some("Malformed share: expected a nonzero coordinate and 32 bytes")
    } else if usize::from(request.shard[0]) != holder + 1 {
        Some("Share coordinate does not match the holder's bundle position")
    } else if state.holders.contains(&holder) {
        Some("Holder already contributed a share")
    } else {
        None
    };
    if let Some(reason) = reason {
        return Outcome::Reply(Reply::Rejected {
            reason: reason.into(),
        });
    }
    let share: [u8; 33] = request
        .shard
        .as_slice()
        .try_into()
        .expect("33 bytes checked");
    state.holders.insert(holder);
    state.shares.push(share);
    let remaining = options.threshold - state.shares.len() as u8;
    if remaining > 0 {
        return Outcome::Reply(Reply::Accepted { remaining });
    }
    let recovered = shamir::recover(&state.shares, options.threshold);
    let result = match (recovered, options.expected_secret) {
        (Some(secret), Some(expected)) if secret != expected => {
            Err("Recovered secret does not match the bundle public key".to_string())
        }
        (Some(secret), _) => Ok(secret),
        (None, _) => Err("Recovered secret does not match the bundle public key".to_string()),
    };
    let reply = match &result {
        Ok(_) => Reply::Accepted { remaining: 0 },
        Err(reason) => Reply::Rejected {
            reason: reason.clone(),
        },
    };
    state.outcome = Some(result);
    Outcome::Reply(reply)
}

impl TestServer {
    /// Bind a loopback port and serve until [`TestServer::finish`] or the quorum completes.
    pub async fn start(options: ServerOptions) -> Self {
        Self::start_on("127.0.0.1:0", options)
            .await
            .expect("bind a loopback port")
    }

    /// Bind `listen` (`host:port`, port 0 for any) and serve.
    pub async fn start_on(listen: &str, options: ServerOptions) -> Result<Self, String> {
        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .map_err(|e| format!("bind {listen}: {e}"))?;
        let addr = listener.local_addr().map_err(|e| e.to_string())?;
        let state = Arc::new(Mutex::new(State {
            shares: Vec::new(),
            holders: HashSet::new(),
            outcome: None,
        }));
        let options = Arc::new(options);
        let task = {
            let state = state.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
                    };
                    let (options, state) = (options.clone(), state.clone());
                    tokio::spawn(async move {
                        let _ = tokio::time::timeout(
                            Duration::from_secs(30),
                            handle(stream, options, state),
                        )
                        .await;
                    });
                }
            })
        };
        Ok(Self { addr, state, task })
    }

    /// Serve until the quorum completes (or fails), then stop and report.
    pub async fn wait(self) -> Result<[u8; 32], String> {
        loop {
            if let Some(outcome) = self.state.lock().await.outcome.clone() {
                self.task.abort();
                return outcome;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// The shares counted so far.
    pub async fn shares(&self) -> Vec<[u8; 33]> {
        self.state.lock().await.shares.clone()
    }

    /// Stop serving; the recovered secret if the quorum completed, its failure if it failed,
    /// `None` if it never completed.
    pub async fn finish(self) -> Option<Result<[u8; 32], String>> {
        self.task.abort();
        let state = self.state.lock().await;
        state.outcome.clone()
    }
}

/// The holder keyring that would be baked for the daemon: every holder certificate in shard
/// order, as [`ServerOptions::holders`] takes it.
pub fn holders_of(fixture: &Fixture) -> Vec<SignedPublicKey> {
    fixture.holder_certs.clone()
}

/// A convenience for tests: parse a fixture's bundle and decrypt its metadata with one holder.
pub fn metadata_of(fixture: &Fixture, holder: usize) -> (Bundle, Metadata) {
    let bundle = Bundle::from_json(&fixture.bundle_json).expect("bundle");
    let keyring = crate::holder::Keyring {
        keys: vec![fixture.holders[holder].clone()],
    };
    let metadata = keyring
        .decrypt_metadata(&bundle.shardfile().expect("shardfile"), &Password::empty())
        .expect("metadata");
    (bundle, metadata)
}

/// `HashMap` of label text, for callers building a bundle by hand.
pub fn label(name: &str) -> HashMap<String, String> {
    HashMap::from([("name".to_string(), name.to_string())])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::holder::{prepare, Keyring};
    use crate::nitro::{At, Pcrs, Verifier};
    use crate::protocol::{send_request, send_shard, Error, SendOptions};

    fn pcrs() -> Pcrs {
        Pcrs::new((0u8..3).map(|i| (i, TEST_PCRS[usize::from(i)])).collect()).unwrap()
    }

    fn options() -> SendOptions {
        SendOptions {
            pcrs: pcrs(),
            allow_zero_pcrs: false,
            verifier: Verifier::with_root(TEST_ROOT),
            at: Some(At::Live(TEST_TIME)),
            timeout: Duration::from_secs(10),
        }
    }

    fn keyring(fixture: &Fixture, i: usize) -> Keyring {
        Keyring {
            keys: vec![fixture.holders[i].clone()],
        }
    }

    #[test]
    fn shamir_recovers_the_locksmith_fixtures_secret() {
        // The sequoia-made 2-of-2 fixture was dealt from [7; 32] by blahaj: our GF(2^8) must
        // agree with it, share for share.
        let bundle = Bundle::from_json(crate::bundle::tests::RAW_V0).unwrap();
        let shares: Vec<[u8; 33]> = [crate::holder::tests::ALICE, crate::holder::tests::BOB]
            .iter()
            .map(|text| {
                prepare(
                    &bundle,
                    &Keyring {
                        keys: Keyring::parse(text).unwrap(),
                    },
                    None,
                    &Password::empty(),
                )
                .unwrap()
                .share
            })
            .collect();
        assert_eq!(shamir::recover(&shares, 2).unwrap(), [7u8; 32]);
        assert_ne!(shamir::recover(&shares[..1], 1).unwrap(), [7u8; 32]);
        let secret: [u8; 32] = rand::random();
        let dealt = shamir::deal(&secret, 3, 5);
        assert_eq!(
            shamir::recover(&[dealt[4], dealt[1], dealt[2]], 3).unwrap(),
            secret
        );
        assert_eq!(shamir::recover(&dealt[..3], 3).unwrap(), secret);
        assert!(shamir::recover(&dealt[..2], 3).is_none());
        assert!(shamir::recover(&[dealt[0], dealt[0]], 2).is_none());
    }

    #[test]
    fn generated_quorums_decode_like_keyforks() {
        for (names, threshold) in [
            (&["a"][..], 1u8),
            (&["a", "b", "c"][..], 2),
            (&["a", "b", "c", "d", "e"][..], 3),
        ] {
            let fixture = make_fixture(names, threshold);
            let bundle = Bundle::from_json(&fixture.bundle_json).unwrap();
            let mut shares = Vec::new();
            for (i, _) in names.iter().enumerate() {
                let holder_keys = keyring(&fixture, i);
                let release = prepare(&bundle, &holder_keys, None, &Password::empty()).unwrap();
                assert_eq!(release.holder.position, i);
                assert_eq!(release.metadata.threshold, threshold);
                assert_eq!(release.share[0], i as u8 + 1);
                shares.push(release.share);
            }
            assert_eq!(shamir::recover(&shares, threshold).unwrap(), fixture.secret);
            // The imported artifact round-trips through the same checks and hashes stably.
            let (_, metadata) = metadata_of(&fixture, 0);
            let imported = bundle.import(&metadata).unwrap();
            let text = serde_json::to_string(&imported).unwrap();
            let reparsed = Bundle::from_json(&text).unwrap();
            assert_eq!(
                reparsed.content_hash().unwrap(),
                Some(imported.content_hash().unwrap())
            );
            prepare(&reparsed, &keyring(&fixture, 0), None, &Password::empty()).unwrap();
        }
    }

    #[tokio::test]
    async fn two_of_three_releases_recover_the_secret() {
        let fixture = make_fixture(&["ann", "ben", "cat"], 2);
        let bundle = Bundle::from_json(&fixture.bundle_json).unwrap();
        let server = TestServer::start(ServerOptions::for_fixture(&fixture)).await;
        let ben = keyring(&fixture, 1);
        let release = prepare(&bundle, &ben, None, &Password::empty()).unwrap();
        assert_eq!(
            send_shard(server.addr, &release, None, &Password::empty(), &options())
                .await
                .unwrap(),
            Reply::Accepted { remaining: 1 }
        );
        // The same holder again is refused; a different one completes the quorum.
        assert_eq!(
            send_shard(server.addr, &release, None, &Password::empty(), &options())
                .await
                .unwrap(),
            Reply::Rejected {
                reason: "Holder already contributed a share".into()
            }
        );
        let cat = keyring(&fixture, 2);
        let release = prepare(&bundle, &cat, None, &Password::empty()).unwrap();
        assert_eq!(
            send_shard(server.addr, &release, None, &Password::empty(), &options())
                .await
                .unwrap(),
            Reply::Accepted { remaining: 0 }
        );
        // A late third holder meets a server whose quorum is complete: closed without a reply.
        let ann = keyring(&fixture, 0);
        let release = prepare(&bundle, &ann, None, &Password::empty()).unwrap();
        assert!(matches!(
            send_shard(server.addr, &release, None, &Password::empty(), &options()).await,
            Err(Error::ClosedWithoutReply)
        ));
        assert_eq!(server.finish().await, Some(Ok(fixture.secret)));
    }

    #[tokio::test]
    async fn one_of_one_with_an_imported_bundle_sends_and_checks_the_hash() {
        let fixture = make_fixture(&["solo"], 1);
        let (raw, metadata) = metadata_of(&fixture, 0);
        let imported = serde_json::to_string(&raw.import(&metadata).unwrap()).unwrap();
        let bundle = Bundle::from_json(&imported).unwrap();
        let hash = bundle.content_hash().unwrap();
        assert!(hash.is_some());
        let server = TestServer::start(ServerOptions::for_bundle(
            &bundle,
            &metadata,
            Some(fixture.secret),
        ))
        .await;
        let solo = keyring(&fixture, 0);
        let release = prepare(&bundle, &solo, None, &Password::empty()).unwrap();
        // A wrong hash is refused, an absent one is tolerated (an older client), the right one accepted.
        assert_eq!(
            send_shard(
                server.addr,
                &release,
                Some("ab".repeat(32)),
                &Password::empty(),
                &options()
            )
            .await
            .unwrap(),
            Reply::Rejected {
                reason: "Share was dealt from a different bundle".into()
            }
        );
        let server2 = TestServer::start(ServerOptions::for_bundle(
            &bundle,
            &metadata,
            Some(fixture.secret),
        ))
        .await;
        assert_eq!(
            send_shard(server2.addr, &release, None, &Password::empty(), &options())
                .await
                .unwrap(),
            Reply::Accepted { remaining: 0 }
        );
        assert_eq!(
            send_shard(server.addr, &release, hash, &Password::empty(), &options())
                .await
                .unwrap(),
            Reply::Accepted { remaining: 0 }
        );
        assert_eq!(server.finish().await, Some(Ok(fixture.secret)));
    }

    #[tokio::test]
    async fn every_rejection_reason_is_reproduced() {
        let fixture = make_fixture(&["ann", "ben"], 2);
        let bundle = Bundle::from_json(&fixture.bundle_json).unwrap();
        let ann = keyring(&fixture, 0);
        let release = prepare(&bundle, &ann, None, &Password::empty()).unwrap();
        let server = TestServer::start(ServerOptions::for_fixture(&fixture)).await;
        let send = |request: ShareRequest| {
            let release = &release;
            async move {
                send_request(
                    server.addr,
                    &request,
                    &release.holder,
                    &Password::empty(),
                    &options(),
                )
                .await
                .unwrap()
            }
        };
        let good = crate::protocol::share_request(&release.share, 2, None);
        assert_eq!(
            send(ShareRequest {
                threshold: 3,
                ..good.clone()
            })
            .await,
            Reply::Rejected {
                reason: "Threshold does not match the verified bundle".into()
            }
        );
        assert_eq!(
            send(ShareRequest {
                shard: vec![1; 32],
                ..good.clone()
            })
            .await,
            Reply::Rejected {
                reason: "Malformed share: expected a nonzero coordinate and 32 bytes".into()
            }
        );
        let mut wrong_coordinate = good.clone();
        wrong_coordinate.shard[0] = 2;
        assert_eq!(
            send(wrong_coordinate).await,
            Reply::Rejected {
                reason: "Share coordinate does not match the holder's bundle position".into()
            }
        );
        assert_eq!(send(good.clone()).await, Reply::Accepted { remaining: 1 });

        // Ben's share signed by an outsider: no holder verifies it.
        let outsider = Keyring {
            keys: vec![crate::test_keys::generate("outsider")],
        };
        let ben = keyring(&fixture, 1);
        let ben_release = prepare(&bundle, &ben, None, &Password::empty()).unwrap();
        let fake_metadata = Metadata {
            threshold: 2,
            signer: fixture.signer.to_public_key(),
            holders: vec![
                outsider.keys[0].to_public_key(),
                fixture.holder_certs[1].clone(),
            ],
        };
        let impostor = outsider.select(&fake_metadata, None).unwrap();
        let ben_request = crate::protocol::share_request(&ben_release.share, 2, None);
        assert_eq!(
            send_request(
                server.addr,
                &ben_request,
                &impostor,
                &Password::empty(),
                &options()
            )
            .await
            .unwrap(),
            Reply::Rejected {
                reason: "Signature did not verify for any bundle holder".into()
            }
        );
        // A server whose clock is two minutes behind sees our (backdated) signature as from the future.
        let behind = TestServer::start(ServerOptions {
            clock: Some(now() - Duration::from_secs(120)),
            ..ServerOptions::for_fixture(&fixture)
        })
        .await;
        assert_eq!(
            send_request(behind.addr, &ben_request, &ben_release.holder, &Password::empty(), &options()).await.unwrap(),
            Reply::Rejected { reason: "Signature is more than 60 seconds ahead of the enclave clock; check signer and enclave clocks".into() }
        );
        // One minute behind is within the tolerance thanks to the backdating.
        let slightly = TestServer::start(ServerOptions {
            clock: Some(now() - Duration::from_secs(60)),
            ..ServerOptions::for_fixture(&fixture)
        })
        .await;
        assert_eq!(
            send_request(
                slightly.addr,
                &ben_request,
                &ben_release.holder,
                &Password::empty(),
                &options()
            )
            .await
            .unwrap(),
            Reply::Accepted { remaining: 1 }
        );

        // The wrong share completes the quorum with the wrong secret.
        let other = make_fixture(&["x", "y"], 2);
        let mismatched = TestServer::start(ServerOptions {
            expected_secret: Some(other.secret),
            ..ServerOptions::for_fixture(&fixture)
        })
        .await;
        assert_eq!(
            send_request(
                mismatched.addr,
                &good,
                &release.holder,
                &Password::empty(),
                &options()
            )
            .await
            .unwrap(),
            Reply::Accepted { remaining: 1 }
        );
        assert_eq!(
            send_request(
                mismatched.addr,
                &ben_request,
                &ben_release.holder,
                &Password::empty(),
                &options()
            )
            .await
            .unwrap(),
            Reply::Rejected {
                reason: "Recovered secret does not match the bundle public key".into()
            }
        );
        assert!(matches!(mismatched.finish().await, Some(Err(_))));
    }

    fn now() -> Duration {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
    }

    #[tokio::test]
    async fn the_client_refuses_a_bad_attestation_before_sending_anything() {
        let fixture = make_fixture(&["ann"], 1);
        let bundle = Bundle::from_json(&fixture.bundle_json).unwrap();
        let ann = keyring(&fixture, 0);
        let release = prepare(&bundle, &ann, None, &Password::empty()).unwrap();
        let server = TestServer::start(ServerOptions::for_fixture(&fixture)).await;
        // Wrong PCRs.
        let mut wrong = options();
        wrong.pcrs = Pcrs::new((0u8..3).map(|i| (i, [0x11; 48])).collect()).unwrap();
        assert!(matches!(
            send_shard(server.addr, &release, None, &Password::empty(), &wrong).await,
            Err(Error::Attestation(crate::nitro::Error::PcrMismatch(0)))
        ));
        // The real root does not trust the test leaf.
        let mut aws = options();
        aws.verifier = Verifier::aws();
        assert!(matches!(
            send_shard(server.addr, &release, None, &Password::empty(), &aws).await,
            Err(Error::Attestation(crate::nitro::Error::Chain(_)))
        ));
        // A clock outside the leaf's validity.
        let mut late = options();
        late.at = Some(At::Live(TEST_TIME + Duration::from_secs(86400)));
        assert!(matches!(
            send_shard(server.addr, &release, None, &Password::empty(), &late).await,
            Err(Error::Attestation(crate::nitro::Error::Chain(_)))
        ));
        // Debug PCRs are refused without the explicit allowance, and never reach the network.
        let mut debug = options();
        debug.pcrs = Pcrs::new((0u8..3).map(|i| (i, [0; 48])).collect()).unwrap();
        assert!(matches!(
            send_shard(server.addr, &release, None, &Password::empty(), &debug).await,
            Err(Error::DebugEnclave)
        ));
        assert!(server.shares().await.is_empty());
        assert_eq!(
            send_shard(server.addr, &release, None, &Password::empty(), &options())
                .await
                .unwrap(),
            Reply::Accepted { remaining: 0 }
        );
    }

    #[tokio::test]
    async fn an_undecryptable_request_is_closed_without_a_reply() {
        let fixture = make_fixture(&["ann"], 1);
        let bundle = Bundle::from_json(&fixture.bundle_json).unwrap();
        let ann = keyring(&fixture, 0);
        let release = prepare(&bundle, &ann, None, &Password::empty()).unwrap();
        let server = TestServer::start(ServerOptions::for_fixture(&fixture)).await;
        let mut stream = tokio::net::TcpStream::connect(server.addr).await.unwrap();
        write_frame(
            &mut stream,
            &serde_json::to_vec(&NonceRequest {
                nonce: crate::protocol::fresh_nonce(),
            })
            .unwrap(),
        )
        .await
        .unwrap();
        read_frame(&mut stream).await.unwrap();
        // A well-signed payload whose ciphertext is not hex: the daemon closes the socket.
        let payload = serde_json::to_string(&EncryptedRequest {
            encrypted_payload: "zz".into(),
            public_key: [9; 32],
        })
        .unwrap();
        let signature = release.holder.sign(&payload, &Password::empty()).unwrap();
        write_frame(
            &mut stream,
            &serde_json::to_vec(&SignedRequest {
                signed_payload: payload,
                signature,
            })
            .unwrap(),
        )
        .await
        .unwrap();
        assert!(matches!(
            crate::protocol::read_reply(&mut stream, Duration::from_secs(5)).await,
            Err(Error::ClosedWithoutReply)
        ));
        assert!(server.shares().await.is_empty());
    }
}
