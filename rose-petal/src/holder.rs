//! This holder's part: their share out of the shardfile, and their signature over the request.
//!
//! A holder is an OpenPGP certificate in the bundle's keyring whose secret keys the holder
//! has, as a transferable secret key in a file (or a directory of files). Two of its keys
//! matter: a storage-encryption key, which decrypts the share; and a signing key, which signs
//! the request the enclave verifies against the same certificate. Both must be present as
//! secret keys, as upstream requires, so one certificate both decrypts and signs.
//!
//! Finding the share is: decrypt the metadata message (encrypted to every holder, so any of
//! the holder's keys will do), locate this holder's certificate among the metadata's holders
//! by fingerprint, decrypt the message at that position plus one, verify its inner signature
//! against the metadata's signing certificate (exactly one good signature), and check that the
//! share's coordinate is the position plus one. None of that is needed on the wire; it is
//! what makes a tampered bundle fail on the holder's machine instead of in the enclave.

use crate::bundle::{same_key, Bundle, EncryptedMessage, Metadata, Shardfile};
use pgp::composed::{
    ArmorOptions, Deserializable, DetachedSignature, Message, SignedPublicKey, SignedSecretKey,
    SubpacketConfig,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::packet::{Subpacket, SubpacketData};
use pgp::types::{KeyDetails, Password, SigningKey, Timestamp, VerifyingKey};
use std::io::Cursor;
use std::path::Path;
use std::time::{Duration, SystemTime};

/// Signatures are stamped this far in the past. The enclave's verifier refuses a signature
/// created after its own clock (the pinned daemon with no tolerance, upstream with a minute),
/// and a holder's clock can run ahead of the enclave's; a signature's creation time has no
/// other reader. The one bound the other way is the key's own creation, which the signer
/// clamps to.
pub const SIGNATURE_BACKDATE: Duration = Duration::from_secs(30);

/// The hash algorithms a signature may use, most preferred first. The certificate's own
/// preference list is honored among these; a certificate with none (keyfork's) gets SHA-512.
const ACCEPTED_HASHES: [HashAlgorithm; 3] = [
    HashAlgorithm::Sha512,
    HashAlgorithm::Sha384,
    HashAlgorithm::Sha256,
];

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("reading {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("OpenPGP: {0}")]
    OpenPgp(String),
    #[error("{0} holds no secret keys")]
    NoSecretKeys(String),
    #[error("none of the keyring's keys decrypts the shard metadata")]
    MetadataUndecryptable,
    #[error("no key in the keyring is a holder of this quorum with both a secret signing key and a secret storage-encryption key")]
    NoMatchingHolder,
    #[error("the selected holder {0} is not a holder of this quorum")]
    HolderNotInQuorum(String),
    #[error("the keyring holds no secret key for holder {0}")]
    HolderKeyMissing(String),
    #[error("the shardfile has no share at this holder's position")]
    ShareMissing,
    #[error("the share did not decrypt with this holder's key")]
    ShareUndecryptable,
    #[error("the share is not a one-pass signed literal with exactly one signature")]
    ShareSignatureCount,
    #[error("the share's signature is not by the quorum's signing certificate")]
    ShareSignature,
    #[error("the share is {len} bytes with coordinate {coordinate}; expected 33 bytes with coordinate {expected}")]
    ShareShape {
        len: usize,
        coordinate: u8,
        expected: u8,
    },
    #[error("the holder certificate has no signing key")]
    NoSigningKey,
    #[error("a secret key is locked and no passphrase was given")]
    Locked,
    #[error("the signature does not verify under the certificate")]
    BadSignature,
    #[error(transparent)]
    Bundle(#[from] crate::bundle::Error),
}

fn pgp_err(e: impl std::fmt::Display) -> Error {
    Error::OpenPgp(e.to_string())
}

/// A fingerprint as lowercase hex without spaces, the form `--holder` is compared in.
pub fn fingerprint_hex(key: &impl KeyDetails) -> String {
    hex::encode(key.fingerprint().as_bytes())
}

fn normalize_fingerprint(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase()
}

/// A holder's transferable secret keys, from one armored file or every file in a directory.
#[derive(Clone, Debug)]
pub struct Keyring {
    pub keys: Vec<SignedSecretKey>,
}

impl Keyring {
    pub fn load(path: &Path) -> Result<Self, Error> {
        let read = |p: &Path| {
            std::fs::read_to_string(p).map_err(|source| Error::Read {
                path: p.display().to_string(),
                source,
            })
        };
        let mut keys = Vec::new();
        if path.is_dir() {
            let mut entries: Vec<_> = std::fs::read_dir(path)
                .map_err(|source| Error::Read {
                    path: path.display().to_string(),
                    source,
                })?
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.is_file())
                .collect();
            entries.sort();
            for entry in entries {
                keys.extend(Self::parse(&read(&entry)?)?);
            }
        } else {
            keys.extend(Self::parse(&read(path)?)?);
        }
        if keys.is_empty() {
            return Err(Error::NoSecretKeys(path.display().to_string()));
        }
        Ok(Self { keys })
    }

    /// Every transferable secret key in an armored text (public keys in it are skipped).
    pub fn parse(armored: &str) -> Result<Vec<SignedSecretKey>, Error> {
        let (iter, _) = SignedSecretKey::from_string_many(armored).map_err(pgp_err)?;
        iter.map(|k| k.map_err(pgp_err)).collect()
    }

    /// Decrypt the metadata message with whichever key can.
    pub fn decrypt_metadata(
        &self,
        shardfile: &Shardfile,
        password: &Password,
    ) -> Result<Metadata, Error> {
        for key in &self.keys {
            if let Ok(plaintext) = decrypt_literal(shardfile.metadata_message(), key, password) {
                return Ok(Metadata::decode(&plaintext)?);
            }
        }
        Err(Error::MetadataUndecryptable)
    }

    /// Pick the holder this keyring can act as: the first holder in shard order whose secret
    /// keys are here (signing and storage-encryption both), or the one `fingerprint` names.
    pub fn select<'a>(
        &'a self,
        metadata: &Metadata,
        fingerprint: Option<&str>,
    ) -> Result<Holder<'a>, Error> {
        let wanted = fingerprint.map(normalize_fingerprint);
        if let Some(wanted) = &wanted {
            let position = metadata
                .holders
                .iter()
                .position(|h| fingerprint_hex(&h.primary_key) == *wanted)
                .ok_or_else(|| Error::HolderNotInQuorum(wanted.clone()))?;
            let cert = &metadata.holders[position];
            let key = self
                .keys
                .iter()
                .find(|k| fingerprint_hex(&k.primary_key) == *wanted)
                .ok_or_else(|| Error::HolderKeyMissing(wanted.clone()))?;
            if signing_key(key).is_none() || !has_secret_decryption_key(key) {
                return Err(Error::NoMatchingHolder);
            }
            return Ok(Holder {
                position,
                key,
                cert: cert.clone(),
            });
        }
        for (position, cert) in metadata.holders.iter().enumerate() {
            if let Some(key) = self.keys.iter().find(|k| {
                k.primary_key.fingerprint().as_bytes() == cert.primary_key.fingerprint().as_bytes()
            }) {
                if signing_key(key).is_some() && has_secret_decryption_key(key) {
                    return Ok(Holder {
                        position,
                        key,
                        cert: cert.clone(),
                    });
                }
            }
        }
        Err(Error::NoMatchingHolder)
    }

    /// Whether any key here is locked (would need a passphrase).
    pub fn any_locked(&self) -> bool {
        self.keys.iter().any(is_locked)
    }
}

fn is_locked(key: &SignedSecretKey) -> bool {
    key.primary_key.secret_params().is_encrypted()
        || key
            .secret_subkeys
            .iter()
            .any(|s| s.key.secret_params().is_encrypted())
}

/// Whether the certificate's own signatures give `key` the signing flag: a subkey through its
/// binding signatures, the primary through its direct-key or user-id self-signatures.
fn flags_allow_signing(sigs: &[pgp::packet::Signature]) -> bool {
    sigs.iter().any(|s| s.key_flags().sign())
}

fn flags_allow_storage(sigs: &[pgp::packet::Signature]) -> bool {
    sigs.iter().any(|s| s.key_flags().encrypt_storage())
}

fn primary_self_sigs(key: &SignedSecretKey) -> Vec<pgp::packet::Signature> {
    let mut sigs = key.details.direct_signatures.clone();
    for user in &key.details.users {
        sigs.extend(user.signatures.iter().cloned());
    }
    sigs
}

/// The secret key that signs for this certificate: a signing-flagged subkey first (the usual
/// layout), else the primary when it is flagged for signing.
enum Signer<'a> {
    Subkey(&'a pgp::packet::SecretSubkey),
    Primary(&'a pgp::packet::SecretKey),
}

fn signing_key(key: &SignedSecretKey) -> Option<Signer<'_>> {
    if let Some(sub) = key
        .secret_subkeys
        .iter()
        .find(|s| flags_allow_signing(&s.signatures))
    {
        return Some(Signer::Subkey(&sub.key));
    }
    if flags_allow_signing(&primary_self_sigs(key)) {
        return Some(Signer::Primary(&key.primary_key));
    }
    None
}

fn has_secret_decryption_key(key: &SignedSecretKey) -> bool {
    key.secret_subkeys
        .iter()
        .any(|s| flags_allow_storage(&s.signatures))
        || flags_allow_storage(&primary_self_sigs(key))
}

fn preferred_hash(key: &SignedSecretKey) -> HashAlgorithm {
    let prefs: Vec<HashAlgorithm> = key
        .details
        .users
        .iter()
        .flat_map(|u| u.signatures.iter())
        .flat_map(|s| s.preferred_hash_algs().iter().copied())
        .collect();
    ACCEPTED_HASHES
        .iter()
        .copied()
        .find(|h| prefs.contains(h))
        .unwrap_or(HashAlgorithm::Sha512)
}

/// Decrypt one shardfile message with `key` and return the inner message, read to its end.
fn decrypt_message<'a>(
    message: &'a EncryptedMessage,
    key: &SignedSecretKey,
    password: &Password,
) -> Result<(Message<'a>, Vec<u8>), Error> {
    let encrypted = Message::from_bytes(Cursor::new(message.bytes.as_slice())).map_err(pgp_err)?;
    let mut inner = encrypted.decrypt(password, key).map_err(pgp_err)?;
    let data = inner.as_data_vec().map_err(pgp_err)?;
    Ok((inner, data))
}

fn decrypt_literal(
    message: &EncryptedMessage,
    key: &SignedSecretKey,
    password: &Password,
) -> Result<Vec<u8>, Error> {
    let (inner, data) = decrypt_message(message, key, password)?;
    if !inner.is_literal() {
        return Err(Error::OpenPgp(
            "the metadata message is not a plain literal".into(),
        ));
    }
    Ok(data)
}

fn verifies_under(cert: &SignedPublicKey, check: impl Fn(&dyn VerifyingKey) -> bool) -> bool {
    check(&cert.primary_key) || cert.public_subkeys.iter().any(|s| check(&s.key))
}

fn signature_verifies(sig: &DetachedSignature, cert: &SignedPublicKey, text: &str) -> bool {
    sig.verify(&cert.primary_key, text.as_bytes()).is_ok()
        || cert
            .public_subkeys
            .iter()
            .any(|s| sig.verify(&s.key, text.as_bytes()).is_ok())
}

/// The holder this keyring acts as, once the metadata placed it.
#[derive(Debug)]
pub struct Holder<'a> {
    /// 0-based position among the metadata's holders; the share's coordinate is this plus one.
    pub position: usize,
    pub key: &'a SignedSecretKey,
    pub cert: SignedPublicKey,
}

/// A share as the request carries it: 33 bytes, the coordinate first.
pub type Share = [u8; 33];

impl Holder<'_> {
    pub fn fingerprint(&self) -> String {
        fingerprint_hex(&self.key.primary_key)
    }

    /// The share's coordinate (the position plus one), as the daemon checks it.
    pub fn coordinate(&self) -> u8 {
        (self.position + 1) as u8
    }

    /// Decrypt this holder's share and verify it: one one-pass signature, by the metadata's
    /// signer, over a 33-byte literal whose first byte is this holder's coordinate.
    pub fn decrypt_share(
        &self,
        shardfile: &Shardfile,
        metadata: &Metadata,
        password: &Password,
    ) -> Result<Share, Error> {
        let message = shardfile
            .share_message(self.position)
            .ok_or(Error::ShareMissing)?;
        let (inner, data) =
            decrypt_message(message, self.key, password).map_err(|_| Error::ShareUndecryptable)?;
        let Message::Signed { reader, .. } = &inner else {
            return Err(Error::ShareSignatureCount);
        };
        if reader.num_signatures() != 1 || !inner.is_one_pass_signed() {
            return Err(Error::ShareSignatureCount);
        }
        if !verifies_under(&metadata.signer, |k| inner.verify(k).is_ok()) {
            return Err(Error::ShareSignature);
        }
        let expected = self.coordinate();
        let share: Share = data.as_slice().try_into().map_err(|_| Error::ShareShape {
            len: data.len(),
            coordinate: data.first().copied().unwrap_or(0),
            expected,
        })?;
        if share[0] != expected {
            return Err(Error::ShareShape {
                len: 33,
                coordinate: share[0],
                expected,
            });
        }
        Ok(share)
    }

    /// An armored detached text-mode signature over `text` by this holder's signing key, with
    /// the certificate's preferred hash and a creation time [`SIGNATURE_BACKDATE`] in the past.
    pub fn sign(&self, text: &str, password: &Password) -> Result<String, Error> {
        let signer = signing_key(self.key).ok_or(Error::NoSigningKey)?;
        let hash = preferred_hash(self.key);
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("the clock is after 1970");
        let created = |key_created: Timestamp| {
            let backdated = now.saturating_sub(SIGNATURE_BACKDATE).as_secs();
            Timestamp::from_secs(
                u32::try_from(backdated)
                    .unwrap_or(u32::MAX)
                    .max(key_created.as_secs()),
            )
        };
        let (locked, sig) = match signer {
            Signer::Subkey(key) => (
                key.secret_params().is_encrypted(),
                sign_with(key, created(key.created_at()), hash, text, password)?,
            ),
            Signer::Primary(key) => (
                key.secret_params().is_encrypted(),
                sign_with(key, created(key.created_at()), hash, text, password)?,
            ),
        };
        let _ = locked;
        sig.to_armored_string(ArmorOptions::default())
            .map_err(pgp_err)
    }
}

fn sign_with(
    key: &impl SigningKey,
    created: Timestamp,
    hash: HashAlgorithm,
    text: &str,
    password: &Password,
) -> Result<DetachedSignature, Error> {
    let hashed = vec![
        Subpacket::regular(SubpacketData::IssuerFingerprint(key.fingerprint())).map_err(pgp_err)?,
        Subpacket::regular(SubpacketData::SignatureCreationTime(created)).map_err(pgp_err)?,
    ];
    let unhashed =
        vec![Subpacket::regular(SubpacketData::IssuerKeyId(key.legacy_key_id())).map_err(pgp_err)?];
    DetachedSignature::sign_text_data_with_subpackets(
        rand::rngs::OsRng,
        key,
        password,
        hash,
        text.as_bytes(),
        SubpacketConfig::UserDefined { hashed, unhashed },
    )
    .map_err(|e| {
        if e.to_string().contains("password") || e.to_string().contains("decrypt") {
            Error::Locked
        } else {
            pgp_err(e)
        }
    })
}

/// Verify an armored detached signature over `text` under `cert`: exactly one signature packet,
/// with a creation time, by the primary or any subkey. The time rules (not from the future,
/// not before the key) are the daemon's; a client-side caller uses this to check its own work.
pub fn verify_detached(
    cert: &SignedPublicKey,
    text: &str,
    armored_signature: &str,
) -> Result<Timestamp, Error> {
    let (sig, _) = DetachedSignature::from_string(armored_signature).map_err(pgp_err)?;
    let created = sig.signature.created().ok_or(Error::BadSignature)?;
    if !signature_verifies(&sig, cert, text) {
        return Err(Error::BadSignature);
    }
    Ok(created)
}

/// Everything a release needs from the bundle and the keyring, in one call: the metadata (and
/// its agreement with what the bundle declares), this holder's place, their share.
pub struct Release<'a> {
    pub metadata: Metadata,
    pub holder: Holder<'a>,
    pub share: Share,
}

pub fn prepare<'a>(
    bundle: &Bundle,
    keyring: &'a Keyring,
    fingerprint: Option<&str>,
    password: &Password,
) -> Result<Release<'a>, Error> {
    let shardfile = bundle.shardfile()?;
    let metadata = keyring.decrypt_metadata(&shardfile, password)?;
    bundle.check_metadata(&metadata)?;
    let holder = keyring.select(&metadata, fingerprint)?;
    let share = holder.decrypt_share(&shardfile, &metadata, password)?;
    Ok(Release {
        metadata,
        holder,
        share,
    })
}

/// Whether two certificates are the same key (by primary fingerprint).
pub fn is_same_holder(a: &SignedPublicKey, b: &SignedPublicKey) -> bool {
    same_key(a, b)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::bundle::tests::{IMPORTED_V0, RAW_V0};

    pub(crate) const ALICE: &str = include_str!("../tests/fixtures/locksmith-v0/alice.private.asc");
    pub(crate) const BOB: &str = include_str!("../tests/fixtures/locksmith-v0/bob.private.asc");

    fn keyring(text: &str) -> Keyring {
        Keyring {
            keys: Keyring::parse(text).unwrap(),
        }
    }

    #[test]
    fn both_holders_decrypt_the_sequoia_made_fixture() {
        let bundle = Bundle::from_json(RAW_V0).unwrap();
        let shardfile = bundle.shardfile().unwrap();
        for (text, expected_position) in [(ALICE, 0usize), (BOB, 1)] {
            let keyring = keyring(text);
            assert!(!keyring.any_locked());
            let metadata = keyring
                .decrypt_metadata(&shardfile, &Password::empty())
                .unwrap();
            assert_eq!(metadata.threshold, 2);
            assert_eq!(metadata.holders.len(), 2);
            bundle.check_metadata(&metadata).unwrap();
            let holder = keyring.select(&metadata, None).unwrap();
            assert_eq!(holder.position, expected_position);
            let share = holder
                .decrypt_share(&shardfile, &metadata, &Password::empty())
                .unwrap();
            assert_eq!(share[0], holder.coordinate());
            assert_eq!(share.len(), 33);
            let release = prepare(&bundle, &keyring, None, &Password::empty()).unwrap();
            assert_eq!(release.share, share);
        }
    }

    #[test]
    fn imported_form_agrees_with_the_metadata_and_a_tampered_one_does_not() {
        let keyring = keyring(ALICE);
        let bundle = Bundle::from_json(IMPORTED_V0).unwrap();
        prepare(&bundle, &keyring, None, &Password::empty()).unwrap();
        let mut changed: serde_json::Value = serde_json::from_str(IMPORTED_V0).unwrap();
        changed["threshold"] = serde_json::json!(1);
        let changed = Bundle::from_json(&changed.to_string()).unwrap();
        assert!(matches!(
            prepare(&changed, &keyring, None, &Password::empty()),
            Err(Error::Bundle(crate::bundle::Error::ThresholdMismatch {
                declared: 1,
                metadata: 2
            }))
        ));
        let mut reversed: serde_json::Value = serde_json::from_str(IMPORTED_V0).unwrap();
        let (a, b) = (
            reversed["keyring"][0].clone(),
            reversed["keyring"][1].clone(),
        );
        reversed["keyring"][0] = b;
        reversed["keyring"][1] = a;
        let reversed = Bundle::from_json(&reversed.to_string()).unwrap();
        assert!(matches!(
            prepare(&reversed, &keyring, None, &Password::empty()),
            Err(Error::Bundle(crate::bundle::Error::HolderMismatch {
                position: 0
            }))
        ));
    }

    #[test]
    fn holder_selection_by_fingerprint_and_the_wrong_share_position() {
        let bundle = Bundle::from_json(RAW_V0).unwrap();
        let shardfile = bundle.shardfile().unwrap();
        let both = Keyring {
            keys: [Keyring::parse(BOB).unwrap(), Keyring::parse(ALICE).unwrap()].concat(),
        };
        let metadata = both
            .decrypt_metadata(&shardfile, &Password::empty())
            .unwrap();
        // With both keys present the first holder in shard order (alice) is picked...
        assert_eq!(both.select(&metadata, None).unwrap().position, 0);
        // ...unless --holder names bob, in any spelling.
        let bob = fingerprint_hex(&Keyring::parse(BOB).unwrap()[0].primary_key);
        let spaced = bob
            .to_uppercase()
            .as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(" ");
        let holder = both.select(&metadata, Some(&spaced)).unwrap();
        assert_eq!(holder.position, 1);
        assert_eq!(holder.fingerprint(), bob);
        assert!(matches!(
            both.select(&metadata, Some("00".repeat(20).as_str())),
            Err(Error::HolderNotInQuorum(_))
        ));
        let alice_only = keyring(ALICE);
        assert!(matches!(
            alice_only.select(&metadata, Some(&bob)),
            Err(Error::HolderKeyMissing(_))
        ));
        // Alice's key cannot open bob's share.
        let mut wrong = alice_only.select(&metadata, None).unwrap();
        wrong.position = 1;
        assert!(matches!(
            wrong.decrypt_share(&shardfile, &metadata, &Password::empty()),
            Err(Error::ShareUndecryptable)
        ));
        let mut off_by_one = alice_only.select(&metadata, None).unwrap();
        off_by_one.position = 0;
        let share = off_by_one
            .decrypt_share(&shardfile, &metadata, &Password::empty())
            .unwrap();
        assert_eq!(share[0], 1);
    }

    #[test]
    fn an_outsider_decrypts_nothing() {
        let bundle = Bundle::from_json(RAW_V0).unwrap();
        let shardfile = bundle.shardfile().unwrap();
        let outsider = Keyring {
            keys: vec![crate::test_keys::generate("outsider")],
        };
        assert!(matches!(
            outsider.decrypt_metadata(&shardfile, &Password::empty()),
            Err(Error::MetadataUndecryptable)
        ));
        let metadata = keyring(ALICE)
            .decrypt_metadata(&shardfile, &Password::empty())
            .unwrap();
        assert!(matches!(
            outsider.select(&metadata, None),
            Err(Error::NoMatchingHolder)
        ));
    }

    #[test]
    fn signatures_verify_under_the_right_holder_only_and_are_backdated() {
        let bundle = Bundle::from_json(RAW_V0).unwrap();
        let shardfile = bundle.shardfile().unwrap();
        let alice = keyring(ALICE);
        let metadata = alice
            .decrypt_metadata(&shardfile, &Password::empty())
            .unwrap();
        let holder = alice.select(&metadata, None).unwrap();
        let signature = holder.sign("payload", &Password::empty()).unwrap();
        assert!(signature.starts_with("-----BEGIN PGP SIGNATURE-----"));
        let created = verify_detached(&metadata.holders[0], "payload", &signature).unwrap();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(u64::from(created.as_secs()) <= now - SIGNATURE_BACKDATE.as_secs() + 1);
        assert!(u64::from(created.as_secs()) >= now - SIGNATURE_BACKDATE.as_secs() - 5);
        assert!(matches!(
            verify_detached(&metadata.holders[1], "payload", &signature),
            Err(Error::BadSignature)
        ));
        assert!(matches!(
            verify_detached(&metadata.holders[0], "payload ", &signature),
            Err(Error::BadSignature)
        ));
        // Text mode: a line-ending change does not invalidate it.
        verify_detached(
            &metadata.holders[0],
            "payload\r\n",
            &holder.sign("payload\n", &Password::empty()).unwrap(),
        )
        .unwrap();
        let (sig, _) = DetachedSignature::from_string(&signature).unwrap();
        assert_eq!(sig.signature.hash_alg(), Some(HashAlgorithm::Sha512));
    }
}
