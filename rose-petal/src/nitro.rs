//! Nitro attestation documents: parse one, and verify it against a set of PCRs.
//!
//! A document is a COSE_Sign1 (RFC 9052) whose payload is a CBOR map: `module_id`, `digest`,
//! `timestamp` (milliseconds), `pcrs` (index to 48-byte value), `certificate` (the DER leaf,
//! issued to the enclave for about three hours), `cabundle` (the DER chain up to AWS's root),
//! and the optional `public_key`, `user_data` and `nonce` the enclave asked the NSM to sign.
//! The signature is ES384 by the leaf. Verifying a document is: the chain from the leaf to
//! the AWS Nitro root at a point in time, the signature, the expected PCRs, the expected
//! nonce. What `user_data` and `public_key` mean is the protocol's business: Locksmith puts
//! the connection's X25519 public key in `user_data`.
//!
//! Two clocks. A live check verifies the chain at "now plus a minute": the leaf is minted by
//! the NSM against the parent's clock, so a client a few seconds behind would otherwise see a
//! certificate from the future (bootproof's rule, kept so both verifiers answer alike). An
//! archived check verifies at the document's own timestamp instead: that proves what was
//! true when the document was issued, not that the enclave is up now.

use ciborium::value::Value;
use coset::{iana, CborSerializable, CoseSign1, RegisteredLabelWithPrivate};
use rustls_pki_types::{CertificateDer, UnixTime};
use std::collections::BTreeMap;
use std::time::Duration;

/// AWS's Nitro Enclaves root certificate (DER), `CN=aws.nitro-enclaves`, as AWS publishes it:
/// its SHA-256 is `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b`.
pub const AWS_NITRO_ROOT_DER: &[u8] =
    include_bytes!("../tests/fixtures/attestation/nitro-root.der");

/// A live check verifies the chain this far ahead of the caller's clock.
pub const CLOCK_SKEW_TOLERANCE: Duration = Duration::from_secs(60);

/// The shortest nonce a verifier accepts when one is expected (bootproof's floor).
pub const MIN_NONCE_LEN: usize = 12;

/// The length of a PCR value.
pub const PCR_LEN: usize = 48;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the document is not CBOR: {0}")]
    Cbor(String),
    #[error("the document is not a COSE_Sign1")]
    NotCoseSign1,
    #[error("the document has no {0}")]
    Missing(&'static str),
    #[error("the document's {0} is malformed")]
    Malformed(&'static str),
    #[error(
        "the certificate chain does not lead to the trusted root at the verification time: {0}"
    )]
    Chain(webpki::Error),
    #[error("the document is signed with an algorithm other than ES384")]
    UnsupportedAlgorithm,
    #[error("the COSE signature does not verify under the leaf certificate")]
    BadSignature,
    #[error("pcr{0} does not match the expected value")]
    PcrMismatch(u8),
    #[error("the document carries no pcr{0}")]
    MissingPcr(u8),
    #[error("the signed nonce is not the expected one")]
    NonceMismatch,
    #[error("the expected nonce is {0} bytes; at least {MIN_NONCE_LEN} are required")]
    NonceTooShort(usize),
    #[error("the document carries a nonce where none was expected")]
    UnexpectedNonce,
    #[error("{0}")]
    Pcrs(String),
}

/// The PCR values an enclave is expected to attest: PCR0 (the image), PCR1 (the kernel and
/// boot ramdisk) and PCR2 (the application) are required; any further index given is checked
/// too. A deployment records them as `trusted_hashes.json`: `{"pcr0": "<96 hex>", ...}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pcrs(BTreeMap<u8, [u8; PCR_LEN]>);

impl Pcrs {
    pub fn new(values: BTreeMap<u8, [u8; PCR_LEN]>) -> Result<Self, Error> {
        for required in 0..3u8 {
            if !values.contains_key(&required) {
                return Err(Error::Pcrs(format!("pcr{required} is required")));
            }
        }
        Ok(Self(values))
    }

    /// The `{"pcrN": "<hex>", ...}` file a deployment commits as its trusted hashes. Other keys
    /// (`verified_at`, ...) are ignored; every `pcrN` key present is taken.
    pub fn from_hashes_json(text: &str) -> Result<Self, Error> {
        let json: serde_json::Value = serde_json::from_str(text)
            .map_err(|e| Error::Pcrs(format!("hashes file is not JSON: {e}")))?;
        let object = json
            .as_object()
            .ok_or_else(|| Error::Pcrs("hashes file is not a JSON object".into()))?;
        let mut values = BTreeMap::new();
        for (key, value) in object {
            let Some(index) = key.strip_prefix("pcr").and_then(|n| n.parse::<u8>().ok()) else {
                continue;
            };
            let hex = value
                .as_str()
                .ok_or_else(|| Error::Pcrs(format!("{key} is not a string")))?;
            let bytes =
                hex::decode(hex).map_err(|e| Error::Pcrs(format!("{key} is not hex: {e}")))?;
            let bytes: [u8; PCR_LEN] = bytes.try_into().map_err(|b: Vec<u8>| {
                Error::Pcrs(format!("{key} is {} bytes, not {PCR_LEN}", b.len()))
            })?;
            values.insert(index, bytes);
        }
        Self::new(values)
    }

    pub fn get(&self, index: u8) -> Option<&[u8; PCR_LEN]> {
        self.0.get(&index)
    }

    pub fn iter(&self) -> impl Iterator<Item = (u8, &[u8; PCR_LEN])> {
        self.0.iter().map(|(i, v)| (*i, v))
    }

    /// Whether any expected value is all zero. A debug-mode enclave attests zero PCRs, so its
    /// document proves nothing about what runs; a caller refuses this unless told otherwise.
    pub fn is_debug(&self) -> bool {
        self.0.values().any(|v| v.iter().all(|b| *b == 0))
    }
}

/// A parsed document: the signed fields, read without any check. [`Verifier::verify`] is what
/// makes them trustworthy.
#[derive(Clone, Debug)]
pub struct Attestation {
    cose: CoseSign1,
    pub module_id: String,
    pub digest: String,
    pub timestamp_ms: u64,
    pub pcrs: BTreeMap<u8, Vec<u8>>,
    pub certificate: Vec<u8>,
    pub cabundle: Vec<Vec<u8>>,
    pub public_key: Option<Vec<u8>>,
    pub user_data: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
}

fn text_key(key: &str) -> Value {
    Value::Text(key.to_string())
}

fn take<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| *k == text_key(key))
        .map(|(_, v)| v)
}

fn bytes(map: &[(Value, Value)], key: &'static str) -> Result<Vec<u8>, Error> {
    match take(map, key) {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        Some(_) => Err(Error::Malformed(key)),
        None => Err(Error::Missing(key)),
    }
}

/// `null` and absent both mean "none"; anything but bytes is malformed.
fn optional_bytes(map: &[(Value, Value)], key: &'static str) -> Result<Option<Vec<u8>>, Error> {
    match take(map, key) {
        Some(Value::Bytes(b)) => Ok(Some(b.clone())),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(Error::Malformed(key)),
    }
}

impl Attestation {
    /// Parse a document's bytes (the COSE_Sign1, tagged or untagged). No field is checked
    /// beyond its shape.
    pub fn parse(document: &[u8]) -> Result<Self, Error> {
        let value: Value =
            ciborium::from_reader(document).map_err(|e| Error::Cbor(e.to_string()))?;
        let value = match value {
            Value::Tag(_, inner) => *inner,
            other => other,
        };
        if !matches!(&value, Value::Array(items) if items.len() == 4) {
            return Err(Error::NotCoseSign1);
        }
        let mut untagged = Vec::new();
        ciborium::into_writer(&value, &mut untagged).map_err(|e| Error::Cbor(e.to_string()))?;
        let cose = CoseSign1::from_slice(&untagged).map_err(|_| Error::NotCoseSign1)?;
        let payload_bytes = cose.payload.as_ref().ok_or(Error::Missing("payload"))?;
        let payload: Value = ciborium::from_reader(payload_bytes.as_slice())
            .map_err(|e| Error::Cbor(e.to_string()))?;
        let Value::Map(map) = payload else {
            return Err(Error::Malformed("payload"));
        };
        let module_id = match take(&map, "module_id") {
            Some(Value::Text(s)) => s.clone(),
            Some(_) => return Err(Error::Malformed("module_id")),
            None => return Err(Error::Missing("module_id")),
        };
        let digest = match take(&map, "digest") {
            Some(Value::Text(s)) => s.clone(),
            Some(_) => return Err(Error::Malformed("digest")),
            None => return Err(Error::Missing("digest")),
        };
        let timestamp_ms = match take(&map, "timestamp") {
            Some(Value::Integer(i)) => {
                u64::try_from(i128::from(*i)).map_err(|_| Error::Malformed("timestamp"))?
            }
            Some(_) => return Err(Error::Malformed("timestamp")),
            None => return Err(Error::Missing("timestamp")),
        };
        let mut pcrs = BTreeMap::new();
        match take(&map, "pcrs") {
            Some(Value::Map(entries)) => {
                for (k, v) in entries {
                    let (Value::Integer(i), Value::Bytes(b)) = (k, v) else {
                        return Err(Error::Malformed("pcrs"));
                    };
                    let index =
                        u8::try_from(i128::from(*i)).map_err(|_| Error::Malformed("pcrs"))?;
                    pcrs.insert(index, b.clone());
                }
            }
            Some(_) => return Err(Error::Malformed("pcrs")),
            None => return Err(Error::Missing("pcrs")),
        }
        let certificate = bytes(&map, "certificate")?;
        let cabundle = match take(&map, "cabundle") {
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| match item {
                    Value::Bytes(b) => Ok(b.clone()),
                    _ => Err(Error::Malformed("cabundle")),
                })
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => return Err(Error::Malformed("cabundle")),
            None => return Err(Error::Missing("cabundle")),
        };
        Ok(Self {
            cose,
            module_id,
            digest,
            timestamp_ms,
            pcrs,
            certificate,
            cabundle,
            public_key: optional_bytes(&map, "public_key")?,
            user_data: optional_bytes(&map, "user_data")?,
            nonce: optional_bytes(&map, "nonce")?,
        })
    }

    /// The document's timestamp as a duration since the Unix epoch.
    pub fn timestamp(&self) -> Duration {
        Duration::from_millis(self.timestamp_ms)
    }

    /// The instance a module id names: `i-xxxx-encYYYY` is enclave `YYYY` on instance `i-xxxx`.
    pub fn instance_id(&self) -> Option<&str> {
        self.module_id
            .rsplit_once("-enc")
            .map(|(instance, _)| instance)
    }
}

/// When the certificate chain is checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum At {
    /// A live document: at this time (a duration since the Unix epoch, normally now) plus
    /// [`CLOCK_SKEW_TOLERANCE`].
    Live(Duration),
    /// A saved document: at its own `timestamp`, which proves provenance, not freshness.
    DocumentTimestamp,
}

impl At {
    /// Now, for a live check.
    pub fn now() -> Self {
        Self::Live(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("the clock is after 1970"),
        )
    }
}

/// What a document must say to pass.
#[derive(Clone, Copy, Debug)]
pub struct Expected<'a> {
    /// The PCRs; every index here must match.
    pub pcrs: &'a Pcrs,
    /// `Some`: the signed nonce must equal these bytes (at least [`MIN_NONCE_LEN`] of them).
    /// `None`: the document must carry no nonce.
    pub nonce: Option<&'a [u8]>,
}

/// A verifier: the trusted root the chain must lead to.
#[derive(Clone, Debug)]
pub struct Verifier {
    root: Vec<u8>,
}

impl Verifier {
    /// The production verifier: AWS's Nitro root.
    pub fn aws() -> Self {
        Self {
            root: AWS_NITRO_ROOT_DER.to_vec(),
        }
    }

    /// A verifier trusting another root (DER). For documents an enclave never signed: the
    /// tests and the `test-server` feature; never for a holder's release.
    pub fn with_root(root_der: &[u8]) -> Self {
        Self {
            root: root_der.to_vec(),
        }
    }

    /// Verify `attestation` in this order, stopping at the first failure: the chain from the
    /// leaf through `cabundle` to the root at `at`; the ES384 signature by the leaf over the
    /// COSE Sig_structure; every expected PCR; the nonce. On success the parsed fields can be
    /// trusted as the NSM signed them.
    pub fn verify(
        &self,
        attestation: &Attestation,
        at: At,
        expected: Expected<'_>,
    ) -> Result<(), Error> {
        if let Some(nonce) = expected.nonce {
            if nonce.len() < MIN_NONCE_LEN {
                return Err(Error::NonceTooShort(nonce.len()));
            }
        }
        self.verify_signed(attestation, at)?;
        for (index, value) in expected.pcrs.iter() {
            match attestation.pcrs.get(&index) {
                Some(signed) if signed.as_slice() == value => {}
                Some(_) => return Err(Error::PcrMismatch(index)),
                None => return Err(Error::MissingPcr(index)),
            }
        }
        match (expected.nonce, &attestation.nonce) {
            (Some(expected), Some(signed)) if signed.as_slice() == expected => Ok(()),
            (Some(_), Some(_)) => Err(Error::NonceMismatch),
            (Some(_), None) => Err(Error::Missing("nonce")),
            (None, None) => Ok(()),
            (None, Some(_)) => Err(Error::UnexpectedNonce),
        }
    }

    /// The chain and the signature alone, at `at`: what makes the document AWS's word, before
    /// any expectation about its contents.
    pub fn verify_signed(&self, attestation: &Attestation, at: At) -> Result<(), Error> {
        let time = match at {
            At::Live(now) => now.saturating_add(CLOCK_SKEW_TOLERANCE),
            At::DocumentTimestamp => attestation.timestamp(),
        };
        self.verify_chain(attestation, time)?;
        self.verify_signature(attestation)
    }

    fn verify_chain(&self, attestation: &Attestation, time: Duration) -> Result<(), Error> {
        let root = CertificateDer::from(self.root.as_slice());
        let anchor = webpki::anchor_from_trusted_cert(&root).map_err(Error::Chain)?;
        let leaf = CertificateDer::from(attestation.certificate.as_slice());
        let leaf = webpki::EndEntityCert::try_from(&leaf).map_err(Error::Chain)?;
        let intermediates: Vec<CertificateDer<'_>> = attestation
            .cabundle
            .iter()
            .map(|der| CertificateDer::from(der.as_slice()))
            .collect();
        leaf.verify_for_usage(
            &[webpki::ring::ECDSA_P384_SHA384],
            std::slice::from_ref(&anchor),
            &intermediates,
            UnixTime::since_unix_epoch(time),
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .map(|_| ())
        .map_err(Error::Chain)
    }

    fn verify_signature(&self, attestation: &Attestation) -> Result<(), Error> {
        match attestation.cose.protected.header.alg.as_ref() {
            Some(RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES384)) => {}
            _ => return Err(Error::UnsupportedAlgorithm),
        }
        let leaf = CertificateDer::from(attestation.certificate.as_slice());
        let leaf = webpki::EndEntityCert::try_from(&leaf).map_err(Error::Chain)?;
        attestation
            .cose
            .verify_signature(&[], |signature, to_be_signed| {
                let der = ecdsa_fixed_to_der(signature).ok_or(Error::BadSignature)?;
                leaf.verify_signature(webpki::ring::ECDSA_P384_SHA384, to_be_signed, &der)
                    .map_err(|_| Error::BadSignature)
            })
    }
}

/// A COSE ES384 signature is `r || s`, two fixed 48-byte unsigned integers; X.509 verifiers
/// take the DER `SEQUENCE { INTEGER r, INTEGER s }`. Leading zero bytes are stripped and a
/// zero byte is added back when the top bit would read as a sign.
fn ecdsa_fixed_to_der(signature: &[u8]) -> Option<Vec<u8>> {
    if signature.len() != 96 {
        return None;
    }
    fn integer(value: &[u8]) -> Vec<u8> {
        let start = value
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(value.len() - 1);
        let trimmed = &value[start..];
        let mut out = vec![0x02];
        if trimmed[0] & 0x80 != 0 {
            out.push((trimmed.len() + 1) as u8);
            out.push(0);
        } else {
            out.push(trimmed.len() as u8);
        }
        out.extend_from_slice(trimmed);
        out
    }
    let (r, s) = (integer(&signature[..48]), integer(&signature[48..]));
    let mut der = vec![0x30, (r.len() + s.len()) as u8];
    der.extend(r);
    der.extend(s);
    Some(der)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// bootproof's fixture: a real document from an enclave, its nonce and PCRs, and a time
    /// shortly after it was issued.
    pub(crate) const AWS_TEST: &[u8] =
        include_bytes!("../tests/fixtures/attestation/aws-test.cbor");
    pub(crate) const AWS_TEST_TIME: Duration = Duration::from_secs(1766510416);
    const AWS_LEAF_NOT_BEFORE: u64 = 1766509560;
    const AWS_LEAF_NOT_AFTER: u64 = 1766520363;

    pub(crate) fn aws_test_nonce() -> Vec<u8> {
        hex::decode("d041b23bce8678bbc7c174bd8494c4f9759386eec963ec69bfd45c1452b10636").unwrap()
    }

    pub(crate) fn aws_test_pcrs() -> Pcrs {
        Pcrs::from_hashes_json(
            r#"{"pcr0": "ef093e4c1fd13878956589833c0e396b935cdf5ae45c1cc595e1a19a6da5812850f0ef3e77df918cb2a86d88ddf9cc03",
                "pcr1": "ef093e4c1fd13878956589833c0e396b935cdf5ae45c1cc595e1a19a6da5812850f0ef3e77df918cb2a86d88ddf9cc03",
                "pcr2": "21b9efbc184807662e966d34f390821309eeac6802309798826296bf3e8bec7c10edb30948c90ba67310f7b964fc500a"}"#,
        )
        .unwrap()
    }

    fn verify_aws(document: &[u8], at: At, pcrs: &Pcrs, nonce: &[u8]) -> Result<(), Error> {
        let attestation = Attestation::parse(document)?;
        Verifier::aws().verify(
            &attestation,
            at,
            Expected {
                pcrs,
                nonce: Some(nonce),
            },
        )
    }

    #[test]
    fn the_aws_root_is_the_published_one() {
        use sha2::Digest;
        assert_eq!(
            hex::encode(sha2::Sha256::digest(AWS_NITRO_ROOT_DER)),
            "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"
        );
    }

    #[test]
    fn a_real_document_verifies_live_and_archived() {
        let pcrs = aws_test_pcrs();
        verify_aws(AWS_TEST, At::Live(AWS_TEST_TIME), &pcrs, &aws_test_nonce()).unwrap();
        verify_aws(AWS_TEST, At::DocumentTimestamp, &pcrs, &aws_test_nonce()).unwrap();
        let attestation = Attestation::parse(AWS_TEST).unwrap();
        assert_eq!(attestation.timestamp_ms, 1766509563435);
        assert!(attestation.user_data.is_some());
        assert_eq!(attestation.pcrs.len(), 16);
        assert!(attestation.module_id.contains("-enc"));
        assert!(attestation.instance_id().unwrap().starts_with("i-"));
    }

    #[test]
    fn live_verification_allows_sixty_seconds_of_skew() {
        let pcrs = aws_test_pcrs();
        for seconds in [AWS_LEAF_NOT_BEFORE - 60, AWS_LEAF_NOT_AFTER - 60] {
            verify_aws(
                AWS_TEST,
                At::Live(Duration::from_secs(seconds)),
                &pcrs,
                &aws_test_nonce(),
            )
            .unwrap();
        }
        for seconds in [AWS_LEAF_NOT_BEFORE - 61, AWS_LEAF_NOT_AFTER - 59] {
            assert!(matches!(
                verify_aws(
                    AWS_TEST,
                    At::Live(Duration::from_secs(seconds)),
                    &pcrs,
                    &aws_test_nonce()
                ),
                Err(Error::Chain(_))
            ));
        }
        let day = Duration::from_secs(86400);
        assert!(matches!(
            verify_aws(
                AWS_TEST,
                At::Live(AWS_TEST_TIME - day),
                &pcrs,
                &aws_test_nonce()
            ),
            Err(Error::Chain(_))
        ));
        assert!(matches!(
            verify_aws(
                AWS_TEST,
                At::Live(AWS_TEST_TIME + day),
                &pcrs,
                &aws_test_nonce()
            ),
            Err(Error::Chain(_))
        ));
    }

    #[test]
    fn wrong_nonce_pcr_or_extra_pcr_fails() {
        let pcrs = aws_test_pcrs();
        assert!(matches!(
            verify_aws(AWS_TEST, At::Live(AWS_TEST_TIME), &pcrs, &[0x10; 12]),
            Err(Error::NonceMismatch)
        ));
        assert!(matches!(
            verify_aws(AWS_TEST, At::Live(AWS_TEST_TIME), &pcrs, &[0x10; 10]),
            Err(Error::NonceTooShort(10))
        ));
        let mut wrong = pcrs.0.clone();
        wrong.get_mut(&0).unwrap()[1] ^= 0xff;
        assert!(matches!(
            verify_aws(
                AWS_TEST,
                At::Live(AWS_TEST_TIME),
                &Pcrs::new(wrong).unwrap(),
                &aws_test_nonce()
            ),
            Err(Error::PcrMismatch(0))
        ));
        let mut extra = pcrs.0.clone();
        extra.insert(7, [0xab; 48]);
        assert!(matches!(
            verify_aws(
                AWS_TEST,
                At::Live(AWS_TEST_TIME),
                &Pcrs::new(extra).unwrap(),
                &aws_test_nonce()
            ),
            Err(Error::PcrMismatch(7))
        ));
        let mut absent = pcrs.0.clone();
        absent.insert(17, [0xab; 48]);
        assert!(matches!(
            verify_aws(
                AWS_TEST,
                At::Live(AWS_TEST_TIME),
                &Pcrs::new(absent).unwrap(),
                &aws_test_nonce()
            ),
            Err(Error::MissingPcr(17))
        ));
    }

    #[test]
    fn mutated_signature_and_mutated_chain_fail() {
        let mut cose = CoseSign1::from_slice(AWS_TEST).unwrap();
        cose.signature[2] ^= 1;
        let bad_signature = cose.to_vec().unwrap();
        assert!(matches!(
            verify_aws(
                &bad_signature,
                At::Live(AWS_TEST_TIME),
                &aws_test_pcrs(),
                &aws_test_nonce()
            ),
            Err(Error::BadSignature)
        ));

        let mut cose = CoseSign1::from_slice(AWS_TEST).unwrap();
        let mut payload: Value = ciborium::from_reader(cose.payload.as_deref().unwrap()).unwrap();
        let Value::Map(map) = &mut payload else {
            panic!()
        };
        let (_, Value::Array(cabundle)) = map
            .iter_mut()
            .find(|(k, _)| k == &text_key("cabundle"))
            .unwrap()
        else {
            panic!()
        };
        let Value::Bytes(intermediate) = &mut cabundle[1] else {
            panic!()
        };
        intermediate[17] ^= 0xff;
        let mut bytes = Vec::new();
        ciborium::into_writer(&payload, &mut bytes).unwrap();
        cose.payload = Some(bytes);
        let bad_chain = cose.to_vec().unwrap();
        assert!(matches!(
            verify_aws(
                &bad_chain,
                At::Live(AWS_TEST_TIME),
                &aws_test_pcrs(),
                &aws_test_nonce()
            ),
            Err(Error::Chain(_))
        ));
    }

    #[test]
    fn a_tampered_payload_fails_the_signature() {
        // Flip a PCR in the signed payload with the chain intact: the signature must catch it.
        let mut cose = CoseSign1::from_slice(AWS_TEST).unwrap();
        let mut payload: Value = ciborium::from_reader(cose.payload.as_deref().unwrap()).unwrap();
        let Value::Map(map) = &mut payload else {
            panic!()
        };
        let (_, Value::Map(pcrs)) = map
            .iter_mut()
            .find(|(k, _)| k == &text_key("pcrs"))
            .unwrap()
        else {
            panic!()
        };
        let (_, Value::Bytes(pcr0)) = &mut pcrs[0] else {
            panic!()
        };
        pcr0[0] ^= 1;
        let mut bytes = Vec::new();
        ciborium::into_writer(&payload, &mut bytes).unwrap();
        cose.payload = Some(bytes);
        assert!(matches!(
            verify_aws(
                &cose.to_vec().unwrap(),
                At::Live(AWS_TEST_TIME),
                &aws_test_pcrs(),
                &aws_test_nonce()
            ),
            Err(Error::BadSignature)
        ));
    }

    #[test]
    fn a_deployments_recorded_document_verifies_at_its_timestamp() {
        // A deployment's committed attestation of 2026-10-28, fetched with the deployed commit
        // as the nonce; the leaf has long expired, so only the archived check passes.
        let answer: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/attestation/rose-deploy-2026-10-28.json"
        ))
        .unwrap();
        let document = base64_decode(answer["document"].as_str().unwrap());
        let pcrs = Pcrs::from_hashes_json(include_str!(
            "../tests/fixtures/attestation/rose-deploy-2026-10-28.hashes.json"
        ))
        .unwrap();
        let nonce = hex::decode("c502c976c57a5f749155bb84f5e32f0f3b16f01a").unwrap();
        let attestation = Attestation::parse(&document).unwrap();
        Verifier::aws()
            .verify(
                &attestation,
                At::DocumentTimestamp,
                Expected {
                    pcrs: &pcrs,
                    nonce: Some(&nonce),
                },
            )
            .unwrap();
        assert_eq!(attestation.instance_id(), Some("i-05c6aee5a0c1935a8"));
        assert!(matches!(
            Verifier::aws().verify(
                &attestation,
                At::Live(Duration::from_secs(1_800_000_000)),
                Expected {
                    pcrs: &pcrs,
                    nonce: Some(&nonce)
                }
            ),
            Err(Error::Chain(_))
        ));
        assert!(matches!(
            Verifier::aws().verify(
                &attestation,
                At::DocumentTimestamp,
                Expected {
                    pcrs: &pcrs,
                    nonce: None
                }
            ),
            Err(Error::UnexpectedNonce)
        ));
    }

    #[test]
    fn hashes_file_parsing_is_strict_about_pcr_values() {
        assert!(Pcrs::from_hashes_json(r#"{"pcr0": "ab"}"#)
            .unwrap_err()
            .to_string()
            .contains("not 48"));
        let short = format!(
            r#"{{"pcr0": "{0}", "pcr1": "{0}", "pcr2": "{1}"}}"#,
            "ab".repeat(48),
            "ab".repeat(47)
        );
        assert!(Pcrs::from_hashes_json(&short)
            .unwrap_err()
            .to_string()
            .contains("47 bytes"));
        let two = format!(r#"{{"pcr0": "{0}", "pcr1": "{0}"}}"#, "ab".repeat(48));
        assert!(Pcrs::from_hashes_json(&two)
            .unwrap_err()
            .to_string()
            .contains("pcr2 is required"));
        let zero = format!(
            r#"{{"pcr0": "{0}", "pcr1": "{0}", "pcr2": "{1}", "verified_at": "x"}}"#,
            "00".repeat(48),
            "ab".repeat(48)
        );
        assert!(Pcrs::from_hashes_json(&zero).unwrap().is_debug());
        assert!(!aws_test_pcrs().is_debug());
    }

    #[test]
    fn der_conversion_strips_padding_and_protects_the_sign_bit() {
        let mut sig = vec![0u8; 96];
        sig[47] = 0x7f;
        sig[48] = 0xd2;
        let der = ecdsa_fixed_to_der(&sig).unwrap();
        // r = 0x7f (one byte), s = 0xd2 followed by 47 zero bytes (sign-protected, 49 bytes).
        assert_eq!(&der[..5], &[0x30, 3 + 51, 0x02, 0x01, 0x7f]);
        assert_eq!(&der[5..8], &[0x02, 49, 0x00]);
        assert_eq!(der[8], 0xd2);
        assert_eq!(der.len(), 2 + 3 + 51);
        assert!(ecdsa_fixed_to_der(&[0; 95]).is_none());
    }

    pub(crate) fn base64_decode(s: &str) -> Vec<u8> {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let (mut out, mut buf, mut bits) = (Vec::new(), 0u32, 0u32);
        for c in s.bytes().filter(|c| !c.is_ascii_whitespace()) {
            if c == b'=' {
                break;
            }
            let v = T.iter().position(|&t| t == c).expect("base64") as u32;
            buf = (buf << 6) | v;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
                buf &= (1 << bits) - 1;
            }
        }
        out
    }
}
