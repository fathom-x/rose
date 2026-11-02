//! The quorum bundle: what Keymaker hands the operator when a quorum is generated, and what
//! the enclave is built with. Three forms are read:
//!
//! - **Raw V0**, the unversioned object Caution's keymaker produced until 2026: `label`,
//!   `keyring` (every holder certificate in one armored block, in no particular order),
//!   `keyring_hash` (its SHA-256), `shardfile`, `public_key` (the quorum's certificate) and an
//!   empty `necroproof`. The threshold and the holder order live only inside the encrypted
//!   shardfile metadata, so a raw V0 has no content hash a server could check without a holder
//!   key, and the client sends none for it.
//! - **ImportedV0**, upstream's artifact for a raw V0: the original, plus the `threshold` and
//!   the ordered holder `keyring` a holder read out of the metadata once (`--allow-legacy` on
//!   the daemon). Its content hash is the SHA-256 of the CBOR pair
//!   `("caution-imported-v0", <canonical artifact>)`.
//! - **V1**, the proofed bundle: `{"data": {"version": "V1", ...}, "necroproof": [...]}`. Its
//!   content hash is the SHA-256 of the canonical CBOR of `data`. The necroproof (the Keymaker
//!   enclave's attestation over that hash) is the daemon's to verify under a PCR policy; a
//!   holder has none, and does not check it here.
//!
//! The **shardfile** is keyfork-shard's: one armored OpenPGP message holding N+1 concatenated
//! encrypted messages, each a run of public-key encrypted session keys (every one to the
//! anonymous recipient, so a message cannot be found by key id) and one integrity-protected
//! data packet. Message zero is the metadata, encrypted to every holder: a version byte (1),
//! the threshold byte, then the quorum's signing certificate and the N holder certificates as
//! concatenated key packets. Messages 1..=N are one per holder in that order, each encrypted to
//! that holder's storage-encryption key only, containing a one-pass-signed literal of the
//! 33-byte share (the coordinate, the holder's position plus one, then 32 bytes), signed by the
//! metadata's signing certificate. Decrypting is [`crate::holder`]'s job; this module parses.

use crate::cbor;
use pgp::composed::{Deserializable, SignedPublicKey};
use pgp::packet::{PacketHeader, PacketParser};
use pgp::ser::Serialize as _;
use pgp::types::KeyDetails;
use pgp::types::{PacketHeaderVersion, PacketLength, Tag};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the bundle is not JSON: {0}")]
    Json(String),
    #[error("unsupported bundle format: {0}")]
    UnsupportedFormat(String),
    #[error("the bundle is not a {form} bundle: {source}")]
    Shape {
        form: Form,
        source: serde_json::Error,
    },
    #[error("a raw V0 bundle must carry an empty necroproof")]
    NecroproofOnV0,
    #[error(
        "keyring checksum mismatch: the keyring text is not the one this bundle was generated with"
    )]
    KeyringHash,
    #[error("OpenPGP: {0}")]
    OpenPgp(String),
    #[error("the bundle's {what} must be exactly one public certificate")]
    OneCertificate { what: &'static str },
    #[error("a holder certificate carries secret key material")]
    SecretInBundle,
    #[error(
        "holder {index} is a WebAuthn holder; an imported V0 bundle takes OpenPGP holders only"
    )]
    WebAuthnHolder { index: usize },
    #[error("the shardfile is not an armored OpenPGP message")]
    ShardfileArmor,
    #[error("the shardfile has an unexpected packet ({0}); expected runs of PKESKs each closed by one SEIPD")]
    ShardfilePacket(String),
    #[error(
        "the shardfile holds {0} messages; a quorum has one metadata message and 1..=254 shares"
    )]
    ShardfileCount(usize),
    #[error("the shard metadata is truncated or not version 1")]
    MetadataVersion,
    #[error("the shard metadata names no signing certificate")]
    MetadataSigner,
    #[error(
        "the quorum is inconsistent: threshold {threshold}, {holders} holders, {shares} shares"
    )]
    Quorum {
        threshold: u8,
        holders: usize,
        shares: usize,
    },
    #[error(
        "the bundle's declared threshold {declared} differs from the shard metadata's {metadata}"
    )]
    ThresholdMismatch { declared: u8, metadata: u8 },
    #[error(
        "the bundle's declared holders differ from the shard metadata's (position {position})"
    )]
    HolderMismatch { position: usize },
    #[error("the bundle's keyring and the shard metadata name different holders")]
    HolderSet,
    #[error("two holders share a certificate")]
    DuplicateHolder,
    #[error("hashing the bundle: {0}")]
    Hash(String),
}

/// Which of the three forms a bundle file is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    RawV0,
    ImportedV0,
    V1,
}

impl std::fmt::Display for Form {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Form::RawV0 => "raw V0",
            Form::ImportedV0 => "ImportedV0",
            Form::V1 => "V1",
        })
    }
}

/// A holder entry of an ImportedV0 or V1 keyring, as upstream defines it. Both kinds carry
/// the OpenPGP certificate the shard is encrypted to and the request is verified against; a
/// WebAuthn holder's credentials are Caution's hosted release flow and are not used here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Key {
    OpenPGP {
        cert: String,
    },
    WebAuthn {
        credential: Vec<String>,
        cert: String,
    },
}

impl Key {
    pub fn cert(&self) -> &str {
        match self {
            Key::OpenPGP { cert } | Key::WebAuthn { cert, .. } => cert,
        }
    }
}

/// The raw V0 object (upstream's `OriginalV0`), exactly as keymaker wrote it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawV0 {
    pub label: HashMap<String, String>,
    pub keyring: String,
    pub keyring_hash: Vec<u8>,
    pub shardfile: String,
    pub public_key: String,
    pub necroproof: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
enum ImportedFormat {
    ImportedV0,
}

/// Upstream's imported artifact. The tag is a format marker, not evidence of anything.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportedV0 {
    format: ImportedFormat,
    pub original: RawV0,
    pub threshold: u8,
    pub keyring: Vec<Key>,
}

/// Upstream's `v1::GenerateQuorumResponse`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V1 {
    pub bundle_id: [u8; 16],
    pub label: HashMap<String, String>,
    pub keyring: Vec<Key>,
    pub threshold: u8,
    pub max: u8,
    pub shardfile: String,
    pub public_key: String,
}

/// The tagged V1 bundle value: what the content hash is computed over.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "version")]
pub enum V1Bundle {
    V1(V1),
}

/// The proofed envelope keymaker returns.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proofed {
    pub data: V1Bundle,
    pub necroproof: Vec<u8>,
}

#[derive(Clone, Debug)]
enum Inner {
    RawV0(RawV0),
    ImportedV0(ImportedV0),
    V1(Proofed),
}

/// A parsed bundle of any form, with the structural checks upstream makes on load. Nothing
/// here needs a holder key; [`crate::holder`] does the decrypting.
#[derive(Clone, Debug)]
pub struct Bundle {
    inner: Inner,
}

/// What a bundle declares about its quorum in the clear: a raw V0 declares nothing but its
/// (unordered) holder set.
#[derive(Clone, Debug)]
pub struct Quorum {
    pub threshold: Option<u8>,
    /// The holders in shard order, when the form declares an order.
    pub holders: Option<Vec<SignedPublicKey>>,
}

fn pgp_err(e: impl std::fmt::Display) -> Error {
    Error::OpenPgp(e.to_string())
}

/// Every public certificate in an armored block, in file order.
pub fn certificates(armored: &str) -> Result<Vec<SignedPublicKey>, Error> {
    let (iter, _) = SignedPublicKey::from_string_many(armored).map_err(pgp_err)?;
    iter.map(|c| c.map_err(pgp_err)).collect()
}

/// A block that must hold exactly one public certificate.
pub fn one_certificate(armored: &str, what: &'static str) -> Result<SignedPublicKey, Error> {
    let mut certs = certificates(armored)?;
    if certs.len() != 1 {
        return Err(Error::OneCertificate { what });
    }
    Ok(certs.remove(0))
}

fn holder_certs(keys: &[Key]) -> Result<Vec<SignedPublicKey>, Error> {
    keys.iter()
        .map(|key| one_certificate(key.cert(), "holder entry"))
        .collect()
}

pub(crate) fn same_key(a: &SignedPublicKey, b: &SignedPublicKey) -> bool {
    a.primary_key.fingerprint().as_bytes() == b.primary_key.fingerprint().as_bytes()
}

impl RawV0 {
    fn validate(&self) -> Result<(), Error> {
        if !self.necroproof.is_empty() {
            return Err(Error::NecroproofOnV0);
        }
        if self.keyring_hash.as_slice() != Sha256::digest(self.keyring.as_bytes()).as_slice() {
            return Err(Error::KeyringHash);
        }
        let holders = certificates(&self.keyring)?;
        if holders.is_empty() {
            return Err(Error::OneCertificate { what: "keyring" });
        }
        one_certificate(&self.public_key, "public_key")?;
        Ok(())
    }
}

impl ImportedV0 {
    /// Upstream's content hash: the SHA-256 of the CBOR pair `("caution-imported-v0", artifact)`.
    pub fn content_hash(&self) -> Result<String, Error> {
        cbor::canonical_sha256(&("caution-imported-v0", self))
            .map(hex::encode)
            .map_err(|e| Error::Hash(e.to_string()))
    }
}

impl V1Bundle {
    /// Upstream's `deterministic_bundle_hash`: the SHA-256 of the canonical CBOR of the tagged
    /// bundle value, labels in canonical order, the necroproof excluded.
    pub fn content_hash(&self) -> Result<String, Error> {
        cbor::canonical_sha256(self)
            .map(hex::encode)
            .map_err(|e| Error::Hash(e.to_string()))
    }
}

impl Bundle {
    /// Parse a bundle file of any form. A `format` key names an ImportedV0 artifact (any other
    /// value is refused rather than guessed at); a `data` object with a `version` is a proofed
    /// V1; anything else must be a raw V0 with its keyring checksum intact.
    pub fn from_json(text: &str) -> Result<Self, Error> {
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|e| Error::Json(e.to_string()))?;
        let inner = match value.get("format") {
            Some(tag) if tag == "ImportedV0" => {
                let imported: ImportedV0 =
                    serde_json::from_value(value).map_err(|source| Error::Shape {
                        form: Form::ImportedV0,
                        source,
                    })?;
                imported.original.validate()?;
                let declared = holder_certs(&imported.keyring)?;
                let original = certificates(&imported.original.keyring)?;
                for (index, (key, cert)) in imported.keyring.iter().zip(&declared).enumerate() {
                    if matches!(key, Key::WebAuthn { .. }) {
                        return Err(Error::WebAuthnHolder { index });
                    }
                    if !original.iter().any(|candidate| same_key(candidate, cert)) {
                        return Err(Error::HolderSet);
                    }
                }
                let shares = Shardfile::parse(&imported.original.shardfile)?.share_count();
                check_quorum(imported.threshold, &declared, shares)?;
                Inner::ImportedV0(imported)
            }
            Some(tag) => return Err(Error::UnsupportedFormat(tag.to_string())),
            None if value.get("data").and_then(|d| d.get("version")).is_some() => {
                let proofed: Proofed =
                    serde_json::from_value(value).map_err(|source| Error::Shape {
                        form: Form::V1,
                        source,
                    })?;
                let V1Bundle::V1(v1) = &proofed.data;
                let declared = holder_certs(&v1.keyring)?;
                if usize::from(v1.max) != declared.len() {
                    return Err(Error::Quorum {
                        threshold: v1.threshold,
                        holders: declared.len(),
                        shares: usize::from(v1.max),
                    });
                }
                let shares = Shardfile::parse(&v1.shardfile)?.share_count();
                check_quorum(v1.threshold, &declared, shares)?;
                Inner::V1(proofed)
            }
            None => {
                let raw: RawV0 = serde_json::from_value(value).map_err(|source| Error::Shape {
                    form: Form::RawV0,
                    source,
                })?;
                raw.validate()?;
                let holders = certificates(&raw.keyring)?;
                let shares = Shardfile::parse(&raw.shardfile)?.share_count();
                if shares != holders.len() {
                    return Err(Error::Quorum {
                        threshold: 0,
                        holders: holders.len(),
                        shares,
                    });
                }
                Inner::RawV0(raw)
            }
        };
        Ok(Self { inner })
    }

    pub fn form(&self) -> Form {
        match &self.inner {
            Inner::RawV0(_) => Form::RawV0,
            Inner::ImportedV0(_) => Form::ImportedV0,
            Inner::V1(_) => Form::V1,
        }
    }

    pub fn label(&self) -> &HashMap<String, String> {
        match &self.inner {
            Inner::RawV0(b) => &b.label,
            Inner::ImportedV0(b) => &b.original.label,
            Inner::V1(Proofed {
                data: V1Bundle::V1(v1),
                ..
            }) => &v1.label,
        }
    }

    pub fn shardfile_text(&self) -> &str {
        match &self.inner {
            Inner::RawV0(b) => &b.shardfile,
            Inner::ImportedV0(b) => &b.original.shardfile,
            Inner::V1(Proofed {
                data: V1Bundle::V1(v1),
                ..
            }) => &v1.shardfile,
        }
    }

    pub fn shardfile(&self) -> Result<Shardfile, Error> {
        Shardfile::parse(self.shardfile_text())
    }

    /// The quorum's own certificate (what the recovered secret must derive).
    pub fn public_key(&self) -> Result<SignedPublicKey, Error> {
        let armored = match &self.inner {
            Inner::RawV0(b) => &b.public_key,
            Inner::ImportedV0(b) => &b.original.public_key,
            Inner::V1(Proofed {
                data: V1Bundle::V1(v1),
                ..
            }) => &v1.public_key,
        };
        one_certificate(armored, "public_key")
    }

    /// Every holder certificate the bundle names in the clear: in shard order for ImportedV0
    /// and V1, in keyring-file order (which is not shard order) for a raw V0.
    pub fn keyring(&self) -> Result<Vec<SignedPublicKey>, Error> {
        match &self.inner {
            Inner::RawV0(b) => certificates(&b.keyring),
            Inner::ImportedV0(b) => holder_certs(&b.keyring),
            Inner::V1(Proofed {
                data: V1Bundle::V1(v1),
                ..
            }) => holder_certs(&v1.keyring),
        }
    }

    pub fn quorum(&self) -> Result<Quorum, Error> {
        Ok(match &self.inner {
            Inner::RawV0(_) => Quorum {
                threshold: None,
                holders: None,
            },
            Inner::ImportedV0(b) => Quorum {
                threshold: Some(b.threshold),
                holders: Some(holder_certs(&b.keyring)?),
            },
            Inner::V1(Proofed {
                data: V1Bundle::V1(v1),
                ..
            }) => Quorum {
                threshold: Some(v1.threshold),
                holders: Some(holder_certs(&v1.keyring)?),
            },
        })
    }

    /// The content hash the share request carries, as upstream's daemon computes it for the
    /// same file: `None` for a raw V0, which has no hash the daemon could check.
    pub fn content_hash(&self) -> Result<Option<String>, Error> {
        Ok(match &self.inner {
            Inner::RawV0(_) => None,
            Inner::ImportedV0(b) => Some(b.content_hash()?),
            Inner::V1(proofed) => Some(proofed.data.content_hash()?),
        })
    }

    /// Check the decrypted shard metadata against what the bundle declares: the threshold and
    /// the holder order where the form declares them, and in every form that the metadata's
    /// holders are exactly the keyring's.
    pub fn check_metadata(&self, metadata: &Metadata) -> Result<(), Error> {
        let keyring = self.keyring()?;
        if keyring.len() != metadata.holders.len() {
            return Err(Error::HolderSet);
        }
        for holder in &metadata.holders {
            if !keyring.iter().any(|k| same_key(k, holder)) {
                return Err(Error::HolderSet);
            }
        }
        let quorum = self.quorum()?;
        if let Some(declared) = quorum.threshold {
            if declared != metadata.threshold {
                return Err(Error::ThresholdMismatch {
                    declared,
                    metadata: metadata.threshold,
                });
            }
        }
        if let Some(holders) = &quorum.holders {
            for (position, (declared, actual)) in holders.iter().zip(&metadata.holders).enumerate()
            {
                if !same_key(declared, actual) {
                    return Err(Error::HolderMismatch { position });
                }
            }
        }
        Ok(())
    }

    /// The ImportedV0 artifact for a raw V0 bundle, from the metadata a holder decrypted: the
    /// original as is, plus the threshold and the holders in shard order (each re-armored).
    /// Upstream's daemon takes it with `--allow-legacy`; the request's `bundle_hash` is then
    /// this artifact's content hash on both sides, so the committed artifact is the one to
    /// bake and to send with.
    pub fn import(&self, metadata: &Metadata) -> Result<ImportedV0, Error> {
        let Inner::RawV0(original) = &self.inner else {
            return Err(Error::UnsupportedFormat(format!(
                "import takes a raw V0 bundle, not {}",
                self.form()
            )));
        };
        self.check_metadata(metadata)?;
        let keyring = metadata
            .holders
            .iter()
            .map(|cert| {
                cert.to_armored_string(Default::default())
                    .map(|cert| Key::OpenPGP { cert })
                    .map_err(pgp_err)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ImportedV0 {
            format: ImportedFormat::ImportedV0,
            original: original.clone(),
            threshold: metadata.threshold,
            keyring,
        })
    }
}

fn check_quorum(threshold: u8, holders: &[SignedPublicKey], shares: usize) -> Result<(), Error> {
    if threshold == 0
        || usize::from(threshold) > holders.len()
        || holders.len() > 254
        || shares != holders.len()
    {
        return Err(Error::Quorum {
            threshold,
            holders: holders.len(),
            shares,
        });
    }
    for (i, a) in holders.iter().enumerate() {
        if holders[..i].iter().any(|b| same_key(a, b)) {
            return Err(Error::DuplicateHolder);
        }
    }
    Ok(())
}

/// One encrypted message of the shardfile: its PKESK packets and the SEIPD, kept as the
/// serialized packets so rpgp's message parser can take them as a message of their own.
#[derive(Clone, Debug)]
pub struct EncryptedMessage {
    pub(crate) bytes: Vec<u8>,
    pub pkesk_count: usize,
}

/// The parsed shardfile: message zero is the metadata, the rest one share per holder.
#[derive(Clone, Debug)]
pub struct Shardfile {
    pub messages: Vec<EncryptedMessage>,
}

impl Shardfile {
    pub fn parse(armored: &str) -> Result<Self, Error> {
        let mut dearmor = pgp::armor::Dearmor::new(armored.as_bytes());
        dearmor.read_header().map_err(|_| Error::ShardfileArmor)?;
        if !matches!(dearmor.typ, Some(pgp::armor::BlockType::Message)) {
            return Err(Error::ShardfileArmor);
        }
        let mut binary = Vec::new();
        dearmor
            .read_to_end(&mut binary)
            .map_err(|_| Error::ShardfileArmor)?;
        let mut messages = Vec::new();
        let mut current: Vec<u8> = Vec::new();
        let mut pkesks = 0usize;
        // Each packet is copied as its raw body under a fresh fixed-length header: the file's
        // own headers may use partial body lengths (sequoia streams them), and the message
        // parser wants one message's packets in plain form.
        let mut parser = PacketParser::new(binary.as_slice());
        while let Some(packet) = parser.next_ref() {
            let mut body = packet.map_err(|e| Error::ShardfilePacket(e.to_string()))?;
            let tag = body.packet_header().tag();
            let mut bytes = Vec::new();
            body.read_to_end(&mut bytes)
                .map_err(|e| Error::ShardfilePacket(e.to_string()))?;
            let len = u32::try_from(bytes.len())
                .map_err(|_| Error::ShardfilePacket("packet too large".into()))?;
            let header =
                PacketHeader::from_parts(PacketHeaderVersion::New, tag, PacketLength::Fixed(len))
                    .map_err(pgp_err)?;
            match tag {
                Tag::PublicKeyEncryptedSessionKey => pkesks += 1,
                Tag::SymEncryptedProtectedData if pkesks > 0 => {}
                other => return Err(Error::ShardfilePacket(format!("{other:?}"))),
            }
            header.to_writer(&mut current).map_err(pgp_err)?;
            current.extend_from_slice(&bytes);
            if tag == Tag::SymEncryptedProtectedData {
                messages.push(EncryptedMessage {
                    bytes: std::mem::take(&mut current),
                    pkesk_count: pkesks,
                });
                pkesks = 0;
            }
        }
        if pkesks > 0 || !(2..=255).contains(&messages.len()) {
            return Err(Error::ShardfileCount(messages.len()));
        }
        Ok(Self { messages })
    }

    /// The number of shares (messages after the metadata).
    pub fn share_count(&self) -> usize {
        self.messages.len() - 1
    }

    pub fn metadata_message(&self) -> &EncryptedMessage {
        &self.messages[0]
    }

    /// The share message of the holder at `index` (0-based position in the metadata).
    pub fn share_message(&self, index: usize) -> Option<&EncryptedMessage> {
        self.messages.get(index + 1)
    }
}

/// The decrypted metadata message: the threshold, the certificate that signs every share, and
/// the holders in shard order.
#[derive(Clone, Debug)]
pub struct Metadata {
    pub threshold: u8,
    pub signer: SignedPublicKey,
    pub holders: Vec<SignedPublicKey>,
}

impl Metadata {
    /// Decode the plaintext of message zero.
    pub fn decode(plaintext: &[u8]) -> Result<Self, Error> {
        if plaintext.len() < 2 || plaintext[0] != 1 {
            return Err(Error::MetadataVersion);
        }
        let threshold = plaintext[1];
        let iter = SignedPublicKey::from_bytes_many(&plaintext[2..]).map_err(pgp_err)?;
        let mut certs = iter
            .map(|c| c.map_err(pgp_err))
            .collect::<Result<Vec<_>, _>>()?;
        if certs.is_empty() {
            return Err(Error::MetadataSigner);
        }
        let signer = certs.remove(0);
        check_quorum(threshold, &certs, certs.len())?;
        Ok(Self {
            threshold,
            signer,
            holders: certs,
        })
    }

    /// The position of `cert`'s holder, if it is one.
    pub fn position_of(&self, cert: &SignedPublicKey) -> Option<usize> {
        self.holders.iter().position(|h| same_key(h, cert))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const RAW_V0: &str = include_str!("../tests/fixtures/locksmith-v0/bundle.json");
    pub(crate) const IMPORTED_V0: &str =
        include_str!("../tests/fixtures/locksmith-v0/imported.json");
    const V1_CONTRACT: &str = include_str!("../tests/fixtures/locksmith-v0/v1-contract.json");

    #[test]
    fn raw_v0_parses_with_two_holders_and_three_messages() {
        let bundle = Bundle::from_json(RAW_V0).unwrap();
        assert_eq!(bundle.form(), Form::RawV0);
        assert_eq!(bundle.label()["name"], "Frozen V0 test fixture");
        assert_eq!(bundle.keyring().unwrap().len(), 2);
        let shardfile = bundle.shardfile().unwrap();
        assert_eq!(shardfile.messages.len(), 3);
        assert!(shardfile.messages.iter().all(|m| m.pkesk_count >= 1));
        assert_eq!(
            shardfile.messages[0].pkesk_count, 2,
            "the metadata is encrypted to both holders"
        );
        assert_eq!(shardfile.messages[1].pkesk_count, 1);
        assert!(bundle.content_hash().unwrap().is_none());
        assert!(bundle.quorum().unwrap().threshold.is_none());
        bundle.public_key().unwrap();
    }

    #[test]
    fn imported_v0_parses_and_hashes_like_serde_cbor() {
        let bundle = Bundle::from_json(IMPORTED_V0).unwrap();
        assert_eq!(bundle.form(), Form::ImportedV0);
        let quorum = bundle.quorum().unwrap();
        assert_eq!(quorum.threshold, Some(2));
        assert_eq!(quorum.holders.unwrap().len(), 2);
        let Inner::ImportedV0(imported) = &bundle.inner else {
            panic!()
        };
        let ours = imported.content_hash().unwrap();
        let value = serde_cbor::value::to_value(imported).unwrap();
        let theirs = hex::encode(Sha256::digest(
            serde_cbor::to_vec(&("caution-imported-v0", value)).unwrap(),
        ));
        assert_eq!(ours, theirs);
        assert_eq!(
            bundle.content_hash().unwrap().as_deref(),
            Some(ours.as_str())
        );
    }

    #[test]
    fn v1_hash_matches_upstreams_contract_fixture() {
        let fixture: serde_json::Value = serde_json::from_str(V1_CONTRACT).unwrap();
        let quorum = &fixture["quorum"];
        let data: V1Bundle = serde_json::from_value(quorum["data"].clone()).unwrap();
        assert_eq!(
            hex::encode(cbor::to_canonical_vec(&data).unwrap()),
            quorum["cbor_hex"].as_str().unwrap()
        );
        assert_eq!(
            data.content_hash().unwrap(),
            quorum["sha256"].as_str().unwrap()
        );
        // The same hash through the serde_cbor oracle upstream uses.
        let theirs = hex::encode(Sha256::digest(
            serde_cbor::to_vec(&serde_cbor::value::to_value(&data).unwrap()).unwrap(),
        ));
        assert_eq!(data.content_hash().unwrap(), theirs);
    }

    #[test]
    fn malformed_and_inconsistent_bundles_are_refused() {
        for text in [
            "{}",
            "null",
            "[]",
            r#"{"data":{"version":"V1"},"necroproof":[]}"#,
            r#"{"format":"Other"}"#,
        ] {
            assert!(Bundle::from_json(text).is_err(), "{text}");
        }
        let mut raw: serde_json::Value = serde_json::from_str(RAW_V0).unwrap();
        raw["keyring_hash"] = serde_json::json!([0]);
        assert!(matches!(
            Bundle::from_json(&raw.to_string()),
            Err(Error::KeyringHash)
        ));
        let mut raw: serde_json::Value = serde_json::from_str(RAW_V0).unwrap();
        raw["shardfile"] = serde_json::json!("");
        assert!(matches!(
            Bundle::from_json(&raw.to_string()),
            Err(Error::ShardfileArmor)
        ));
        let mut raw: serde_json::Value = serde_json::from_str(RAW_V0).unwrap();
        raw["necroproof"] = serde_json::json!([1]);
        assert!(matches!(
            Bundle::from_json(&raw.to_string()),
            Err(Error::NecroproofOnV0)
        ));
        let mut imported: serde_json::Value = serde_json::from_str(IMPORTED_V0).unwrap();
        imported["threshold"] = serde_json::json!(3);
        assert!(matches!(
            Bundle::from_json(&imported.to_string()),
            Err(Error::Quorum { .. })
        ));
        let mut imported: serde_json::Value = serde_json::from_str(IMPORTED_V0).unwrap();
        let first = imported["keyring"][0].clone();
        imported["keyring"][1] = first;
        assert!(matches!(
            Bundle::from_json(&imported.to_string()),
            Err(Error::DuplicateHolder)
        ));
        for bytes in [vec![], vec![1], vec![9, 2], vec![1, 2]] {
            assert!(Metadata::decode(&bytes).is_err());
        }
        let public_key = Bundle::from_json(RAW_V0).unwrap().public_key().unwrap();
        assert!(
            Shardfile::parse(&public_key.to_armored_string(Default::default()).unwrap()).is_err()
        );
        assert!(Shardfile::parse("garbage").is_err());
    }
}
