//! Locksmith's recovery protocol, as the client speaks it.
//!
//! Plain TCP, port 49504 by convention, no TLS: security rests on the attestation (the
//! enclave proves what it runs and binds a fresh key to the connection), the ECDH session
//! (only that enclave can read the share) and the holder's signature (only a holder can
//! submit). Three frames and a reply:
//!
//! 1. Client: `{"nonce": "<24 lowercase hex chars>"}`. The server hands those 24 ASCII bytes
//!    to the NSM, so the attested nonce is the string's bytes, not the 12 random bytes behind
//!    them.
//! 2. Server: `{"attestation": [..bytes..]}`, a Nitro document whose `user_data` is the
//!    enclave's X25519 public key for this connection.
//! 3. Client: `{"signed_payload": "<string>", "signature": "<armored detached signature>"}`.
//!    The signed string is the JSON text of `{"encrypted_payload": "<hex>", "public_key":
//!    [..32..]}`, exactly as signed, fields in that order; the hex is AES-256-GCM over the JSON
//!    of `{"shard": [..33..], "threshold": n, "bundle_hash": "<hex>"}` (the hash omitted when
//!    the bundle has none), tag appended. The signature is text-mode, by the holder's key.
//!
//! The reply is `{"Accepted":{"remaining":n}}` once the share has been counted, or
//! `{"Rejected":{"reason":"..."}}`. A hex or AEAD failure closes the socket with no reply, so
//! end of stream after frame 3 is a rejection with no reason.
//!
//! Framing, both directions: a 4-byte big-endian length, the SHA-256 of the body, the body
//! (the length counts both, so body length plus 32). The server accepts lengths in
//! 32..=1 MiB, waits at most 10 s for the first frame, holds a connection at most 300 s and
//! serves at most 32 at once, dropping the rest unanswered; the client imposes the same bounds
//! on what it reads. The session key is HKDF-SHA256 with no salt over the X25519 shared
//! secret: info `key` expands to the 32-byte AES-256-GCM key, info `nonce` to the 12-byte GCM
//! nonce. One key, one message, so a derived nonce is fine.

use crate::holder::{Holder, Release, Share};
use crate::nitro::{At, Attestation, Expected, Pcrs, Verifier};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use pgp::types::Password;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Locksmith's recovery port.
pub const DEFAULT_PORT: u16 = 49504;
/// The largest frame body (checksum included) either side accepts.
pub const MAX_FRAME_BODY: u32 = 1024 * 1024;
/// The smallest: a checksum with nothing after it.
pub const MIN_FRAME_BODY: u32 = 32;
/// The server's patience for the first frame.
pub const FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(10);
/// The server's cap on one connection.
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame length {0} is outside {MIN_FRAME_BODY}..={MAX_FRAME_BODY}")]
    InvalidLength(u32),
    #[error("the frame's checksum does not match its body")]
    BadChecksum,
    #[error("reading a frame: {0}")]
    Io(#[from] std::io::Error),
    #[error("a frame body of {0} bytes cannot be framed")]
    TooLarge(usize),
}

/// Encode one frame: length, SHA-256, body.
pub fn encode_frame(body: &[u8]) -> Result<Vec<u8>, FrameError> {
    let len = u32::try_from(body.len() + 32).map_err(|_| FrameError::TooLarge(body.len()))?;
    let mut out = Vec::with_capacity(4 + len as usize);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&Sha256::digest(body));
    out.extend_from_slice(body);
    Ok(out)
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    body: &[u8],
) -> Result<(), FrameError> {
    writer.write_all(&encode_frame(body)?).await?;
    Ok(())
}

/// Read one frame: the length is checked before anything is allocated, the checksum before
/// the body is returned.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, FrameError> {
    let len = reader.read_u32().await?;
    if !(MIN_FRAME_BODY..=MAX_FRAME_BODY).contains(&len) {
        return Err(FrameError::InvalidLength(len));
    }
    let mut data = vec![0u8; len as usize];
    reader.read_exact(&mut data).await?;
    let (checksum, body) = data.split_at(32);
    if Sha256::digest(body).as_slice() != checksum {
        return Err(FrameError::BadChecksum);
    }
    Ok(body.to_vec())
}

/// Frame 1.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NonceRequest {
    pub nonce: String,
}

/// Frame 2.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationResponse {
    pub attestation: Vec<u8>,
}

/// Frame 3.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedRequest {
    pub signed_payload: String,
    pub signature: String,
}

/// What frame 3's `signed_payload` is the JSON text of. Field order matters: the server
/// verifies the signature over the text as sent, then parses it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedRequest {
    pub encrypted_payload: String,
    pub public_key: [u8; 32],
}

/// What the `encrypted_payload` encrypts.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareRequest {
    pub shard: Vec<u8>,
    pub threshold: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_hash: Option<String>,
}

/// The reply.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Reply {
    Accepted { remaining: u8 },
    Rejected { reason: String },
}

/// The session key for one connection: derived by both sides from the X25519 exchange.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Session {
    key: [u8; 32],
    nonce: [u8; 12],
}

impl Session {
    /// Derive from the shared secret: HKDF-SHA256, no salt, info `key` and `nonce`.
    pub fn derive(shared_secret: &[u8; 32]) -> Self {
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        hkdf.expand(b"key", &mut key)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        hkdf.expand(b"nonce", &mut nonce)
            .expect("12 bytes is a valid HKDF-SHA256 output length");
        Self { key, nonce }
    }

    /// The client side: an ephemeral key against the enclave's attested public key. Returns
    /// our public key (for the request) and the session.
    pub fn client(their_public_key: [u8; 32]) -> Result<([u8; 32], Self), Error> {
        let secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let our_public = PublicKey::from(&secret).to_bytes();
        let session = Self::server(secret, their_public_key)?;
        Ok((our_public, session))
    }

    /// Either side's derivation from its own ephemeral secret and the peer's public key.
    pub fn server(secret: EphemeralSecret, their_public_key: [u8; 32]) -> Result<Self, Error> {
        let shared = secret.diffie_hellman(&PublicKey::from(their_public_key));
        if !shared.was_contributory() {
            return Err(Error::LowOrderKey);
        }
        Ok(Self::derive(shared.as_bytes()))
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        Aes256Gcm::new_from_slice(&self.key)
            .expect("32-byte key")
            .encrypt(Nonce::from_slice(&self.nonce), plaintext)
            .expect("AES-GCM encryption of a short message does not fail")
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        Aes256Gcm::new_from_slice(&self.key)
            .expect("32-byte key")
            .decrypt(Nonce::from_slice(&self.nonce), ciphertext)
            .ok()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("connecting to {addr}: {source}")]
    Connect {
        addr: SocketAddr,
        source: std::io::Error,
    },
    #[error("the enclave did not answer within {0:?}")]
    Timeout(Duration),
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("the enclave sent something other than the expected JSON: {0}")]
    Json(String),
    #[error("the enclave's attestation was refused: {0}")]
    Attestation(#[from] crate::nitro::Error),
    #[error("the expected PCRs are all zero: a debug enclave, whose attestation proves nothing; refused unless allowed explicitly")]
    DebugEnclave,
    #[error("the attested user_data is {0} bytes, not a 32-byte X25519 public key")]
    UserData(usize),
    #[error("the enclave's public key is a low-order point")]
    LowOrderKey,
    #[error(transparent)]
    Holder(#[from] crate::holder::Error),
    #[error("the enclave closed the connection without a reply: a rejection it gives no reason for (a malformed or undecryptable request), or a quorum that is already complete")]
    ClosedWithoutReply,
}

/// How a release is checked and sent.
pub struct SendOptions {
    /// The PCRs the enclave must attest.
    pub pcrs: Pcrs,
    /// Send to a debug enclave (all-zero expected PCRs) anyway.
    pub allow_zero_pcrs: bool,
    /// The trusted root; [`Verifier::aws`] for anything real.
    pub verifier: Verifier,
    /// When the chain is checked; `None` is now.
    pub at: Option<At>,
    /// Patience for each network step.
    pub timeout: Duration,
}

impl SendOptions {
    pub fn new(pcrs: Pcrs) -> Self {
        Self {
            pcrs,
            allow_zero_pcrs: false,
            verifier: Verifier::aws(),
            at: None,
            timeout: Duration::from_secs(120),
        }
    }
}

/// A random 12-byte nonce as the 24 lowercase hex characters frame 1 carries.
pub fn fresh_nonce() -> String {
    hex::encode(rand::random::<[u8; 12]>())
}

/// The request as the share holder builds it, before encryption.
pub fn share_request(share: &Share, threshold: u8, bundle_hash: Option<String>) -> ShareRequest {
    ShareRequest {
        shard: share.to_vec(),
        threshold,
        bundle_hash,
    }
}

/// Release one share to the enclave at `addr`: the whole exchange, with the share already in
/// hand (so no prompt holds a connection open). Returns the enclave's reply.
pub async fn send_shard(
    addr: SocketAddr,
    release: &Release<'_>,
    bundle_hash: Option<String>,
    password: &Password,
    options: &SendOptions,
) -> Result<Reply, Error> {
    let request = share_request(&release.share, release.metadata.threshold, bundle_hash);
    send_request(addr, &request, &release.holder, password, options).await
}

/// The exchange for any request: what [`send_shard`] does once it has built the request from a
/// release. The server's own checks are what reject a request that does not match the bundle.
pub async fn send_request(
    addr: SocketAddr,
    request: &ShareRequest,
    holder: &Holder<'_>,
    password: &Password,
    options: &SendOptions,
) -> Result<Reply, Error> {
    if options.pcrs.is_debug() && !options.allow_zero_pcrs {
        return Err(Error::DebugEnclave);
    }
    let mut stream = tokio::time::timeout(options.timeout, tokio::net::TcpStream::connect(addr))
        .await
        .map_err(|_| Error::Timeout(options.timeout))?
        .map_err(|source| Error::Connect { addr, source })?;

    let nonce = fresh_nonce();
    let frame1 = serde_json::to_vec(&NonceRequest {
        nonce: nonce.clone(),
    })
    .expect("serializable");
    write_frame(&mut stream, &frame1).await?;
    let frame2 = tokio::time::timeout(options.timeout, read_frame(&mut stream))
        .await
        .map_err(|_| Error::Timeout(options.timeout))??;
    let response: AttestationResponse =
        serde_json::from_slice(&frame2).map_err(|e| Error::Json(e.to_string()))?;

    let attestation = Attestation::parse(&response.attestation)?;
    options.verifier.verify(
        &attestation,
        options.at.unwrap_or_else(At::now),
        Expected {
            pcrs: &options.pcrs,
            nonce: Some(nonce.as_bytes()),
        },
    )?;
    let user_data = attestation.user_data.as_deref().unwrap_or(&[]);
    let their_public: [u8; 32] = user_data
        .try_into()
        .map_err(|_| Error::UserData(user_data.len()))?;

    let (our_public, session) = Session::client(their_public)?;
    let plaintext = serde_json::to_vec(request).expect("serializable");
    let encrypted = EncryptedRequest {
        encrypted_payload: hex::encode(session.encrypt(&plaintext)),
        public_key: our_public,
    };
    let signed_payload = serde_json::to_string(&encrypted).expect("serializable");
    let signature = holder.sign(&signed_payload, password)?;
    let frame3 = serde_json::to_vec(&SignedRequest {
        signed_payload,
        signature,
    })
    .expect("serializable");
    write_frame(&mut stream, &frame3).await?;
    read_reply(&mut stream, options.timeout).await
}

/// Frame 4, or the closed connection that stands for a rejection without a reason.
pub async fn read_reply<R: AsyncRead + Unpin>(
    stream: &mut R,
    timeout: Duration,
) -> Result<Reply, Error> {
    let reply = match tokio::time::timeout(timeout, read_frame(stream)).await {
        Err(_) => return Err(Error::Timeout(timeout)),
        Ok(Err(FrameError::Io(e))) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(Error::ClosedWithoutReply)
        }
        Ok(frame) => frame?,
    };
    serde_json::from_slice(&reply).map_err(|e| Error::Json(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn invalid_lengths_fail_with_only_a_header() {
        for length in [0u32, 1, 31, MAX_FRAME_BODY + 1, u32::MAX] {
            let (mut peer, mut reader) = tokio::io::duplex(4);
            peer.write_u32(length).await.unwrap();
            let result = tokio::time::timeout(Duration::from_secs(1), read_frame(&mut reader))
                .await
                .expect("an invalid length must not wait for a body");
            assert!(matches!(result, Err(FrameError::InvalidLength(l)) if l == length));
        }
    }

    #[tokio::test]
    async fn frames_roundtrip_at_the_limits_and_fail_when_damaged() {
        let max = vec![b'x'; MAX_FRAME_BODY as usize - 32];
        let frame = encode_frame(&max).unwrap();
        assert_eq!(frame.len(), MAX_FRAME_BODY as usize + 4);
        assert_eq!(read_frame(&mut frame.as_slice()).await.unwrap(), max);
        let one_over = encode_frame(&vec![0u8; MAX_FRAME_BODY as usize - 31]).unwrap();
        assert!(
            matches!(read_frame(&mut one_over.as_slice()).await, Err(FrameError::InvalidLength(l)) if l == MAX_FRAME_BODY + 1)
        );

        let empty = encode_frame(b"").unwrap();
        assert_eq!(empty.len(), 36);
        assert!(read_frame(&mut empty.as_slice()).await.unwrap().is_empty());

        let mut frame = encode_frame(b"{}").unwrap();
        for truncated in [&frame[..2], &frame[..frame.len() - 1]] {
            let mut r = truncated;
            assert!(matches!(read_frame(&mut r).await, Err(FrameError::Io(_))));
        }
        frame[4] ^= 1;
        assert!(matches!(
            read_frame(&mut frame.as_slice()).await,
            Err(FrameError::BadChecksum)
        ));
        let mut frame = encode_frame(b"{}").unwrap();
        let last = frame.len() - 1;
        frame[last] ^= 1;
        assert!(matches!(
            read_frame(&mut frame.as_slice()).await,
            Err(FrameError::BadChecksum)
        ));
    }

    #[tokio::test]
    async fn consecutive_frames_are_not_overread_and_trailing_bytes_stay() {
        let mut frames = encode_frame(b"1").unwrap();
        frames.extend(encode_frame(b"2").unwrap());
        frames.extend(b"tail");
        let mut reader = frames.as_slice();
        assert_eq!(read_frame(&mut reader).await.unwrap(), b"1");
        assert_eq!(read_frame(&mut reader).await.unwrap(), b"2");
        assert_eq!(reader, b"tail");
    }

    #[test]
    fn models_serialize_as_the_wire_expects() {
        assert_eq!(
            serde_json::to_string(&NonceRequest {
                nonce: "ab".repeat(12)
            })
            .unwrap(),
            format!(r#"{{"nonce":"{}"}}"#, "ab".repeat(12))
        );
        let request = ShareRequest {
            shard: vec![1; 33],
            threshold: 2,
            bundle_hash: None,
        };
        let text = serde_json::to_string(&request).unwrap();
        assert!(text.starts_with(r#"{"shard":[1,1,"#));
        assert!(text.ends_with(r#"],"threshold":2}"#), "{text}");
        let with_hash = ShareRequest {
            bundle_hash: Some("ab".into()),
            ..request.clone()
        };
        assert!(serde_json::to_string(&with_hash)
            .unwrap()
            .ends_with(r#","threshold":2,"bundle_hash":"ab"}"#));
        // The pinned daemon's model has no bundle_hash; upstream's accepts its absence.
        assert_eq!(
            serde_json::from_str::<ShareRequest>(r#"{"shard":[1],"threshold":1}"#)
                .unwrap()
                .bundle_hash,
            None
        );
        let encrypted = EncryptedRequest {
            encrypted_payload: "ab".into(),
            public_key: [7; 32],
        };
        let text = serde_json::to_string(&encrypted).unwrap();
        assert!(text.starts_with(r#"{"encrypted_payload":"ab","public_key":[7,7,"#));
        assert_eq!(
            serde_json::to_string(&Reply::Accepted { remaining: 1 }).unwrap(),
            r#"{"Accepted":{"remaining":1}}"#
        );
        assert_eq!(
            serde_json::from_str::<Reply>(r#"{"Rejected":{"reason":"x"}}"#).unwrap(),
            Reply::Rejected { reason: "x".into() }
        );
        assert_eq!(fresh_nonce().len(), 24);
        assert!(fresh_nonce()
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn both_sides_derive_the_same_session_and_the_key_differs_from_the_nonce() {
        let server_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let server_public = PublicKey::from(&server_secret).to_bytes();
        let (client_public, client) = Session::client(server_public).unwrap();
        let server = Session::server(server_secret, client_public).unwrap();
        assert_eq!(client.key, server.key);
        assert_eq!(client.nonce, server.nonce);
        assert_ne!(&client.key[..12], &client.nonce[..]);
        let ciphertext = client.encrypt(b"share");
        assert_eq!(ciphertext.len(), 5 + 16);
        assert_eq!(server.decrypt(&ciphertext).unwrap(), b"share");
        let mut damaged = ciphertext.clone();
        damaged[0] ^= 1;
        assert!(server.decrypt(&damaged).is_none());
        assert!(matches!(Session::client([0; 32]), Err(Error::LowOrderKey)));
    }

    #[test]
    fn session_derivation_is_the_documented_hkdf() {
        // Reference: HKDF-SHA256(salt = none, ikm = shared), info "key" -> 32, info "nonce" -> 12.
        let shared = [0x42u8; 32];
        let session = Session::derive(&shared);
        let hk = Hkdf::<Sha256>::new(None, &shared);
        let mut key = [0u8; 32];
        hk.expand(b"key", &mut key).unwrap();
        let mut nonce = [0u8; 12];
        hk.expand(b"nonce", &mut nonce).unwrap();
        assert_eq!(session.key, key);
        assert_eq!(session.nonce, nonce);
    }
}
