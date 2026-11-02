//! The shard holder's client for a rose enclave deployment.
//!
//! A deployment of `rosed` in an AWS Nitro enclave starts with no secrets: Locksmith's
//! `locksmithd` inside the enclave waits for a threshold of holders to release their Shamir
//! shares of the quorum secret, recombines it, and decrypts the wallet's secrets with it.
//! This crate is what a holder runs on their own machine to release one share, speaking
//! Locksmith's recovery protocol as it stands upstream today, in pure Rust and from
//! crates.io: no git dependencies, no private registry, no C libraries, and a license a
//! client written to a wire protocol can carry.
//!
//! - [`nitro`]: parse and verify a Nitro attestation document against a set of PCRs.
//! - [`bundle`]: the quorum bundle (three forms), its shardfile, and its content hash.
//! - [`holder`]: this holder's share out of the shardfile, and the signature over the request.
//! - [`protocol`]: the three frames, the session key, the signed request, the reply.
//!
//! The protocol, in one paragraph: the client sends a nonce; the enclave answers with an
//! attestation document whose `nonce` is that nonce and whose `user_data` is a fresh X25519
//! public key; the client verifies the document (AWS chain, signature, PCR0-2, nonce), derives
//! an AES-256-GCM key from an ephemeral X25519 exchange, encrypts the share request to it,
//! signs the encrypted request with the holder's OpenPGP key and sends it; the enclave answers
//! `Accepted` or `Rejected`. Each step is its own module so a deployment can also check a
//! saved document (`attestation-check`) or inspect a bundle without a network.

pub mod bundle;
pub mod cbor;
pub mod holder;
pub mod nitro;
pub mod protocol;

#[cfg(any(test, feature = "test-server"))]
pub mod test_server;

#[cfg(any(test, feature = "test-server"))]
pub mod test_keys;

pub use nitro::{Attestation, Pcrs, Verifier};
