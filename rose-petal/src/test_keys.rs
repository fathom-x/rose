//! Freshly generated holder certificates for the tests and the test server: a certifying
//! primary with a signing subkey and a storage-encryption subkey, the layout keyfork and
//! sequoia's `CertBuilder` both produce.

use pgp::composed::{
    EncryptionCaps, KeyType, SecretKeyParamsBuilder, SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::types::KeyVersion;

pub fn generate(name: &str) -> SignedSecretKey {
    let rng = rand::rngs::OsRng;
    let params = SecretKeyParamsBuilder::default()
        .version(KeyVersion::V4)
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(false)
        .can_encrypt(EncryptionCaps::None)
        .primary_user_id(format!("{name} <{name}@test.invalid>"))
        .subkey(
            SubkeyParamsBuilder::default()
                .version(KeyVersion::V4)
                .key_type(KeyType::Ed25519Legacy)
                .can_sign(true)
                .build()
                .expect("subkey params"),
        )
        .subkey(
            SubkeyParamsBuilder::default()
                .version(KeyVersion::V4)
                .key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
                .can_encrypt(EncryptionCaps::Storage)
                .build()
                .expect("subkey params"),
        )
        .build()
        .expect("key params");
    params.generate(rng).expect("key generation")
}
