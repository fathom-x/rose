// Send one holder's shard to a Locksmith enclave at an address of our choosing: what
// `caution secret send-shard` does after it has asked the Caution API where the enclave is.
// For an enclave a deployment hosts itself (rose-deploy's docs/NITRO.md), where no API knows
// the address. Built as a bin of Locksmith's own crate at its pinned commit (build.sh, and
// the holder-tools workflow for the released binaries).
//
//   locksmith-send-shard <ip:port> <trusted_hashes.json> <quorum-bundle.json> [holder-private-keyring.asc | dir]
//
// Everything that matters happens in Locksmith's own client (locksmith::client::send_shard):
// it sends a fresh nonce, verifies the enclave's Nitro attestation against the PCRs in the
// hashes file (the AWS root, the nonce, PCR0-2), takes the enclave's public key from the
// attested user_data, decrypts this holder's shard with the keyring, re-encrypts it to that
// key and signs the request. A wrong PCR fails before the shard is decrypted. This file only
// turns a hashes file into the PCR map and reports the answer.

use keymaker_models::generate_quorum::v0::GenerateQuorumResponse;

fn pcr(hashes: &serde_json::Value, n: u8) -> Vec<u8> {
    let key = format!("pcr{n}");
    let hex = hashes[&key]
        .as_str()
        .unwrap_or_else(|| panic!("the hashes file has no {key}"));
    let bytes = smex::decode_to_vec(hex).unwrap_or_else(|e| panic!("{key} is not hex: {e}"));
    assert!(bytes.len() == 48, "{key} is {} bytes, not 48", bytes.len());
    if bytes.iter().all(|b| *b == 0) {
        // A debug enclave attests all-zero PCRs: the attestation then proves nothing about
        // what runs, and the console shows everything. Only with the operator's explicit say-so.
        if std::env::var("LOCKSMITH_ALLOW_ZERO_PCRS").as_deref() != Ok("1") {
            panic!("{key} is all zero: a debug enclave; refused unless LOCKSMITH_ALLOW_ZERO_PCRS=1 (--debug-zero-pcrs)");
        }
        eprintln!("WARNING: {key} is all zero; sending to a DEBUG enclave whose attestation proves nothing");
    }
    bytes
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (address, hashes_path, bundle_path, keyring) = match args.as_slice() {
        [a, h, b] => (a, h, b, None),
        [a, h, b, k] => (a, h, b, Some(std::path::PathBuf::from(k))),
        _ => {
            eprintln!("usage: locksmith-send-shard <ip:port> <trusted_hashes.json> <quorum-bundle.json> [holder keyring]");
            std::process::exit(2);
        }
    };
    let address: std::net::SocketAddr = address.parse().expect("address is ip:port, port 49504");
    let hashes: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(hashes_path).expect("hashes file readable"))
            .expect("hashes file is JSON");
    let pcrs = std::collections::HashMap::from_iter([(0u8, pcr(&hashes, 0)), (1, pcr(&hashes, 1)), (2, pcr(&hashes, 2))]);
    if let Some(at) = hashes["verified_at"].as_str() {
        eprintln!("trusted hashes verified at {at}");
    }
    let bundle: GenerateQuorumResponse =
        serde_json::from_str(&std::fs::read_to_string(bundle_path).expect("bundle readable"))
            .expect("bundle is a quorum bundle");

    eprintln!("sending the shard to {address} (attestation checked against the hashes first)");
    let status = locksmith::client::send_shard(address, pcrs, &bundle, keyring)
        .await
        .unwrap_or_else(|e| {
            eprintln!("error: {e}");
            let mut src = std::error::Error::source(&e);
            while let Some(s) = src {
                eprintln!("  caused by: {s}");
                src = s.source();
            }
            std::process::exit(1);
        });
    match status {
        locksmith::models::SendSignedEncryptedShardResponse::Accepted { remaining } => {
            eprintln!("shard accepted; {remaining} more until the enclave reconstitutes the secret");
        }
        locksmith::models::SendSignedEncryptedShardResponse::Rejected { reason } => {
            eprintln!("shard rejected: {reason}");
            std::process::exit(1);
        }
    }
}
