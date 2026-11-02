//! The shard holder's command line.
//!
//!   rose-petal send <host[:port]> <trusted_hashes.json> <bundle.json> --keyring <file|dir>
//!                   [--holder FINGERPRINT] [--allow-zero-pcrs] [--timeout SECS]
//!                   [--passphrase-file FILE]
//!   rose-petal inspect <bundle.json> [--keyring <file|dir>] [--holder FINGERPRINT]
//!   rose-petal import <bundle.json> --keyring <file|dir> [--holder FINGERPRINT] [--out FILE]
//!
//! `send` releases this holder's share to the Locksmith enclave at the address (port 49504
//! when none is given): the share is decrypted and checked first, then the enclave's
//! attestation is verified against the hashes file (AWS chain, PCR0-2, the nonce of this
//! connection), and only then is the share encrypted to the attested key, signed and sent.
//! Exit 0 when the enclave accepted it, 1 when it rejected it or anything failed, 2 for usage.
//! All-zero PCRs in the hashes file mean a debug enclave whose attestation proves nothing:
//! refused unless `--allow-zero-pcrs`.
//!
//! `inspect` prints what a bundle declares and, with a keyring, what its encrypted metadata
//! says (threshold, holders in shard order, this holder's position), decrypting no share.
//!
//! `import` writes upstream's ImportedV0 artifact for a raw V0 bundle: the threshold and the
//! ordered holders out of the metadata, which the current Locksmith daemon takes with
//! `--allow-legacy` and whose content hash both sides then check.
//!
//! Two flags exist for rehearsals against the crate's own test server and nothing else:
//! `--trust-root FILE` replaces AWS's root with a DER certificate, and `--verify-at SECONDS`
//! checks the chain at that Unix time instead of now. Either prints a warning; a holder
//! releasing a share to a real enclave never passes them. With the `test-server` feature,
//! `rose-petal test-server <bundle.json> --keyring <file> [--listen ADDR]` runs that stand-in.

use pgp::types::Password;
use rose_petal::bundle::Bundle;
use rose_petal::holder::{fingerprint_hex, prepare, Keyring};
use rose_petal::nitro::Pcrs;
use rose_petal::protocol::{send_shard, Reply, SendOptions, DEFAULT_PORT};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

const USAGE: &str = "usage:
  rose-petal send <host[:port]> <trusted_hashes.json> <bundle.json> --keyring <file|dir>
                  [--holder FINGERPRINT] [--allow-zero-pcrs] [--timeout SECS] [--passphrase-file FILE]
  rose-petal inspect <bundle.json> [--keyring <file|dir>] [--holder FINGERPRINT] [--passphrase-file FILE]
  rose-petal import <bundle.json> --keyring <file|dir> [--holder FINGERPRINT] [--out FILE] [--passphrase-file FILE]
  rose-petal --version
rehearsal only (against the crate's test server, never a real enclave):
  send ... --trust-root <root.der> --verify-at <unix seconds>
  rose-petal test-server <bundle.json> --keyring <file|dir> [--listen 127.0.0.1:0] [--trust-root/--verify-at as above]";

fn usage() -> ! {
    eprintln!("{USAGE}");
    std::process::exit(2)
}

fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1)
}

#[derive(Default)]
struct Args {
    positional: Vec<String>,
    keyring: Option<PathBuf>,
    holder: Option<String>,
    allow_zero_pcrs: bool,
    timeout: Option<u64>,
    passphrase_file: Option<PathBuf>,
    out: Option<PathBuf>,
    trust_root: Option<PathBuf>,
    verify_at: Option<u64>,
    listen: Option<String>,
}

fn parse_args() -> (String, Args) {
    let mut raw = std::env::args().skip(1);
    let Some(command) = raw.next() else { usage() };
    if command == "--version" || command == "-V" {
        println!("rose-petal {}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }
    if command == "--help" || command == "-h" {
        println!("{USAGE}");
        std::process::exit(0);
    }
    let mut args = Args::default();
    while let Some(a) = raw.next() {
        match a.as_str() {
            "--keyring" => args.keyring = raw.next().map(PathBuf::from),
            "--holder" => args.holder = raw.next(),
            "--allow-zero-pcrs" => args.allow_zero_pcrs = true,
            "--timeout" => args.timeout = raw.next().map(|s| s.parse().unwrap_or_else(|_| usage())),
            "--passphrase-file" => args.passphrase_file = raw.next().map(PathBuf::from),
            "--out" | "-o" => args.out = raw.next().map(PathBuf::from),
            "--trust-root" => args.trust_root = raw.next().map(PathBuf::from),
            "--verify-at" => {
                args.verify_at = raw.next().map(|s| s.parse().unwrap_or_else(|_| usage()))
            }
            "--listen" => args.listen = raw.next(),
            s if s.starts_with('-') => usage(),
            _ => args.positional.push(a),
        }
    }
    (command, args)
}

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| fail(format!("{path}: {e}")))
}

fn load_keyring(args: &Args) -> Keyring {
    let path = args.keyring.as_ref().unwrap_or_else(|| usage());
    Keyring::load(path).unwrap_or_else(|e| fail(e))
}

/// The passphrase for a locked keyring: from the file named, else asked on the terminal.
fn password(keyring: &Keyring, args: &Args) -> Password {
    if !keyring.any_locked() {
        return Password::empty();
    }
    if let Some(file) = &args.passphrase_file {
        let text = std::fs::read_to_string(file)
            .unwrap_or_else(|e| fail(format!("{}: {e}", file.display())));
        return Password::from(text.trim_end_matches(['\r', '\n']));
    }
    let text =
        rpassword::prompt_password("the keyring is locked; passphrase: ").unwrap_or_else(|e| {
            fail(format!(
                "no passphrase: {e} (use --passphrase-file without a terminal)"
            ))
        });
    Password::from(text)
}

fn resolve(target: &str) -> SocketAddr {
    let with_port = if target
        .rsplit_once(':')
        .is_some_and(|(host, port)| port.parse::<u16>().is_ok() && !host.is_empty())
    {
        target.to_string()
    } else {
        format!("{target}:{DEFAULT_PORT}")
    };
    with_port
        .to_socket_addrs()
        .unwrap_or_else(|e| fail(format!("{target}: {e}")))
        .next()
        .unwrap_or_else(|| fail(format!("{target}: no address")))
}

fn describe(bundle: &Bundle) {
    eprintln!(
        "bundle: {} form, label {}",
        bundle.form(),
        serde_json::to_string(bundle.label()).unwrap_or_default()
    );
    match bundle.quorum() {
        Ok(q) => {
            if let Some(t) = q.threshold {
                eprintln!("declared threshold {t}");
            }
            if let Some(h) = q.holders {
                for (i, cert) in h.iter().enumerate() {
                    eprintln!(
                        "declared holder {}: {}",
                        i + 1,
                        fingerprint_hex(&cert.primary_key)
                    );
                }
            }
        }
        Err(e) => fail(e),
    }
    match bundle.content_hash() {
        Ok(Some(hash)) => eprintln!("bundle hash {hash}"),
        Ok(None) => eprintln!("bundle hash: none (a raw V0 bundle carries none; `rose-petal import` makes the artifact that has one)"),
        Err(e) => fail(e),
    }
}

fn main() {
    let (command, args) = parse_args();
    match command.as_str() {
        "send" => send(args),
        "inspect" => inspect(args),
        "import" => import(args),
        #[cfg(feature = "test-server")]
        "test-server" => test_server(args),
        _ => usage(),
    }
}

fn inspect(args: Args) {
    let [bundle_path] = args.positional.as_slice() else {
        usage()
    };
    let bundle = Bundle::from_json(&read(bundle_path)).unwrap_or_else(|e| fail(e));
    describe(&bundle);
    let keyring_certs = bundle.keyring().unwrap_or_else(|e| fail(e));
    eprintln!("keyring: {} certificate(s)", keyring_certs.len());
    if args.keyring.is_none() {
        eprintln!("(no --keyring: the encrypted metadata was not read)");
        return;
    }
    let keyring = load_keyring(&args);
    let password = password(&keyring, &args);
    let shardfile = bundle.shardfile().unwrap_or_else(|e| fail(e));
    let metadata = keyring
        .decrypt_metadata(&shardfile, &password)
        .unwrap_or_else(|e| fail(e));
    eprintln!(
        "metadata: threshold {} of {}",
        metadata.threshold,
        metadata.holders.len()
    );
    for (i, cert) in metadata.holders.iter().enumerate() {
        eprintln!("holder {}: {}", i + 1, fingerprint_hex(&cert.primary_key));
    }
    bundle.check_metadata(&metadata).unwrap_or_else(|e| fail(e));
    let holder = keyring
        .select(&metadata, args.holder.as_deref())
        .unwrap_or_else(|e| fail(e));
    eprintln!(
        "this keyring is holder {} ({})",
        holder.coordinate(),
        holder.fingerprint()
    );
    println!(
        "{}",
        serde_json::json!({
            "form": bundle.form().to_string(),
            "threshold": metadata.threshold,
            "holders": metadata.holders.iter().map(|c| fingerprint_hex(&c.primary_key)).collect::<Vec<_>>(),
            "this_holder": holder.coordinate(),
            "bundle_hash": bundle.content_hash().ok().flatten(),
        })
    );
}

fn import(args: Args) {
    let [bundle_path] = args.positional.as_slice() else {
        usage()
    };
    let bundle = Bundle::from_json(&read(bundle_path)).unwrap_or_else(|e| fail(e));
    let keyring = load_keyring(&args);
    let password = password(&keyring, &args);
    let shardfile = bundle.shardfile().unwrap_or_else(|e| fail(e));
    let metadata = keyring
        .decrypt_metadata(&shardfile, &password)
        .unwrap_or_else(|e| fail(e));
    keyring
        .select(&metadata, args.holder.as_deref())
        .unwrap_or_else(|e| fail(e));
    let imported = bundle.import(&metadata).unwrap_or_else(|e| fail(e));
    let text = serde_json::to_string_pretty(&imported).expect("json");
    let hash = imported.content_hash().unwrap_or_else(|e| fail(e));
    match &args.out {
        Some(path) => {
            std::fs::write(path, format!("{text}\n"))
                .unwrap_or_else(|e| fail(format!("{}: {e}", path.display())));
            eprintln!("wrote {} (content hash {hash})", path.display());
        }
        None => println!("{text}"),
    }
}

fn send(args: Args) {
    let [target, hashes_path, bundle_path] = args.positional.as_slice() else {
        usage()
    };
    let pcrs = Pcrs::from_hashes_json(&read(hashes_path))
        .unwrap_or_else(|e| fail(format!("{hashes_path}: {e}")));
    if pcrs.is_debug() {
        if !args.allow_zero_pcrs {
            fail(format!("{hashes_path} has an all-zero PCR: a debug enclave, whose attestation proves nothing; refused unless --allow-zero-pcrs"));
        }
        eprintln!(
            "WARNING: all-zero PCRs: sending to a DEBUG enclave whose attestation proves nothing"
        );
    }
    let bundle = Bundle::from_json(&read(bundle_path)).unwrap_or_else(|e| fail(e));
    describe(&bundle);
    let keyring = load_keyring(&args);
    let password = password(&keyring, &args);
    // The share first, so no prompt holds a connection open.
    let release =
        prepare(&bundle, &keyring, args.holder.as_deref(), &password).unwrap_or_else(|e| fail(e));
    eprintln!(
        "metadata: threshold {} of {}; this keyring is holder {} ({})",
        release.metadata.threshold,
        release.metadata.holders.len(),
        release.holder.coordinate(),
        release.holder.fingerprint()
    );
    let bundle_hash = bundle.content_hash().unwrap_or_else(|e| fail(e));
    let addr = resolve(target);
    let mut options = SendOptions::new(pcrs);
    options.allow_zero_pcrs = args.allow_zero_pcrs;
    if let Some(secs) = args.timeout {
        options.timeout = Duration::from_secs(secs);
    }
    if let Some(root) = &args.trust_root {
        let der = std::fs::read(root).unwrap_or_else(|e| fail(format!("{}: {e}", root.display())));
        eprintln!("WARNING: --trust-root {}: the attestation is checked against this root, not AWS's; a rehearsal, never a release", root.display());
        options.verifier = rose_petal::nitro::Verifier::with_root(&der);
    }
    if let Some(secs) = args.verify_at {
        eprintln!("WARNING: --verify-at {secs}: the certificate chain is checked at that time, not now; a rehearsal, never a release");
        options.at = Some(rose_petal::nitro::At::Live(Duration::from_secs(secs)));
    }
    eprintln!("connecting to {addr}; PCRs from {hashes_path}");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    match runtime.block_on(send_shard(addr, &release, bundle_hash, &password, &options)) {
        Ok(Reply::Accepted { remaining }) => {
            println!("accepted: {remaining} share(s) remaining");
        }
        Ok(Reply::Rejected { reason }) => {
            println!("rejected: {reason}");
            std::process::exit(1);
        }
        Err(e) => fail(e),
    }
}

/// The crate's Locksmith stand-in, for a deployment's rehearsal of its holders' release: the
/// quorum's holders and threshold are read from the bundle's metadata with the keyring given,
/// the attestation is the synthetic test one (so the sender needs `--trust-root` on
/// `rose-petal/tests/fixtures/attestation/historical-test-root.der` and `--verify-at
/// 1766510000`), and the hashes file to send with is printed. The recovered secret is not
/// checked against the quorum certificate (that derivation is Keymaker's).
#[cfg(feature = "test-server")]
fn test_server(args: Args) {
    use rose_petal::test_server::{ServerOptions, TestServer, TEST_PCRS, TEST_TIME};
    let [bundle_path] = args.positional.as_slice() else {
        usage()
    };
    let bundle = Bundle::from_json(&read(bundle_path)).unwrap_or_else(|e| fail(e));
    let keyring = load_keyring(&args);
    let password = password(&keyring, &args);
    let shardfile = bundle.shardfile().unwrap_or_else(|e| fail(e));
    let metadata = keyring
        .decrypt_metadata(&shardfile, &password)
        .unwrap_or_else(|e| fail(e));
    bundle.check_metadata(&metadata).unwrap_or_else(|e| fail(e));
    let options = ServerOptions::for_bundle(&bundle, &metadata, None);
    let listen = args.listen.clone().unwrap_or_else(|| "127.0.0.1:0".into());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async move {
        let server = TestServer::start_on(&listen, options).await.unwrap_or_else(|e| fail(e));
        let hashes = serde_json::json!({
            "pcr0": hex::encode(TEST_PCRS[0]), "pcr1": hex::encode(TEST_PCRS[1]), "pcr2": hex::encode(TEST_PCRS[2]),
        });
        eprintln!("test server listening on {}; threshold {} of {}", server.addr, metadata.threshold, metadata.holders.len());
        eprintln!("send with: rose-petal send {} <hashes.json> {bundle_path} --keyring ... --trust-root <historical-test-root.der> --verify-at {}", server.addr, TEST_TIME.as_secs());
        eprintln!("where <hashes.json> is: {hashes}");
        println!("{}", serde_json::json!({"listening": server.addr.to_string(), "hashes": hashes, "verify_at": TEST_TIME.as_secs()}));
        match server.wait().await {
            Ok(_) => eprintln!("quorum complete: the shares recovered a secret"),
            Err(reason) => fail(reason),
        }
    });
}
