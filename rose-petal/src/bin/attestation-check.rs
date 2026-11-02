//! Check a saved Nitro attestation document against what a deployment records: the AWS chain
//! and COSE signature, the nonce it echoes (a deployment fetches with its deployed commit as
//! the nonce, which binds the document to one deployment), PCR0-2 against a hashes file, and
//! the module id against the recorded instance.
//!
//!   attestation-check --document FILE --pcrs FILE --nonce BASE64 [--instance i-...]
//!                     [--archived] [--allow-zero-pcrs]
//!
//! FILE is bootproofd's answer (`{"document": base64, "manifest": ...}`) or a bare base64
//! document. `--archived` verifies the chain at the document's own timestamp, for a document
//! fetched earlier (the leaf certificate lives three hours): it then proves what was true when
//! the document was issued, not that the enclave is up now. Prints a JSON verdict (one entry
//! per check) on stdout, one line per check on stderr, and exits 0 only if every check passed.
//! The manifest beside the document is bootproofd's own JSON outside the signed payload and
//! is not read.

use base64::Engine;
use rose_petal::nitro::{At, Attestation, Expected, Pcrs, Verifier};

fn usage() -> ! {
    eprintln!("usage: attestation-check --document FILE --pcrs FILE --nonce BASE64 [--instance ID] [--archived] [--allow-zero-pcrs]");
    std::process::exit(2)
}

fn fail(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(2)
}

struct Check {
    name: &'static str,
    ok: bool,
    detail: String,
}

fn main() {
    let mut document = None;
    let mut pcrs_path = None;
    let mut nonce_b64 = None;
    let mut instance: Option<String> = None;
    let mut archived = false;
    let mut allow_zero = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--document" => document = args.next(),
            "--pcrs" => pcrs_path = args.next(),
            "--nonce" => nonce_b64 = args.next(),
            "--instance" => instance = args.next(),
            "--archived" => archived = true,
            "--allow-zero-pcrs" => allow_zero = true,
            "--version" | "-V" => {
                println!("attestation-check {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            _ => usage(),
        }
    }
    let (Some(document), Some(pcrs_path), Some(nonce_b64)) = (document, pcrs_path, nonce_b64)
    else {
        usage()
    };

    let raw =
        std::fs::read_to_string(&document).unwrap_or_else(|e| fail(&format!("{document}: {e}")));
    let b64 = match serde_json::from_str::<serde_json::Value>(&raw) {
        Ok(v) => v["document"]
            .as_str()
            .unwrap_or_else(|| fail("the JSON has no \"document\" string"))
            .to_string(),
        Err(_) => raw.trim().to_string(),
    };
    let decode = |s: &str| base64::engine::general_purpose::STANDARD.decode(s.trim());
    let bytes = decode(&b64).unwrap_or_else(|e| fail(&format!("document: not base64: {e}")));
    let expected_nonce =
        decode(&nonce_b64).unwrap_or_else(|e| fail(&format!("--nonce: not base64: {e}")));

    let hashes =
        std::fs::read_to_string(&pcrs_path).unwrap_or_else(|e| fail(&format!("{pcrs_path}: {e}")));
    let expected =
        Pcrs::from_hashes_json(&hashes).unwrap_or_else(|e| fail(&format!("{pcrs_path}: {e}")));
    if expected.is_debug() && !allow_zero {
        fail("the hashes file has an all-zero PCR: a debug enclave; refused unless --allow-zero-pcrs");
    }

    let attestation =
        Attestation::parse(&bytes).unwrap_or_else(|e| fail(&format!("document: {e}")));
    let at = if archived {
        At::DocumentTimestamp
    } else {
        At::now()
    };
    let when = if archived {
        "at the document's timestamp"
    } else {
        "now"
    };
    let verifier = Verifier::aws();
    let mut checks = Vec::new();

    // 1. The AWS chain and the COSE signature, so that this check fails only for the chain,
    //    the signature or a malformed document.
    let signed = verifier.verify_signed(&attestation, at);
    checks.push(Check {
        name: "aws_chain_and_signature",
        ok: signed.is_ok(),
        detail: match &signed {
            Ok(()) => format!("chain to the AWS Nitro root and COSE signature valid {when}"),
            Err(e) => format!("{e} ({when})"),
        },
    });

    // 2. The nonce: the document answers the request that carried this value.
    let signed_nonce = attestation.nonce.clone().unwrap_or_default();
    checks.push(Check {
        name: "nonce",
        ok: signed_nonce == expected_nonce,
        detail: if signed_nonce == expected_nonce {
            format!("signed nonce {} as expected", hex::encode(&signed_nonce))
        } else {
            format!(
                "signed nonce {} is not the expected {}",
                hex::encode(&signed_nonce),
                hex::encode(&expected_nonce)
            )
        },
    });

    // 3. PCR0-2 (and any further index in the hashes file) against the file.
    for (index, value) in expected.iter() {
        let name: &'static str = match index {
            0 => "pcr0",
            1 => "pcr1",
            2 => "pcr2",
            _ => Box::leak(format!("pcr{index}").into_boxed_str()),
        };
        let signed = attestation.pcrs.get(&index);
        let ok = signed.is_some_and(|s| s.as_slice() == value);
        checks.push(Check {
            name,
            ok,
            detail: match signed {
                Some(s) if ok => format!("{} as in {pcrs_path}", hex::encode(s)),
                Some(s) => format!(
                    "signed {} is not {} in {pcrs_path}",
                    hex::encode(s),
                    hex::encode(value)
                ),
                None => format!("the document carries no pcr{index}"),
            },
        });
    }

    // 4. The instance: an enclave's module id is <instance id>-enc<enclave id>.
    if let Some(inst) = &instance {
        let ok = attestation.instance_id() == Some(inst.as_str());
        checks.push(Check {
            name: "instance",
            ok,
            detail: if ok {
                format!("module {} is on {inst}", attestation.module_id)
            } else {
                format!("module {} is not on {inst}", attestation.module_id)
            },
        });
    }

    // 5. The verifier's own verdict with the expected values, as the shard sender would see it.
    let full = verifier.verify(
        &attestation,
        at,
        Expected {
            pcrs: &expected,
            nonce: Some(&expected_nonce),
        },
    );
    checks.push(Check {
        name: "full_verify",
        ok: full.is_ok(),
        detail: match &full {
            Ok(()) => "the verifier passes with the expected PCRs and nonce".into(),
            Err(e) => e.to_string(),
        },
    });

    let ok = checks.iter().all(|c| c.ok);
    for c in &checks {
        eprintln!(
            "{} {}: {}",
            if c.ok { "ok  " } else { "FAIL" },
            c.name,
            c.detail
        );
    }
    let verdict = serde_json::json!({
        "ok": ok,
        "document": {
            "module_id": attestation.module_id,
            "timestamp_ms": attestation.timestamp_ms,
            "timestamp_unix": attestation.timestamp_ms / 1000,
            "nonce": hex::encode(&signed_nonce),
            "pcr0": attestation.pcrs.get(&0).map(hex::encode),
            "pcr1": attestation.pcrs.get(&1).map(hex::encode),
            "pcr2": attestation.pcrs.get(&2).map(hex::encode),
            "user_data": attestation.user_data.as_deref().map(|u| String::from_utf8(u.to_vec()).unwrap_or_else(|_| hex::encode(u))),
        },
        "verified_at": if archived { "document_timestamp" } else { "now" },
        "checks": checks.iter().map(|c| serde_json::json!({"check": c.name, "ok": c.ok, "detail": c.detail})).collect::<Vec<_>>(),
    });
    println!("{}", serde_json::to_string_pretty(&verdict).expect("json"));
    std::process::exit(if ok { 0 } else { 1 });
}
