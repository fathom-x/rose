// Check a Nitro attestation document against what this repository records: the AWS
// certificate chain and COSE signature (bootproof-sdk, the verifier Locksmith's client and
// steve-cli use), the nonce it echoes (the deployed commit, which binds the document to one
// deployment), PCR0-2 against a hashes file, and the module id against the recorded
// instance. Its own crate (../Cargo.toml: `cargo build --release --manifest-path
// contrib/holder-tools/attestation-check/Cargo.toml`), and also built as a bin of
// Locksmith's crate in its StageX image (../../build.sh) for the released binaries; a
// deployment's attestation.sh runs whichever is at hand.
//
//   attestation-check --document FILE --pcrs FILE --nonce BASE64 [--instance i-...]
//                     [--archived] [--allow-zero-pcrs]
//
// FILE is bootproofd's answer ({"document": base64, "manifest": ...}) or a bare base64
// document. --archived verifies the certificate chain at the document's own timestamp, for
// a document fetched earlier (the leaf certificate lives three hours, set by AWS): it then
// proves what was true when the document was issued, not that the enclave is up now.
// Prints a JSON verdict (one entry per check) on stdout, one line per check on stderr, and
// exits 0 only if every check passed. The manifest beside the document is bootproofd's own
// JSON, outside the signed payload, and is not read here.

use bootproof_sdk::VerifiableSignedAttestationFormat;
use bootproof_sdk::format::nitro::Nitro;
use serde_cbor::Value;
use std::collections::HashMap;
use std::time::Duration;

fn usage() -> ! {
    eprintln!(
        "usage: attestation-check --document FILE --pcrs FILE --nonce BASE64 [--instance ID] [--archived] [--allow-zero-pcrs]"
    );
    std::process::exit(2)
}

fn b64decode(s: &str) -> Result<Vec<u8>, String> {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let (mut out, mut buf, mut bits) = (Vec::new(), 0u32, 0u32);
    for c in s.bytes().filter(|c| !c.is_ascii_whitespace()) {
        if c == b'=' {
            break;
        }
        let v = T
            .iter()
            .position(|&t| t == c)
            .ok_or_else(|| format!("not base64: {:?}", c as char))? as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
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
            _ => usage(),
        }
    }
    let (Some(document), Some(pcrs_path), Some(nonce_b64)) = (document, pcrs_path, nonce_b64) else { usage() };

    // The document: bootproofd's JSON envelope, or a bare base64 string.
    let raw = std::fs::read_to_string(&document).unwrap_or_else(|e| fail(&format!("{document}: {e}")));
    let b64 = match serde_json::from_str::<serde_json::Value>(&raw) {
        Ok(v) => v["document"]
            .as_str()
            .unwrap_or_else(|| fail("the JSON has no \"document\" string"))
            .to_string(),
        Err(_) => raw.trim().to_string(),
    };
    let doc = b64decode(&b64).unwrap_or_else(|e| fail(&format!("document: {e}")));
    let expected_nonce = b64decode(&nonce_b64).unwrap_or_else(|e| fail(&format!("--nonce: {e}")));

    // The expected PCRs, as scripts/locksmith-send-shard.rs reads them.
    let hashes: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&pcrs_path).unwrap_or_else(|e| fail(&format!("{pcrs_path}: {e}"))),
    )
    .unwrap_or_else(|e| fail(&format!("{pcrs_path}: not JSON: {e}")));
    let mut expected: HashMap<u8, Vec<u8>> = HashMap::new();
    for n in 0u8..3 {
        let key = format!("pcr{n}");
        let hex = hashes[&key].as_str().unwrap_or_else(|| fail(&format!("{pcrs_path} has no {key}")));
        let bytes = smex::decode_to_vec(hex).unwrap_or_else(|e| fail(&format!("{key} is not hex: {e}")));
        if bytes.len() != 48 {
            fail(&format!("{key} is {} bytes, not 48", bytes.len()));
        }
        if bytes.iter().all(|b| *b == 0) && !allow_zero {
            fail(&format!("{key} is all zero: a debug enclave; refused unless --allow-zero-pcrs"));
        }
        expected.insert(n, bytes);
    }

    // The signed payload, read directly so that each comparison is reported on its own.
    let cose: Value = serde_cbor::from_slice(&doc).unwrap_or_else(|e| fail(&format!("document is not CBOR: {e}")));
    let cose = match cose {
        Value::Tag(_, inner) => *inner,
        v => v,
    };
    let payload_bytes = match &cose {
        Value::Array(items) if items.len() == 4 => match &items[2] {
            Value::Bytes(b) => b.clone(),
            _ => fail("COSE_Sign1 payload is not bytes"),
        },
        _ => fail("document is not a COSE_Sign1 array"),
    };
    let payload: Value =
        serde_cbor::from_slice(&payload_bytes).unwrap_or_else(|e| fail(&format!("payload is not CBOR: {e}")));
    let Value::Map(payload) = payload else { fail("payload is not a map") };
    let text = |k: &str| payload.get(&Value::Text(k.into()));
    let module_id = match text("module_id") {
        Some(Value::Text(s)) => s.clone(),
        _ => fail("payload has no module_id"),
    };
    let timestamp_ms = match text("timestamp") {
        Some(Value::Integer(i)) => *i as u64,
        _ => fail("payload has no timestamp"),
    };
    let signed_nonce = match text("nonce") {
        Some(Value::Bytes(b)) => b.clone(),
        _ => Vec::new(),
    };
    let user_data = match text("user_data") {
        Some(Value::Bytes(b)) => String::from_utf8(b.clone()).ok(),
        _ => None,
    };
    let mut signed_pcrs: HashMap<u8, Vec<u8>> = HashMap::new();
    if let Some(Value::Map(m)) = text("pcrs") {
        for n in 0u8..3 {
            if let Some(Value::Bytes(b)) = m.get(&Value::Integer(i128::from(n))) {
                signed_pcrs.insert(n, b.clone());
            }
        }
    }
    if signed_pcrs.len() != 3 {
        fail("payload has no PCR0-2");
    }

    let mut checks = Vec::new();

    // 1. The AWS chain and the COSE signature, over the document's own values, so that this
    //    check fails only for the chain, the signature or a malformed document.
    let at = if archived {
        Duration::from_millis(timestamp_ms) + Duration::from_secs(1)
    } else {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time is linear")
    };
    let when = if archived { "at the document's timestamp" } else { "now" };
    let chain = Nitro::new(doc.clone(), signed_pcrs.clone())
        .and_then(|n| n.verify(at, &signed_nonce));
    checks.push(Check {
        name: "aws_chain_and_signature",
        ok: chain.is_ok(),
        detail: match &chain {
            Ok(_) => format!("chain to the AWS Nitro root and COSE signature valid {when}"),
            Err(e) => format!("{e} ({when})"),
        },
    });

    // 2. The nonce: the document answers the request that carried this value.
    checks.push(Check {
        name: "nonce",
        ok: signed_nonce == expected_nonce,
        detail: if signed_nonce == expected_nonce {
            format!("signed nonce {} as expected", smex::encode_to_string(&signed_nonce))
        } else {
            format!(
                "signed nonce {} is not the expected {}",
                smex::encode_to_string(&signed_nonce),
                smex::encode_to_string(&expected_nonce)
            )
        },
    });

    // 3. PCR0-2 against the hashes file.
    for n in 0u8..3 {
        let (s, e) = (&signed_pcrs[&n], &expected[&n]);
        checks.push(Check {
            name: ["pcr0", "pcr1", "pcr2"][n as usize],
            ok: s == e,
            detail: if s == e {
                format!("{} as in {pcrs_path}", smex::encode_to_string(s))
            } else {
                format!("signed {} is not {} in {pcrs_path}", smex::encode_to_string(s), smex::encode_to_string(e))
            },
        });
    }

    // 4. The instance: an enclave's module id is <instance id>-enc<enclave id>.
    if let Some(inst) = &instance {
        let ok = module_id.starts_with(&format!("{inst}-enc"));
        checks.push(Check {
            name: "instance",
            ok,
            detail: if ok {
                format!("module {module_id} is on {inst}")
            } else {
                format!("module {module_id} is not on {inst}")
            },
        });
    }

    // 5. The verifier's own verdict with the expected values, as the shard sender would see it.
    let agree = Nitro::new(doc, expected).and_then(|n| n.verify(at, &expected_nonce));
    checks.push(Check {
        name: "bootproof_verify",
        ok: agree.is_ok(),
        detail: match &agree {
            Ok(_) => "bootproof verify passes with the expected PCRs and nonce".into(),
            Err(e) => format!("{e}"),
        },
    });

    let ok = checks.iter().all(|c| c.ok);
    for c in &checks {
        eprintln!("{} {}: {}", if c.ok { "ok  " } else { "FAIL" }, c.name, c.detail);
    }
    let ts_secs = timestamp_ms / 1000;
    let verdict = serde_json::json!({
        "ok": ok,
        "document": {
            "module_id": module_id,
            "timestamp_ms": timestamp_ms,
            "timestamp_unix": ts_secs,
            "nonce": smex::encode_to_string(&signed_nonce),
            "pcr0": smex::encode_to_string(&signed_pcrs[&0]),
            "pcr1": smex::encode_to_string(&signed_pcrs[&1]),
            "pcr2": smex::encode_to_string(&signed_pcrs[&2]),
            "user_data": user_data,
        },
        "verified_at": if archived { "document_timestamp" } else { "now" },
        "checks": checks.iter().map(|c| serde_json::json!({"check": c.name, "ok": c.ok, "detail": c.detail})).collect::<Vec<_>>(),
    });
    println!("{}", serde_json::to_string_pretty(&verdict).unwrap());
    std::process::exit(if ok { 0 } else { 1 });
}

fn fail(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(2)
}
