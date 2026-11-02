//! Black-box tests of the two binaries: the arguments, the exit codes, the outputs, and one
//! release end to end against the crate's test server.

use rose_petal::holder::Keyring;
use rose_petal::test_server::{
    make_fixture, metadata_of, ServerOptions, TestServer, TEST_PCRS, TEST_ROOT, TEST_TIME,
};
use std::path::{Path, PathBuf};
use std::process::Command;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn rose_petal() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rose-petal"))
}

fn attestation_check() -> Command {
    Command::new(env!("CARGO_BIN_EXE_attestation-check"))
}

fn fixture(rel: &str) -> PathBuf {
    Path::new(FIXTURES).join(rel)
}

fn run(cmd: &mut Command) -> (i32, String, String) {
    let out = cmd.output().expect("run");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn usage_version_and_inspect() {
    let (code, _, err) = run(&mut rose_petal());
    assert_eq!(code, 2);
    assert!(err.contains("usage:"));
    let (code, out, _) = run(rose_petal().arg("--version"));
    assert_eq!(code, 0);
    assert!(out.starts_with("rose-petal "));
    let (code, _, _) = run(rose_petal().args(["send", "only-one-positional"]));
    assert_eq!(code, 2);

    let (code, out, err) = run(rose_petal()
        .args(["inspect"])
        .arg(fixture("locksmith-v0/bundle.json")));
    assert_eq!(code, 0, "{err}");
    assert!(out.is_empty());
    assert!(err.contains("raw V0 form"));
    assert!(err.contains("no --keyring"));
    let (code, out, err) = run(rose_petal()
        .args(["inspect"])
        .arg(fixture("locksmith-v0/bundle.json"))
        .arg("--keyring")
        .arg(fixture("locksmith-v0/bob.private.asc")));
    assert_eq!(code, 0, "{err}");
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(json["threshold"], 2);
    assert_eq!(json["this_holder"], 2);
    assert_eq!(json["holders"].as_array().unwrap().len(), 2);
    assert!(json["bundle_hash"].is_null());
}

#[test]
fn import_then_inspect_the_artifact() {
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("imported.json");
    let (code, _, err) = run(rose_petal()
        .args(["import"])
        .arg(fixture("locksmith-v0/bundle.json"))
        .arg("--keyring")
        .arg(fixture("locksmith-v0/alice.private.asc"))
        .arg("--out")
        .arg(&out_path));
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("content hash"));
    let (code, out, err) = run(rose_petal()
        .args(["inspect"])
        .arg(&out_path)
        .arg("--keyring")
        .arg(fixture("locksmith-v0/bob.private.asc")));
    assert_eq!(code, 0, "{err}");
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(json["form"], "ImportedV0");
    assert_eq!(json["bundle_hash"].as_str().unwrap().len(), 64);
    // An outsider's keyring is refused.
    let outsider = dir.path().join("outsider.asc");
    std::fs::write(
        &outsider,
        rose_petal::test_keys::generate("outsider")
            .to_armored_string(Default::default())
            .unwrap(),
    )
    .unwrap();
    let (code, _, err) = run(rose_petal()
        .args(["inspect"])
        .arg(&out_path)
        .arg("--keyring")
        .arg(&outsider));
    assert_eq!(code, 1);
    assert!(err.contains("none of the keyring's keys decrypts"));
}

#[test]
fn attestation_check_verdicts() {
    let nonce = base64_of_hex("c502c976c57a5f749155bb84f5e32f0f3b16f01a");
    let doc = fixture("attestation/rose-deploy-2026-10-28.json");
    let pcrs = fixture("attestation/rose-deploy-2026-10-28.hashes.json");
    let (code, out, err) = run(attestation_check()
        .arg("--document")
        .arg(&doc)
        .arg("--pcrs")
        .arg(&pcrs)
        .args([
            "--nonce",
            &nonce,
            "--instance",
            "i-05c6aee5a0c1935a8",
            "--archived",
        ]));
    assert_eq!(code, 0, "{err}");
    let verdict: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(verdict["ok"], true);
    assert_eq!(verdict["verified_at"], "document_timestamp");
    assert_eq!(verdict["checks"].as_array().unwrap().len(), 7);
    // Live: the leaf expired long ago, so the chain fails and only it.
    let (code, out, _) = run(attestation_check()
        .arg("--document")
        .arg(&doc)
        .arg("--pcrs")
        .arg(&pcrs)
        .args(["--nonce", &nonce]));
    assert_eq!(code, 1);
    let verdict: serde_json::Value = serde_json::from_str(&out).unwrap();
    let failed: Vec<_> = verdict["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["ok"] == false)
        .map(|c| c["check"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(failed, ["aws_chain_and_signature", "full_verify"]);
    // The wrong instance and the wrong nonce are reported by name.
    let (code, out, _) = run(attestation_check()
        .arg("--document")
        .arg(&doc)
        .arg("--pcrs")
        .arg(&pcrs)
        .args([
            "--nonce",
            &base64_of_hex(&"00".repeat(20)),
            "--instance",
            "i-0other",
            "--archived",
        ]));
    assert_eq!(code, 1);
    let verdict: serde_json::Value = serde_json::from_str(&out).unwrap();
    let failed: Vec<_> = verdict["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["ok"] == false)
        .map(|c| c["check"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(failed, ["nonce", "instance", "full_verify"]);
    let (code, _, err) = run(attestation_check().args(["--document"]));
    assert_eq!(code, 2);
    assert!(err.contains("usage"));
}

fn base64_of_hex(hex: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(hex::decode(hex).unwrap())
}

#[tokio::test]
async fn send_end_to_end_through_the_binary() {
    let fixture = make_fixture(&["ann", "ben"], 2);
    let (bundle, metadata) = metadata_of(&fixture, 0);
    let dir = tempfile::tempdir().unwrap();
    let bundle_path = dir.path().join("bundle.json");
    std::fs::write(&bundle_path, &fixture.bundle_json).unwrap();
    let hashes_path = dir.path().join("hashes.json");
    std::fs::write(
        &hashes_path,
        format!(
            r#"{{"pcr0":"{}","pcr1":"{}","pcr2":"{}"}}"#,
            hex::encode(TEST_PCRS[0]),
            hex::encode(TEST_PCRS[1]),
            hex::encode(TEST_PCRS[2])
        ),
    )
    .unwrap();
    let root_path = dir.path().join("root.der");
    std::fs::write(&root_path, TEST_ROOT).unwrap();
    let keyrings: Vec<PathBuf> = fixture
        .holders
        .iter()
        .enumerate()
        .map(|(i, key)| {
            let path = dir.path().join(format!("holder{i}.asc"));
            std::fs::write(&path, key.to_armored_string(Default::default()).unwrap()).unwrap();
            path
        })
        .collect();
    let _ = Keyring::load(&keyrings[0]).unwrap();

    let server = TestServer::start(ServerOptions::for_bundle(
        &bundle,
        &metadata,
        Some(fixture.secret),
    ))
    .await;
    let addr = server.addr.to_string();
    let send = |keyring: &Path, extra: &[&str]| {
        let mut cmd = rose_petal();
        cmd.arg("send")
            .arg(&addr)
            .arg(&hashes_path)
            .arg(&bundle_path)
            .arg("--keyring")
            .arg(keyring)
            .arg("--trust-root")
            .arg(&root_path)
            .args([
                "--verify-at",
                &TEST_TIME.as_secs().to_string(),
                "--timeout",
                "10",
            ])
            .args(extra);
        cmd
    };
    // Without the rehearsal flags the binary trusts only AWS's root: refused before anything is sent.
    let (code, _, err) = tokio::task::spawn_blocking({
        let (addr, hashes_path, bundle_path, keyring) = (
            addr.clone(),
            hashes_path.clone(),
            bundle_path.clone(),
            keyrings[0].clone(),
        );
        move || {
            run(rose_petal()
                .arg("send")
                .arg(&addr)
                .arg(&hashes_path)
                .arg(&bundle_path)
                .arg("--keyring")
                .arg(&keyring)
                .args(["--timeout", "10"]))
        }
    })
    .await
    .unwrap();
    assert_eq!(code, 1);
    assert!(err.contains("certificate chain"), "{err}");
    assert!(server.shares().await.is_empty());

    let (code, out, err) = tokio::task::spawn_blocking({
        let mut cmd = send(&keyrings[0], &[]);
        move || run(&mut cmd)
    })
    .await
    .unwrap();
    assert_eq!(code, 0, "{err}");
    assert_eq!(out.trim(), "accepted: 1 share(s) remaining");
    assert!(err.contains("WARNING: --trust-root"));
    assert!(err.contains("this keyring is holder 1"));

    // The same holder again: rejected, exit 1, the reason on stdout.
    let (code, out, _) = tokio::task::spawn_blocking({
        let mut cmd = send(&keyrings[0], &[]);
        move || run(&mut cmd)
    })
    .await
    .unwrap();
    assert_eq!(code, 1);
    assert_eq!(out.trim(), "rejected: Holder already contributed a share");

    let (code, out, err) = tokio::task::spawn_blocking({
        let mut cmd = send(&keyrings[1], &[]);
        move || run(&mut cmd)
    })
    .await
    .unwrap();
    assert_eq!(code, 0, "{err}");
    assert_eq!(out.trim(), "accepted: 0 share(s) remaining");
    assert_eq!(server.finish().await, Some(Ok(fixture.secret)));
}

#[test]
fn debug_pcrs_are_refused_before_connecting() {
    let dir = tempfile::tempdir().unwrap();
    let hashes_path = dir.path().join("hashes.json");
    std::fs::write(
        &hashes_path,
        format!(
            r#"{{"pcr0":"{0}","pcr1":"{0}","pcr2":"{0}"}}"#,
            "00".repeat(48)
        ),
    )
    .unwrap();
    let (code, _, err) = run(rose_petal()
        .args(["send", "127.0.0.1:1"])
        .arg(&hashes_path)
        .arg(fixture("locksmith-v0/bundle.json"))
        .arg("--keyring")
        .arg(fixture("locksmith-v0/alice.private.asc")));
    assert_eq!(code, 1);
    assert!(err.contains("debug enclave"), "{err}");
    assert!(!err.contains("connecting"));
}
