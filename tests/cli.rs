//! Black-box acceptance tests for the `rosed` daemon binary: run it as a subprocess and
//! assert the refusals it must make before serving (a placeholder password, a malformed
//! rpcauth entry, an unknown config key, ...). Everything that takes a subcommand is `rose`'s
//! (rose-cli/tests/cli.rs), which also drives this binary for the restore-then-serve flows.
//!
//! Everything here is offline.

// The bin target declares `required-features = ["server", "cli"]`, so under a build without
// them `CARGO_BIN_EXE_rosed` is never set and this file must vanish rather than fail to expand
// that env var.
#![cfg(all(feature = "server", feature = "cli"))]

use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn rosed() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rosed"))
}

/// Run to completion, killing the child if it is still alive after `timeout` - a
/// startup-failure path that regresses into a running daemon should fail the test,
/// not hang CI.
///
/// Both pipes are drained by reader threads *while* the child runs, rather than collected
/// after it exits: a child writing more than the pipe buffer (~64 KiB) otherwise blocks in
/// `write` forever, and the deadline above turns that into "did not exit within 10s" - a
/// timeout that looks like a hung daemon but is really this harness holding the pipe shut.
/// `rose licenses` (rose-cli) emits ~290 KiB and hit exactly that.
fn run_with_timeout(mut cmd: Command, timeout: Duration) -> Output {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .spawn()
        .expect("spawning rosed");
    let mut out_pipe = child.stdout.take().expect("piped stdout");
    let mut err_pipe = child.stderr.take().expect("piped stderr");
    let readers = (
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            std::io::Read::read_to_end(&mut out_pipe, &mut buf).expect("reading stdout");
            buf
        }),
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            std::io::Read::read_to_end(&mut err_pipe, &mut buf).expect("reading stderr");
            buf
        }),
    );
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait().expect("polling rose") {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                // Killing the child closes its ends of both pipes, so the readers see EOF and
                // the joins below cannot hang.
                child.kill().ok();
                child.wait().ok();
                readers.0.join().ok();
                readers.1.join().ok();
                panic!("rose did not exit within {timeout:?}; expected a fast failure");
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    };
    Output {
        status,
        stdout: readers.0.join().expect("stdout reader"),
        stderr: readers.1.join().expect("stderr reader"),
    }
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn version_prints_name_and_semver() {
    let out = run_with_timeout(
        {
            let mut c = rosed();
            c.arg("--version");
            c
        },
        Duration::from_secs(10),
    );
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut words = stdout.split_whitespace();
    assert_eq!(words.next(), Some("rosed"));
    let version = words.next().expect("version after name");
    assert!(
        version.split('.').count() >= 3
            && version.chars().next().is_some_and(|c| c.is_ascii_digit()),
        "expected semver, got {version:?}"
    );
}

#[test]
fn unknown_flag_is_a_usage_error() {
    let out = run_with_timeout(
        {
            let mut c = rosed();
            c.arg("--definitely-not-a-flag");
            c
        },
        Duration::from_secs(10),
    );
    // clap's conventional usage-error exit code, same as bitcoind's arg parsing.
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr_of(&out));
}

#[test]
fn invalid_network_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let out = run_with_timeout(
        {
            let mut c = rosed();
            c.args([
                "--datadir",
                dir.path().to_str().unwrap(),
                "--network",
                "bogus",
            ]);
            c
        },
        Duration::from_secs(10),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr_of(&out).contains("unsupported network"),
        "stderr: {}",
        stderr_of(&out)
    );
}

#[test]
fn unknown_config_field_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("rose.toml"), "[rpc]\nbogus_field = 1\n").unwrap();
    let out = run_with_timeout(
        {
            let mut c = rosed();
            c.args(["--datadir", dir.path().to_str().unwrap()]);
            c
        },
        Duration::from_secs(10),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr_of(&out).contains("parsing config"),
        "stderr: {}",
        stderr_of(&out)
    );
}

/// The RPC password is spend authority, so the daemon must refuse to start while it is still the
/// shipped placeholder - in any case, since the deploy templates use `CHANGE-ME` and the example
/// config uses lowercase `change-me` - and on every network: a testnet stack that comes up on the
/// committed value is one nobody is prompted to change.
#[test]
fn placeholder_password_refuses_to_start_on_every_network() {
    for network in ["main", "test", "regtest"] {
        for placeholder in ["CHANGE-ME", "change-me", " Change-Me "] {
            let dir = tempfile::tempdir().unwrap();
            let out = run_with_timeout(
                {
                    let mut c = rosed();
                    c.args([
                        "--datadir",
                        dir.path().to_str().unwrap(),
                        "--network",
                        network,
                        "--rpcuser",
                        "u",
                        "--rpcpassword",
                        placeholder,
                    ]);
                    c
                },
                Duration::from_secs(10),
            );
            assert_eq!(
                out.status.code(),
                Some(1),
                "{network}: placeholder {placeholder:?} should refuse to start; stderr: {}",
                stderr_of(&out)
            );
            assert!(
                stderr_of(&out).contains("CHANGE-ME"),
                "{network}: placeholder {placeholder:?} stderr: {}",
                stderr_of(&out)
            );
        }
    }
}

#[test]
fn malformed_rpcauth_fails_startup() {
    let dir = tempfile::tempdir().unwrap();
    let out = run_with_timeout(
        {
            let mut c = rosed();
            c.args([
                "--datadir",
                dir.path().to_str().unwrap(),
                "--network",
                "test",
                "--rpcauth",
                "no-colon-or-dollar",
            ]);
            c
        },
        Duration::from_secs(10),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr_of(&out).contains("invalid rpcauth entry"),
        "stderr: {}",
        stderr_of(&out)
    );
}

/// A typo'd method in the `[rpc] allowed_methods` safelist must fail at startup, not silently
/// disable a method the operator believed they had enabled.
#[test]
fn unknown_allowed_method_fails_startup() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("rose.toml"),
        "[rpc]\nallowed_methods = [\"getbalance\", \"not_a_real_method\"]\n",
    )
    .unwrap();
    let out = run_with_timeout(
        {
            let mut c = rosed();
            c.args([
                "--datadir",
                dir.path().to_str().unwrap(),
                "--network",
                "test",
            ]);
            c
        },
        Duration::from_secs(10),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr_of(&out).contains("not_a_real_method"),
        "stderr: {}",
        stderr_of(&out)
    );
}

/// A default receiver that names a pool the wallet doesn't enable is a startup error, caught at
/// config parse before any network/wallet I/O.
#[cfg(feature = "zcash")]
#[test]
fn default_receivers_not_subset_of_pools_fails_startup() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("rose.toml"),
        "[pools]\nenabled = [\"orchard\"]\ndefault_receivers = [\"sapling\"]\n",
    )
    .unwrap();
    let out = run_with_timeout(
        {
            let mut c = rosed();
            c.args([
                "--datadir",
                dir.path().to_str().unwrap(),
                "--network",
                "test",
            ]);
            c
        },
        Duration::from_secs(10),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr_of(&out).contains("subset") && stderr_of(&out).contains("sapling"),
        "stderr: {}",
        stderr_of(&out)
    );
}

/// An unknown pool name in `[pools]` is rejected at startup.
#[cfg(feature = "zcash")]
#[test]
fn unknown_pool_name_fails_startup() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("rose.toml"),
        "[pools]\nenabled = [\"ironwood\"]\n",
    )
    .unwrap();
    let out = run_with_timeout(
        {
            let mut c = rosed();
            c.args([
                "--datadir",
                dir.path().to_str().unwrap(),
                "--network",
                "test",
            ]);
            c
        },
        Duration::from_secs(10),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr_of(&out).contains("ironwood"),
        "stderr: {}",
        stderr_of(&out)
    );
}
