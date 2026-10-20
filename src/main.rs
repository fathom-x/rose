//! `rosed` - the rose daemon: a Bitcoin-Core-style JSON-RPC wallet server. Like `bitcoind` it
//! has no subcommands; everything an operator runs beside it (`init`, `config check`,
//! `derive-address`, `rpcauth`, the RPC client, ...) is the `rose` binary (rose-cli/).

use clap::Parser;

use rosed::config::{AppConfig, Cli, RunArgs};
use rosed::daemon;

// musl's default allocator contends under Orchard proving's multi-threaded allocation churn
// (~80x more futex syscalls than mimalloc) - costing ~10% per send on bare metal, several× in
// syscall-expensive sandboxes. Both musl release
// images build with `--features mimalloc-secure` to close that gap (the `mimalloc` feature, plus
// MI_SECURE heap hardening); native glibc builds leave it off (parity either way, so it would be
// pure dependency weight). The hardening is a compile-time flag of the mimalloc crate, so the
// global allocator declaration is identical for both `mimalloc` and `mimalloc-secure`.
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// The daemon's command line: the global flags every rose binary shares, plus the boot-time
/// options a shell-less deployment needs (`--restore-if-empty`).
#[derive(Debug, Clone, Parser)]
#[command(
    name = "rosed",
    version,
    about = "rosed - a Bitcoin-Core-style JSON-RPC wallet server"
)]
struct DaemonCli {
    #[command(flatten)]
    globals: Cli,
    #[command(flatten)]
    run: RunArgs,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let DaemonCli { globals: cli, run } = DaemonCli::parse();

    let config = AppConfig::resolve(&cli)?;
    daemon::init_tracing(&config.log);
    // Disable core dumps + ptrace before any seed is decrypted (best-effort; see hardening).
    rosed::hardening::harden_process();

    let restore = rosed::init::restore_if_empty_from_args(&config, &run)?;
    // SIGHUP re-resolves through exactly the path the daemon started with, so a reload sees
    // what a restart would - the same file, the same CLI overrides, the same defaults.
    let cli_for_reload = cli.clone();
    daemon::run_with_reload(
        config,
        restore,
        Some(Box::new(move || AppConfig::resolve(&cli_for_reload))),
    )
    .await
}
