//! `zecd` - a Bitcoin-Core-style JSON-RPC server for shielded-first Zcash.

use clap::Parser;

use zecd::config::{AppConfig, Cli, Command, ConfigCommand};
use zecd::daemon;

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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // `rpcauth` is a pure credential generator - it needs no datadir, config file, or wallet,
    // so handle it before resolving config (which can refuse e.g. a placeholder mainnet setup).
    if let Some(Command::Rpcauth(args)) = &cli.command {
        return zecd::server::auth::run_rpcauth(args);
    }

    // `example-config` likewise: it emits a *starting* config, so it must work when there is no
    // config yet - resolving one first would reject the very situation the command exists for
    // (no `zecd.toml`, or one whose placeholders `resolve` refuses on mainnet).
    if let Some(Command::ExampleConfig(args)) = &cli.command {
        return zecd::example_config::run(args);
    }

    // `licenses` prints text embedded at compile time. Like the two above it needs no config,
    // datadir or wallet - and the container images are `FROM scratch`, so this is the only way
    // to read the notices from inside one.
    if let Some(Command::Licenses) = &cli.command {
        return zecd::licenses::run();
    }

    // The `config` subcommands report on the configuration - including one `resolve` rejects,
    // which is the case `check` exists for - so they must run *before* `resolve`, and without
    // tracing (their output is the command's product; log lines would interleave with it).
    match &cli.command {
        Some(Command::Config(ConfigCommand::Check(args))) => {
            return zecd::config_check::run(&cli, args)
        }
        Some(Command::Config(ConfigCommand::Show(args))) => {
            return zecd::config_show::run(&cli, args)
        }
        _ => {}
    }

    let config = AppConfig::resolve(&cli)?;
    daemon::init_tracing(&config.log);
    // Disable core dumps + ptrace before any seed is decrypted (best-effort; see hardening).
    zecd::hardening::harden_process();

    match &cli.command {
        Some(Command::Init(args)) => zecd::init::run(&config, args).await,
        Some(Command::ExportUfvk(args)) => zecd::init::export_ufvk(&config, args),
        Some(Command::ExportXpub(args)) => zecd::init::export_xpub(&config, args),
        // `derive-address` and `chain info` are the Zcash engine's (offline address derivation,
        // a lightwalletd/zebra probe). They stay in the subcommand list in every build - so
        // `zecd --help` names one surface - and refuse at runtime where the engine is absent,
        // the way `export-xpub` refuses a Zcash wallet.
        Some(Command::DeriveAddress(args)) => derive_address(&config, args),
        Some(Command::Rescan(args)) => zecd::init::rescan(&config, args).await,
        #[cfg(feature = "zcash")]
        Some(Command::ChainInfo(args)) => zecd::chain_probe::run(&config, args).await,
        #[cfg(not(feature = "zcash"))]
        Some(Command::ChainInfo(_)) => Err(unsupported_without_zcash("chain-info")),
        _ => {
            // SIGHUP re-resolves through exactly the path the daemon started with, so a reload
            // sees what a restart would - the same file, the same CLI overrides, the same
            // defaults.
            let cli_for_reload = cli.clone();
            daemon::run_with_reload(
                config,
                Some(Box::new(move || AppConfig::resolve(&cli_for_reload))),
            )
            .await
        }
    }
}

/// `derive-address` answers from the engine the wallet's coin names: BIP 84 for a Bitcoin
/// wallet (`btc::derive`), Unified/transparent addresses for a Zcash one.
fn derive_address(
    config: &zecd::config::AppConfig,
    args: &zecd::config::DeriveAddressArgs,
) -> anyhow::Result<()> {
    #[cfg(feature = "bitcoin")]
    if zecd::btc::derive::serves(config, args.wallet.as_deref()) {
        return zecd::btc::derive::run(config, args);
    }
    #[cfg(feature = "zcash")]
    {
        zecd::derive_address::run(config, args)
    }
    #[cfg(not(feature = "zcash"))]
    {
        let _ = (config, args);
        Err(unsupported_without_zcash("derive-address"))
    }
}

/// The refusal a Zcash-only subcommand gives in a build without that engine: the same shape as
/// the wrong-coin refusals in `init`, naming what this build does serve.
#[cfg(not(feature = "zcash"))]
fn unsupported_without_zcash(command: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "`zecd {command}` needs the Zcash engine, which this build does not carry (this build \
         supports: {})",
        zecd::coin::Coin::supported_names()
    )
}
