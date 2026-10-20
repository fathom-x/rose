//! `rose` - the operator's command line for the `rosed` wallet daemon.
//!
//! Two halves, one binary, modeled on `bitcoin-cli` plus Bitcoin Core's wallet tooling: the
//! subcommands ([`Command`]) set a wallet or a deployment up and inspect it - `init`,
//! `rescan`, `config check`, `derive-address`, `rpcauth`, ... - and any other first word is an
//! RPC method name sent to a running daemon (`rose getbalance`, `rose -rpcwallet=btc
//! listunspent 1`). Both halves resolve configuration the way the daemon does, from the same
//! flags, so `--conf` and `--datadir` mean one thing across `rosed` and `rose`.

use std::ffi::OsString;

use clap::Parser;

use rosed::config::{AppConfig, Cli, Command, ConfigCommand};
use rosed::daemon;

mod rpc;

/// The command line: the global flags every rose binary shares, the client's own connection
/// flags, and either a subcommand or an RPC method.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "rose",
    version,
    about = "rose - the rosed wallet daemon's command line: wallet setup, configuration, and a \
             JSON-RPC client",
    after_help = "Any other first word is a JSON-RPC method sent to the running daemon, with the \
                  remaining words as its parameters (each parsed as JSON, else taken as a \
                  string): `rose getblockcount`, `rose --rpcwallet btc getbalance`, `rose \
                  sendtoaddress <address> 0.001`. The daemon is found through the same \
                  configuration rosed reads (`--conf`, `--datadir`, `[rpc]`), its cookie file \
                  or `--rpcuser`/`--rpcpassword`."
)]
struct RoseCli {
    #[command(flatten)]
    globals: Cli,

    #[command(flatten)]
    client: rpc::ClientArgs,

    #[command(subcommand)]
    command: Option<CliCommand>,
}

#[derive(Debug, Clone, clap::Subcommand)]
enum CliCommand {
    #[command(flatten)]
    Admin(Command),
    /// An RPC method and its parameters.
    #[command(external_subcommand)]
    Rpc(Vec<OsString>),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let RoseCli {
        globals: cli,
        client,
        command,
    } = RoseCli::parse();

    let command = match command {
        Some(CliCommand::Admin(command)) => command,
        Some(CliCommand::Rpc(words)) => {
            // The client needs the daemon's port and credentials, which the configuration
            // resolves exactly as the daemon did; no tracing, no hardening - its output is
            // the method's result and it holds no secret of its own.
            let config = AppConfig::resolve(&cli)?;
            return rpc::run(&config, &client, &words).await;
        }
        None => {
            // Like `bitcoin-cli` with no method: usage, exit 1.
            use clap::CommandFactory;
            RoseCli::command().print_help()?;
            std::process::exit(1);
        }
    };

    // `rpcauth` is a pure credential generator - it needs no datadir, config file, or wallet,
    // so handle it before resolving config (which can refuse e.g. a placeholder mainnet setup).
    if let Command::Rpcauth(args) = &command {
        return rosed::server::auth::run_rpcauth(args);
    }

    // `example-config` likewise: it emits a *starting* config, so it must work when there is no
    // config yet - resolving one first would reject the very situation the command exists for
    // (no `rose.toml`, or one whose placeholders `resolve` refuses on mainnet).
    if let Command::ExampleConfig(args) = &command {
        return rosed::example_config::run(args);
    }

    // `licenses` prints text embedded at compile time. Like the two above it needs no config,
    // datadir or wallet - and the container images are `FROM scratch`, so this is the only way
    // to read the notices from inside one.
    if let Command::Licenses = &command {
        return rosed::licenses::run();
    }

    // The `config` subcommands report on the configuration - including one `resolve` rejects,
    // which is the case `check` exists for - so they must run *before* `resolve`, and without
    // tracing (their output is the command's product; log lines would interleave with it).
    match &command {
        Command::Config(ConfigCommand::Check(args)) => {
            return rosed::config_check::run(&cli, args);
        }
        Command::Config(ConfigCommand::Show(args)) => {
            return rosed::config_show::run(&cli, args);
        }
        _ => {}
    }

    let config = AppConfig::resolve(&cli)?;
    daemon::init_tracing(&config.log);
    // Disable core dumps + ptrace before any seed is decrypted (best-effort; see hardening).
    rosed::hardening::harden_process();

    match &command {
        Command::Init(args) => rosed::init::run(&config, args).await,
        Command::ExportUfvk(args) => rosed::init::export_ufvk(&config, args),
        Command::ExportXpub(args) => rosed::init::export_xpub(&config, args),
        // `derive-address` and `chain info` are the Zcash engine's (offline address derivation,
        // a lightwalletd/zebra probe). They stay in the subcommand list in every build - so
        // `rose --help` names one surface - and refuse at runtime where the engine is absent,
        // the way `export-xpub` refuses a Zcash wallet.
        Command::DeriveAddress(args) => derive_address(&config, args),
        Command::Rescan(args) => rosed::init::rescan(&config, args).await,
        #[cfg(feature = "zcash")]
        Command::ChainInfo(args) => rosed::chain_probe::run(&config, args).await,
        #[cfg(not(feature = "zcash"))]
        Command::ChainInfo(_) => Err(unsupported_without_zcash("chain-info")),
        // Dispatched above, before `resolve`; spelled out so a new subcommand is a compile
        // error here rather than a silent fall-through.
        Command::Rpcauth(_)
        | Command::ExampleConfig(_)
        | Command::Licenses
        | Command::Config(_) => {
            unreachable!("handled before configuration resolution")
        }
    }
}

/// `derive-address` answers from the engine the wallet's coin names: BIP 84 for a Bitcoin
/// wallet (`btc::derive`), Unified/transparent addresses for a Zcash one.
fn derive_address(
    config: &rosed::config::AppConfig,
    args: &rosed::config::DeriveAddressArgs,
) -> anyhow::Result<()> {
    #[cfg(feature = "bitcoin")]
    if rosed::btc::derive::serves(config, args.wallet.as_deref()) {
        return rosed::btc::derive::run(config, args);
    }
    #[cfg(feature = "zcash")]
    {
        rosed::derive_address::run(config, args)
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
        "`rose {command}` needs the Zcash engine, which this build does not carry (this build \
         supports: {})",
        rosed::coin::Coin::supported_names()
    )
}
