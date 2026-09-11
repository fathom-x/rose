//! `zecd config show` - print the effective configuration in the config file's own syntax.
//!
//! `sshd -T` to `config check`'s `sshd -t`. A zecd config file is only half the configuration:
//! every key it leaves unset takes this build's default, and those move between versions. This
//! renders what the binary actually resolved - file, CLI overrides, environment and defaults all
//! collapsed - as TOML, so it can be diffed across two binaries, captured before an upgrade, or
//! read to answer "what is this daemon actually doing" without cross-referencing the docs.
//!
//! TOML rather than a prose summary for two reasons. It names **real config keys**, so a line
//! that surprises you is a line you can go and change (a hand-formatted summary invents labels
//! that map to nothing). And it re-parses: [`tests::render_is_idempotent_through_a_resolve`]
//! feeds the output back through `AppConfig::resolve` and requires the second render to be
//! identical, which pins every emitted key as one this build's parser accepts - `deny_unknown_fields`
//! turns any drift between the renderer and the schema into a failing test rather than output
//! that looks authoritative and isn't.
//!
//! **Secrets are redacted, so this is an inspection view rather than a drop-in config file.**
//! The RPC password, the `rpcauth` credential hashes and the `[zebra]` credentials are emitted
//! as commented-out lines naming the key but not the value. Commented rather than
//! `password = "<redacted>"` deliberately: a redacted placeholder that *parses* would silently
//! become a real (wrong) credential if the file were ever deployed, whereas an absent password
//! falls back to cookie auth, which fails loudly and safely. The cost is that a config carrying
//! secrets does not round-trip byte-for-byte - which is the honest outcome, since the daemon's
//! behaviour genuinely depends on values that must not be printed.

#[cfg(feature = "cli")]
use std::io::Write;
use std::path::Path;

use crate::config::AppConfig;
#[cfg(feature = "cli")]
use crate::config::{Cli, ConfigShowArgs};

/// Preamble on the rendered config, explaining what the reader is looking at. Deliberately free
/// of the version and the source path - those are provenance, and they go to stderr like
/// `config check`'s header, so that two versions' stdout differ only where the configuration
/// differs.
const HEADER: &str = "\
# The EFFECTIVE zecd configuration: the config file, CLI flags and environment resolved
# together, with every unset key filled in by this build's default. Diff two zecd versions'
# output to see which defaults moved.
#
# Secrets (the RPC password, rpcauth hashes, [zebra] credentials) are shown as commented-out
# key names, never values - so this is an inspection view, not a drop-in config file.
";

/// Render `config` as TOML.
pub fn render(config: &AppConfig) -> String {
    let mut s = String::from(HEADER);

    // Top-level scalars first: in TOML every key after a `[table]` header belongs to that table.
    s.push('\n');
    kv(&mut s, "network", str_val(config.network.name()));
    // `btc_testnet` renders only where `resolve` accepts it - a testnet daemon, in a build
    // carrying the bitcoin engine - since emitting it anywhere else would produce a config
    // `config check` rejects, which the idempotence contract forbids. There it renders
    // unconditionally (default included): which public Bitcoin testnet the daemon's Bitcoin
    // wallets ride is exactly the kind of default a cross-version diff should surface.
    #[cfg(feature = "bitcoin")]
    if matches!(config.network, crate::network::ZNetwork::Test) {
        kv(&mut s, "btc_testnet", str_val(config.btc_testnet.name()));
    }
    kv(&mut s, "datadir", path_val(&config.datadir));
    kv(&mut s, "default_wallet", str_val(&config.default_wallet));

    table(&mut s, "backend");
    let b = &config.backend;
    // The token is what the operator writes; what it resolves to (host, port, protocol, and for
    // lightwalletd the TLS decision) is the thing they actually want to confirm, and it is not
    // itself a config key - so it rides as a comment, derived from the value beside it.
    match crate::backend::resolve_configured(config) {
        Ok(server) => kv_note(&mut s, "server", str_val(&b.server), &server.describe()),
        Err(e) => kv_note(
            &mut s,
            "server",
            str_val(&b.server),
            &format!("UNRESOLVED: {e}"),
        ),
    }
    // Rendered only when set, like tls_ca_file: an absent proxy has no key to write back.
    // `SocksProxy`'s Display is the canonical token, so this re-parses to the same value -
    // which `render_is_idempotent_through_a_resolve` depends on.
    if let Some(proxy) = &b.proxy {
        kv(&mut s, "proxy", str_val(&proxy.to_string()));
    }
    kv(&mut s, "connect_timeout_secs", b.connect_timeout_secs);
    kv(&mut s, "reconnect_base_secs", b.reconnect_base_secs);
    kv(&mut s, "reconnect_max_secs", b.reconnect_max_secs);
    kv(&mut s, "rfc1918_is_local", b.rfc1918_is_local);
    kv(&mut s, "allow_remote_cleartext", b.allow_remote_cleartext);
    kv(
        &mut s,
        "tls",
        str_val(match b.tls {
            None => "auto",
            Some(true) => "yes",
            Some(false) => "no",
        }),
    );
    kv(
        &mut s,
        "tls_roots",
        str_val(match b.tls_roots {
            crate::backend::TlsRoots::Native => "native",
            crate::backend::TlsRoots::Webpki => "webpki",
        }),
    );
    kv(
        &mut s,
        "tls_insecure_skip_verify",
        b.tls_insecure_skip_verify,
    );
    if let Some(ca) = &b.tls_ca_file {
        kv(&mut s, "tls_ca_file", path_val(ca));
    }
    if !b.tls_pins.is_empty() {
        let pins: Vec<String> = b.tls_pins.iter().map(|p| p.to_string()).collect();
        kv(&mut s, "tls_pinned_sha256", list_val(&pins));
    }
    kv(
        &mut s,
        "assume_transparent_in_compact_blocks",
        b.assume_transparent_in_compact_blocks,
    );

    table(&mut s, "zebra");
    if let Some(cookie) = &config.zebra.rpc_cookie {
        kv(&mut s, "rpc_cookie", path_val(cookie));
    }
    redacted_pair(
        &mut s,
        &["rpc_user", "rpc_password"],
        config.zebra.rpc_user.is_some() || config.zebra.rpc_password.is_some(),
    );

    // `[bitcoind]` mirrors `[backend]` + `[zebra]` for bitcoin wallets: the global default
    // upstream (rendered like `[backend] server` - always, with the resolved endpoint as a
    // note) plus credentials, secrets redacted the same way. The section exists only in a
    // build carrying the BDK engine, which is also the only build whose parser accepts it -
    // the idempotence contract holds per build.
    #[cfg(feature = "bitcoin")]
    {
        table(&mut s, "bitcoind");
        let btc_network =
            crate::coin::BitcoinNetwork::from_environment(config.network, config.btc_testnet);
        let token = config.bitcoind.server.as_deref().unwrap_or("bitcoind");
        match crate::btc::chain::describe_token(token, btc_network) {
            Ok(described) => kv_note(&mut s, "server", str_val(token), &described),
            Err(e) => kv_note(
                &mut s,
                "server",
                str_val(token),
                &format!("UNRESOLVED: {e}"),
            ),
        }
        if let Some(cookie) = &config.bitcoind.rpc_cookie {
            kv(&mut s, "rpc_cookie", path_val(cookie));
        }
        redacted_pair(
            &mut s,
            &["rpc_user", "rpc_password"],
            config.bitcoind.rpc_user.is_some() || config.bitcoind.rpc_password.is_some(),
        );

        // `[fees]` - the kyoto backend's fee-oracle chain. `sources` renders always (the
        // effective order is the thing an operator wants to read back); each URL renders only
        // when overridden, since "unset" means the built-in per-network endpoint, which is not
        // one value this key could carry. Each tier's *resolved* endpoint rides as a note, so
        // a tier that is inert on this network - Blockstream runs no testnet4 Esplora - says
        // so here rather than only in `config check`.
        table(&mut s, "fees");
        let sources: Vec<String> = config
            .fees
            .sources
            .iter()
            .map(|source| source.as_str().to_string())
            .collect();
        kv(&mut s, "sources", list_val(&sources));
        for (key, source, configured) in [
            (
                "mempool_space_url",
                crate::config::FeeSource::MempoolSpace,
                config.fees.mempool_space_url.as_deref(),
            ),
            (
                "esplora_url",
                crate::config::FeeSource::Esplora,
                config.fees.esplora_url.as_deref(),
            ),
        ] {
            if !config.fees.sources.contains(&source) {
                continue;
            }
            match (
                configured,
                crate::btc::fees::endpoint_for(&config.fees, source, btc_network),
            ) {
                (Some(url), _) => kv_note(&mut s, key, str_val(url), "overrides the built-in"),
                // Unset: there is no value this key could carry (the built-in endpoint is
                // per-network, not a config value), so the resolved URL rides as a comment -
                // which is also how a tier that is inert on this network says so.
                (None, Some(built_in)) => {
                    s.push_str(&format!("# {key} unset - using {built_in}\n"))
                }
                (None, None) => s.push_str(&format!(
                    "# {key} unset and no built-in endpoint for this network - the {} \
                     source is skipped\n",
                    source.as_str()
                )),
            }
        }

        // `[mempool]` - the kyoto backend's opt-in 0-conf feed, rendered on the `[fees]`
        // pattern: `sources` always (an empty list is the effective "off" and says so), the
        // URL as the real key only when overridden, else the resolved endpoint as a note.
        table(&mut s, "mempool");
        let sources: Vec<String> = config
            .mempool
            .sources
            .iter()
            .map(|source| source.as_str().to_string())
            .collect();
        kv(&mut s, "sources", list_val(&sources));
        if config
            .mempool
            .sources
            .contains(&crate::config::MempoolSource::P2p)
        {
            match config.mempool.p2p_peer {
                Some(peer) => kv_note(
                    &mut s,
                    "p2p_peer",
                    str_val(&peer.to_string()),
                    "overrides each wallet's kyoto:// peer",
                ),
                // Per wallet, not one value: each kyoto wallet peers with its own trusted
                // node, so there is nothing this key could carry.
                None => s.push_str(
                    "# p2p_peer unset - each kyoto wallet peers with its own kyoto://<ip>:<port> \
                     node (a DNS-seeded wallet runs no p2p feed)\n",
                ),
            }
            kv(&mut s, "p2p_snapshot", config.mempool.p2p_snapshot);
            kv(
                &mut s,
                "p2p_snapshot_interval_secs",
                config.mempool.p2p_snapshot_interval_secs,
            );
        }
        if config
            .mempool
            .sources
            .contains(&crate::config::MempoolSource::MempoolSpace)
        {
            match (
                config.mempool.mempool_space_url.as_deref(),
                crate::btc::mempool_feed::endpoint_for(&config.mempool, btc_network),
            ) {
                (Some(url), _) => kv_note(
                    &mut s,
                    "mempool_space_url",
                    str_val(url),
                    "overrides the built-in",
                ),
                (None, Some(built_in)) => {
                    s.push_str(&format!("# mempool_space_url unset - using {built_in}\n"))
                }
                (None, None) => s.push_str(
                    "# mempool_space_url unset and no built-in endpoint for this network - \
                     the feed does not start\n",
                ),
            }
        }
    }

    table(&mut s, "rpc");
    kv(&mut s, "bind", str_val(&config.rpc.bind.to_string()));
    kv(&mut s, "port", config.rpc.port);
    redacted_pair(
        &mut s,
        &["user", "password"],
        config.rpc.user.is_some() || config.rpc.password.is_some(),
    );
    redacted_pair(&mut s, &["auth"], !config.rpc.auth.is_empty());
    if let Some(cookie) = &config.rpc.cookiefile {
        kv(&mut s, "cookiefile", path_val(cookie));
    }
    kv(&mut s, "work_queue", config.rpc.work_queue);
    kv(
        &mut s,
        "allowed_methods",
        list_val(&config.rpc.allowed_methods),
    );
    kv(
        &mut s,
        "allow_duplicate_shielded_recipients",
        config.rpc.allow_duplicate_shielded_recipients,
    );

    table(&mut s, "keys");
    if let Some(id) = &config.keys.age_identity {
        kv(&mut s, "age_identity", path_val(id));
    }
    kv(&mut s, "auto_unlock", config.keys.auto_unlock);
    kv(
        &mut s,
        "allow_multiple_spending_wallets",
        config.keys.allow_multiple_spending_wallets,
    );
    kv(
        &mut s,
        "bootstrap_from_keys",
        config.keys.bootstrap_from_keys,
    );
    // Rendered only when set: unset means "each wallet's coin default", which is not one
    // number (100 Zcash / 6 Bitcoin) - the per-wallet lines below carry the resolved values.
    if let Some(margin) = config.keys.fresh_wallet_birthday_margin {
        kv(&mut s, "fresh_wallet_birthday_margin", margin);
    }

    table(&mut s, "sync");
    kv(&mut s, "interval_secs", config.sync.interval_secs);
    kv(&mut s, "rebroadcast_secs", config.sync.rebroadcast_secs);

    table(&mut s, "spend");
    kv(
        &mut s,
        "trusted_confirmations",
        config.spend.trusted_confirmations,
    );
    kv(
        &mut s,
        "untrusted_confirmations",
        config.spend.untrusted_confirmations,
    );
    kv(
        &mut s,
        "trust_own_transactions",
        config.spend.trust_own_transactions,
    );
    // The `Debug` spelling is the config spelling (`SendPrivacy::parse` accepts exactly these),
    // so the rendered value round-trips.
    kv(
        &mut s,
        "privacy_policy",
        str_val(&format!("{:?}", config.spend.privacy)),
    );
    kv(
        &mut s,
        "orchard_action_limit",
        config.spend.orchard_action_limit,
    );
    kv(&mut s, "cache_proving_key", config.spend.cache_proving_key);
    kv(&mut s, "pipeline_proving", config.spend.pipeline_proving);
    kv(&mut s, "target_note_count", config.spend.target_note_count);
    kv(
        &mut s,
        "min_split_output_value",
        config.spend.min_split_output_value,
    );

    table(&mut s, "pools");
    pools_keys(&mut s, &config.pools);

    table(&mut s, "health");
    kv(&mut s, "enabled", config.health.enabled);
    kv(&mut s, "bind", str_val(&config.health.bind.to_string()));
    kv(&mut s, "port", config.health.port);
    kv(
        &mut s,
        "readiness",
        str_val(config.health.readiness.as_str()),
    );
    kv(&mut s, "max_scan_lag", config.health.max_scan_lag);

    table(&mut s, "fleet");
    // First, because every other key here is inert without it.
    kv(&mut s, "enabled", config.fleet.enabled);
    // Rendered as absolute paths, as resolved: the config accepts either, and an operator
    // reading "which directory is this daemon actually watching for wallet manifests" wants the
    // answer, not the datadir-relative form they may have written.
    kv(&mut s, "manifest_dir", path_val(&config.fleet.manifest_dir));
    kv(&mut s, "dir", path_val(&config.fleet.dir));
    kv(&mut s, "shard_size", config.fleet.shard_size);
    kv(&mut s, "cohort_depth", config.fleet.cohort_depth);

    table(&mut s, "log");
    kv(&mut s, "level", str_val(&config.log.level));
    kv(&mut s, "format", str_val(&config.log.format));

    // Wallets last: every pool setting is emitted per wallet, resolved, so each entry stands on
    // its own rather than depending on the reader to apply the `[pools]` defaults above.
    for (name, w) in &config.wallets {
        table(&mut s, &format!("wallets.{name}"));
        // `coin` renders only when it is not the default, so a Zcash-only config's output is
        // byte-stable across the key's existence - and a non-Zcash wallet's entry names the
        // engine serving it.
        if w.coin != crate::coin::Coin::Zcash {
            kv(&mut s, "coin", str_val(w.coin.name()));
        }
        kv(&mut s, "dir", path_val(&w.dir));
        if let Some(keys_file) = &w.keys_file {
            kv(&mut s, "keys_file", path_val(keys_file));
        }
        // Legal on every coin, rendered only when it differs from what this wallet would
        // resolve to anyway (the global `[keys]` value, else the coin default) - the entry
        // stores the resolved value, so "differs from the fallback" is exactly "this wallet
        // set it".
        let default_margin = config
            .keys
            .fresh_wallet_birthday_margin
            .unwrap_or_else(|| crate::init::default_fresh_wallet_birthday_margin(w.coin));
        if w.fresh_wallet_birthday_margin != default_margin {
            kv(
                &mut s,
                "fresh_wallet_birthday_margin",
                w.fresh_wallet_birthday_margin,
            );
        }
        // `server` is legal on every coin (each engine has its own token grammar), rendered
        // only when this wallet actually sets it: an absent key means "the coin's default
        // upstream" (the global `[backend]` for Zcash, a local bitcoind for Bitcoin).
        #[cfg(feature = "bitcoin")]
        if w.coin == crate::coin::Coin::Bitcoin {
            if let Some(server) = &w.backend.server {
                match crate::btc::chain::resolve_for_wallet(config, w) {
                    Ok(resolved) => {
                        kv_note(&mut s, "server", str_val(server), &resolved.describe())
                    }
                    Err(e) => kv_note(
                        &mut s,
                        "server",
                        str_val(server),
                        &format!("UNRESOLVED: {e}"),
                    ),
                }
            }
        }
        // The remaining per-wallet keys configure the Zcash engine and are refused by
        // `resolve` on any other wallet, so rendering them there would emit a config
        // `config check` rejects - the idempotence contract forbids that.
        if w.coin != crate::coin::Coin::Zcash {
            continue;
        }
        // Endpoint overrides are rendered only when this wallet actually sets them: an absent
        // key means "falls back to [backend]", which is what the omission says.
        let bo = &w.backend;
        if let Some(server) = &bo.server {
            match crate::backend::resolve_for_wallet(config, w) {
                Ok(resolved) => kv_note(&mut s, "server", str_val(server), &resolved.describe()),
                Err(e) => kv_note(
                    &mut s,
                    "server",
                    str_val(server),
                    &format!("UNRESOLVED: {e}"),
                ),
            }
        }
        if let Some(tls) = bo.tls {
            kv(
                &mut s,
                "tls",
                str_val(match tls {
                    None => "auto",
                    Some(true) => "yes",
                    Some(false) => "no",
                }),
            );
        }
        if let Some(roots) = bo.tls_roots {
            kv(
                &mut s,
                "tls_roots",
                str_val(match roots {
                    crate::backend::TlsRoots::Native => "native",
                    crate::backend::TlsRoots::Webpki => "webpki",
                }),
            );
        }
        if let Some(skip) = bo.tls_insecure_skip_verify {
            kv(&mut s, "tls_insecure_skip_verify", skip);
        }
        if let Some(ca) = &bo.tls_ca_file {
            kv(&mut s, "tls_ca_file", path_val(ca));
        }
        if let Some(pins) = &bo.tls_pins {
            let pins: Vec<String> = pins.iter().map(|p| p.to_string()).collect();
            kv(&mut s, "tls_pinned_sha256", list_val(&pins));
        }
        if let Some(assume) = bo.assume_transparent_in_compact_blocks {
            kv(&mut s, "assume_transparent_in_compact_blocks", assume);
        }
        kv(&mut s, "pools", list_val(&w.pools.names()));
        kv(
            &mut s,
            "default_receivers",
            list_val(&w.default_receivers.names()),
        );
        kv(&mut s, "transparent", w.transparent_enabled);
        kv(&mut s, "transparent_default", w.transparent_default);
        kv(&mut s, "transparent_gap_limit", w.transparent_gap_limit);
        kv(
            &mut s,
            "transparent_initial_scan",
            w.transparent_initial_scan,
        );
        kv(
            &mut s,
            "transparent_allow_beyond_recovery_window",
            w.transparent_allow_beyond_recovery_window,
        );
        kv(
            &mut s,
            "transparent_gap_warn_threshold",
            w.transparent_gap_warn_threshold,
        );
    }
    s
}

/// The `[pools]` keys, shared by the global table (per-wallet entries spell the same settings
/// under `[wallets.<name>]`, where the key for the pool list is `pools` rather than `enabled`).
fn pools_keys(s: &mut String, pools: &crate::config::PoolsConfig) {
    kv(s, "enabled", list_val(&pools.enabled.names()));
    kv(
        s,
        "default_receivers",
        list_val(&pools.default_receivers.names()),
    );
    kv(s, "transparent", pools.transparent_enabled);
    kv(s, "transparent_default", pools.transparent_default);
    kv(s, "transparent_gap_limit", pools.transparent_gap_limit);
    kv(
        s,
        "transparent_initial_scan",
        pools.transparent_initial_scan,
    );
    kv(
        s,
        "transparent_allow_beyond_recovery_window",
        pools.transparent_allow_beyond_recovery_window,
    );
    kv(
        s,
        "transparent_gap_warn_threshold",
        pools.transparent_gap_warn_threshold,
    );
}

/// `[name]`, preceded by a blank line.
fn table(s: &mut String, name: &str) {
    s.push_str(&format!("\n[{name}]\n"));
}

/// `key = value`, where `value` is already TOML-formatted.
fn kv(s: &mut String, key: &str, value: impl std::fmt::Display) {
    s.push_str(&format!("{key} = {value}\n"));
}

/// `key = value  # note` - for facts that are *derived* from the value (so the comment stays a
/// function of the configuration, and two renders of the same config still match).
fn kv_note(s: &mut String, key: &str, value: impl std::fmt::Display, note: &str) {
    s.push_str(&format!("{key} = {value}  # {note}\n"));
}

/// Name the secret-bearing keys without printing them. Emitted only when something is set, so a
/// config with no credentials renders without the noise.
fn redacted_pair(s: &mut String, keys: &[&str], set: bool) {
    if set {
        s.push_str(&format!("# {} = <redacted>\n", keys.join(", ")));
    }
}

/// A TOML string literal, escaped by the same library that will parse it back.
fn str_val(v: &str) -> String {
    toml::Value::String(v.to_string()).to_string()
}

fn path_val(p: &Path) -> String {
    str_val(&p.display().to_string())
}

fn list_val<S: AsRef<str>>(items: &[S]) -> String {
    toml::Value::Array(
        items
            .iter()
            .map(|i| toml::Value::String(i.as_ref().to_string()))
            .collect(),
    )
    .to_string()
}

/// `zecd config show`.
///
/// Same stream contract as `config check`: the configuration goes to stdout, provenance to
/// stderr, so `zecd config show > effective.toml` captures exactly the config.
///
/// Unlike `config check`, a missing config file is **not** an error here. The two commands
/// answer different questions: `check` validates a file the caller says exists (so a path that
/// isn't there is a typo worth failing on), while `show` reports what this binary would do -
/// which is perfectly well defined with no file at all, and is then the most direct way to see
/// the built-in defaults.
#[cfg(feature = "cli")]
pub fn run(cli: &Cli, _args: &ConfigShowArgs) -> anyhow::Result<()> {
    let conf_path = AppConfig::conf_path(cli);
    let source = if conf_path.exists() {
        format!("config file: {}", conf_path.display())
    } else {
        format!(
            "no config file at {} - showing this build's defaults with any CLI/environment \
             overrides applied",
            conf_path.display()
        )
    };
    emit_err(&format!("zecd {}\n{source}\n", env!("CARGO_PKG_VERSION")));

    let config = AppConfig::resolve(cli)?;
    emit(&render(&config));
    Ok(())
}

/// Write the configuration to stdout, treating a closed pipe as a clean exit (`zecd config show
/// | head` would otherwise *panic* through `print!`, which panics on EPIPE).
#[cfg(feature = "cli")]
fn emit(text: &str) {
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(text.as_bytes()).and_then(|()| out.flush());
}

#[cfg(feature = "cli")]
fn emit_err(text: &str) {
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(text.as_bytes()).and_then(|()| err.flush());
}

#[cfg(all(test, feature = "cli"))]
mod tests {
    use super::*;
    use clap::Parser;

    fn resolve_from(text: &str, dir: &Path) -> AppConfig {
        let path = dir.join("zecd.toml");
        std::fs::write(&path, text).unwrap();
        let cli = Cli::try_parse_from(["zecd", "--conf", path.to_str().unwrap()]).unwrap();
        AppConfig::resolve(&cli).expect("config resolves")
    }

    /// The property that keeps this honest: the rendered config must re-resolve to the same
    /// configuration, and render identically the second time. That pins every emitted key as one
    /// the parser accepts (`deny_unknown_fields` would otherwise let the renderer drift into
    /// producing a config zecd itself would reject) and every emitted *value* as one that parses
    /// back to what it came from.
    ///
    /// Deliberately a secret-free config: redacted keys are emitted as comments, so a config
    /// carrying credentials cannot round-trip by construction (see the module docs).
    #[test]
    fn render_is_idempotent_through_a_resolve() {
        let dir = tempfile::tempdir().unwrap();
        let first = render(&resolve_from(
            &format!(
                "network = \"test\"\ndatadir = {:?}\n\
                 [pools]\nenabled = [\"orchard\", \"sapling\"]\ndefault_receivers = [\"orchard\"]\n\
                 transparent = true\ntransparent_gap_limit = 30\n\
                 [spend]\nprivacy_policy = \"FullPrivacy\"\ntrusted_confirmations = 5\n\
                 untrusted_confirmations = 11\n\
                 [health]\nreadiness = \"connected\"\n",
                dir.path()
            ),
            dir.path(),
        ));

        let round_trip = tempfile::tempdir().unwrap();
        let second = render(&resolve_from(&first, round_trip.path()));
        assert_eq!(
            first, second,
            "the effective config must survive being fed back to zecd"
        );

        // ...and it really did carry the settings, rather than round-tripping empty. Note the
        // pool list comes back in `ReceiverSet`'s canonical order, not the order the file wrote -
        // which is itself worth rendering, since that is the order zecd works in.
        assert!(
            first.contains("privacy_policy = \"FullPrivacy\""),
            "{first}"
        );
        assert!(
            first.contains("enabled = [\"sapling\", \"orchard\"]"),
            "{first}"
        );
        assert!(first.contains("readiness = \"connected\""), "{first}");
    }

    /// A Bitcoin wallet renders its `coin` (the one non-default key selecting it), none of the
    /// Zcash-engine keys (`resolve` refuses them there, and the idempotence contract forbids
    /// emitting a config `config check` rejects), and still round-trips byte-identically.
    #[test]
    #[cfg(feature = "bitcoin")]
    fn a_bitcoin_wallet_renders_without_zcash_engine_keys_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let first = render(&resolve_from(
            &format!(
                "network = \"test\"\ndatadir = {:?}\n[wallets.btc]\ncoin = \"bitcoin\"\n",
                dir.path()
            ),
            dir.path(),
        ));
        // The effective Bitcoin testnet renders as a top-level key on a testnet daemon,
        // default included, so the choice of chain is never implicit in the output.
        assert!(first.contains("btc_testnet = \"testnet3\""), "{first}");
        let btc_section = first
            .split("[wallets.btc]")
            .nth(1)
            .map(|rest| rest.split("[wallets.").next().unwrap())
            .expect("bitcoin wallet section rendered");
        assert!(btc_section.contains("coin = \"bitcoin\""), "{first}");
        for absent in ["pools", "transparent", "default_receivers", "server"] {
            assert!(
                !btc_section.contains(absent),
                "{absent:?} must not render for a bitcoin wallet:\n{first}"
            );
        }
        // The implicit default wallet is untouched: no `coin` line (it is the default), the
        // Zcash keys present as ever.
        let default_section = first
            .split("[wallets.default]")
            .nth(1)
            .map(|rest| rest.split("[wallets.").next().unwrap())
            .expect("default wallet section rendered");
        assert!(!default_section.contains("coin ="), "{first}");
        assert!(default_section.contains("transparent = false"), "{first}");

        let round_trip = tempfile::tempdir().unwrap();
        let second = render(&resolve_from(&first, round_trip.path()));
        assert_eq!(first, second);

        // A non-default btc_testnet round-trips too: the rendered key is one `resolve`
        // accepts and reproduces.
        let testnet4 = render(&resolve_from(
            &format!(
                "network = \"test\"\ndatadir = {:?}\nbtc_testnet = \"testnet4\"\n\
                 [wallets.btc]\ncoin = \"bitcoin\"\n",
                dir.path()
            ),
            dir.path(),
        ));
        assert!(
            testnet4.contains("btc_testnet = \"testnet4\""),
            "{testnet4}"
        );
        assert_eq!(testnet4, render(&resolve_from(&testnet4, dir.path())));
    }

    /// The kyoto fee chain renders its effective order, names each tier's resolved endpoint
    /// (which is where an inert tier becomes visible), and round-trips.
    #[test]
    #[cfg(feature = "bitcoin")]
    fn the_fee_oracle_chain_renders_its_effective_endpoints_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let show = |body: &str| render(&resolve_from(body, dir.path()));

        // Defaults on testnet4: both tiers named, but only mempool.space resolves - Blockstream
        // runs no testnet4 Esplora, and the rendering says so rather than implying two oracles.
        let first = show(&format!(
            "network = \"test\"\nbtc_testnet = \"testnet4\"\ndatadir = {:?}\n",
            dir.path()
        ));
        assert!(
            first.contains("sources = [\"mempool_space\", \"esplora\", \"peer_median\"]"),
            "{first}"
        );
        assert!(
            first.contains("# mempool_space_url unset - using https://mempool.space/testnet4/"),
            "{first}"
        );
        assert!(
            first.contains("# esplora_url unset and no built-in endpoint"),
            "{first}"
        );
        assert_eq!(first, render(&resolve_from(&first, dir.path())));

        // An override renders as the real key - the one shape here that is a config value - and
        // survives a re-resolve, so `config show | config check` stays a valid pipeline.
        let overridden = show(&format!(
            "network = \"test\"\nbtc_testnet = \"testnet4\"\ndatadir = {:?}\n\
             [fees]\nsources = [\"esplora\", \"peer_median\"]\n\
             esplora_url = \"http://esplora.internal/api/fee-estimates\"\n",
            dir.path()
        ));
        assert!(
            overridden.contains("sources = [\"esplora\", \"peer_median\"]"),
            "{overridden}"
        );
        assert!(
            overridden.contains("esplora_url = \"http://esplora.internal/api/fee-estimates\""),
            "{overridden}"
        );
        // A source not in the chain renders nothing at all: its endpoint is never asked.
        assert!(!overridden.contains("mempool_space_url"), "{overridden}");
        assert_eq!(overridden, render(&resolve_from(&overridden, dir.path())));
    }

    /// The mempool feed renders its effective (default: empty) source list, names the
    /// endpoint it would subscribe at, and round-trips.
    #[test]
    #[cfg(feature = "bitcoin")]
    fn the_mempool_feed_renders_its_endpoint_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let show = |body: &str| render(&resolve_from(body, dir.path()));

        // Off by default: the empty list is the effective value, rendered so a reader sees
        // the knob exists, and nothing else about it.
        let off = show(&format!(
            "network = \"test\"\nbtc_testnet = \"testnet4\"\ndatadir = {:?}\n",
            dir.path()
        ));
        assert!(off.contains("[mempool]\nsources = []\n"), "{off}");
        // Nothing about the endpoint in the section (the `[fees]` section has a key of the
        // same name, so look at this section alone).
        let section = off.split("[mempool]").nth(1).unwrap();
        let section = section.split("\n[").next().unwrap();
        assert!(!section.contains("mempool_space_url"), "{off}");
        assert_eq!(off, render(&resolve_from(&off, dir.path())));

        // Named: the resolved public endpoint rides as a note (it is not a config value).
        let on = show(&format!(
            "network = \"test\"\nbtc_testnet = \"testnet4\"\ndatadir = {:?}\n\
             [mempool]\nsources = [\"mempool_space\"]\n",
            dir.path()
        ));
        assert!(on.contains("sources = [\"mempool_space\"]"), "{on}");
        assert!(
            on.contains("# mempool_space_url unset - using wss://mempool.space/testnet4/api/v1/ws"),
            "{on}"
        );
        assert_eq!(on, render(&resolve_from(&on, dir.path())));

        // Overridden: the real key, surviving a re-resolve.
        let hosted = show(&format!(
            "network = \"regtest\"\ndatadir = {:?}\n\
             [mempool]\nsources = [\"mempool_space\"]\n\
             mempool_space_url = \"ws://mempool.internal:8999/api/v1/ws\"\n",
            dir.path()
        ));
        assert!(
            hosted.contains("mempool_space_url = \"ws://mempool.internal:8999/api/v1/ws\""),
            "{hosted}"
        );
        let section = hosted.split("[mempool]").nth(1).unwrap();
        let section = section.split("\n[").next().unwrap();
        assert!(!section.contains("p2p_"), "{hosted}");
        assert_eq!(hosted, render(&resolve_from(&hosted, dir.path())));

        // The P2P source: the peer is per wallet unless overridden, and the snapshot flag
        // renders with its effective value.
        let p2p = show(&format!(
            "network = \"test\"\nbtc_testnet = \"testnet4\"\ndatadir = {:?}\n\
             [mempool]\nsources = [\"p2p\"]\n",
            dir.path()
        ));
        assert!(
            p2p.contains("# p2p_peer unset - each kyoto wallet"),
            "{p2p}"
        );
        assert!(p2p.contains("p2p_snapshot = false"), "{p2p}");
        assert!(p2p.contains("p2p_snapshot_interval_secs = 300"), "{p2p}");
        // (Again scoped to the section: `[fees]` has a key of the same name.)
        let section = p2p.split("[mempool]").nth(1).unwrap();
        let section = section.split("\n[").next().unwrap();
        assert!(!section.contains("mempool_space_url"), "{p2p}");
        assert_eq!(p2p, render(&resolve_from(&p2p, dir.path())));
        let pinned = show(&format!(
            "network = \"test\"\nbtc_testnet = \"testnet4\"\ndatadir = {:?}\n\
             [mempool]\nsources = [\"p2p\", \"mempool_space\"]\n\
             p2p_peer = \"[2001:db8::7]:48333\"\np2p_snapshot = true\n",
            dir.path()
        ));
        assert!(
            pinned.contains("p2p_peer = \"[2001:db8::7]:48333\""),
            "{pinned}"
        );
        assert!(pinned.contains("p2p_snapshot = true"), "{pinned}");
        assert_eq!(pinned, render(&resolve_from(&pinned, dir.path())));
    }

    /// Every value the file left unset appears, filled in by this build - the whole point of the
    /// command, and what makes a cross-version diff meaningful.
    #[test]
    fn defaults_the_file_never_mentions_are_rendered() {
        let dir = tempfile::tempdir().unwrap();
        let out = render(&resolve_from("network = \"test\"\n", dir.path()));
        for defaulted in [
            "privacy_policy = \"AllowRevealedRecipients\"",
            "trusted_confirmations = 3",
            "untrusted_confirmations = 10",
            "work_queue = 100",
            "interval_secs = 20",
            "readiness = \"synced\"",
            "transparent = false",
            "cache_proving_key = true",
        ] {
            assert!(out.contains(defaulted), "missing {defaulted:?} in:\n{out}");
        }
        // The resolved endpoint rides alongside the token it derives from.
        assert!(
            out.contains("server = \"zebra\"  # zebra-rpc 127.0.0.1:18234"),
            "{out}"
        );
    }

    /// Credentials are named, never printed - `zecd config show` output is the kind of thing
    /// that gets pasted into an issue, and the RPC password is spend authority.
    #[test]
    fn secrets_are_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let out = render(&resolve_from(
            "network = \"test\"\n\
             [rpc]\nuser = \"alice\"\npassword = \"hunter2\"\nauth = [\"bob:ab$cd\"]\n\
             [zebra]\nrpc_user = \"zu\"\nrpc_password = \"zp\"\n",
            dir.path(),
        ));
        for secret in ["hunter2", "bob:ab$cd", "zp"] {
            assert!(!out.contains(secret), "leaked {secret:?}:\n{out}");
        }
        assert!(out.contains("# user, password = <redacted>"), "{out}");
        assert!(out.contains("# auth = <redacted>"), "{out}");
        assert!(
            out.contains("# rpc_user, rpc_password = <redacted>"),
            "{out}"
        );
        // Commented out rather than a parsable placeholder: a redacted value that *parses* would
        // become a real, wrong credential if the output were ever deployed.
        assert!(!out.contains("password = \"<redacted>\""), "{out}");
    }

    /// A wallet entry stands on its own: every pool setting appears resolved under the wallet,
    /// so reading it never means mentally applying the global `[pools]` defaults.

    #[test]
    fn per_wallet_backend_overrides_render_and_re_resolve() {
        // The renderer's schema contract on the per-wallet endpoint keys: what it emits must be
        // a config `resolve` accepts, and rendering it again must reproduce it byte for byte.
        let dir = tempfile::tempdir().unwrap();
        let cfg = resolve_from(
            &format!(
                "network = \"test\"\ndatadir = {:?}\n\
                 [backend]\nserver = \"zebra\"\n\
                 [wallets.default]\n\
                 [wallets.replica]\nserver = \"https://lwd.example:9067\"\n\
                 tls = \"yes\"\ntls_roots = \"webpki\"\n\
                 assume_transparent_in_compact_blocks = true\n",
                dir.path()
            ),
            dir.path(),
        );
        let out = render(&cfg);

        let replica = out
            .split("[wallets.replica]")
            .nth(1)
            .expect("the wallet table");
        assert!(
            replica.contains("server = \"https://lwd.example:9067\""),
            "{replica}"
        );
        assert!(replica.contains("tls = \"yes\""), "{replica}");
        assert!(replica.contains("tls_roots = \"webpki\""), "{replica}");
        assert!(
            replica.contains("assume_transparent_in_compact_blocks = true"),
            "{replica}"
        );

        // A wallet with no overrides emits no endpoint keys - it falls back to [backend].
        let default = out
            .split("[wallets.default]")
            .nth(1)
            .and_then(|rest| rest.split("[wallets.replica]").next())
            .expect("the default wallet table");
        assert!(!default.contains("server ="), "{default}");
        assert!(!default.contains("tls ="), "{default}");

        assert_eq!(out, render(&resolve_from(&out, dir.path())));
    }

    #[test]
    fn wallet_entries_carry_their_resolved_pool_settings() {
        let dir = tempfile::tempdir().unwrap();
        let out = render(&resolve_from(
            &format!(
                "network = \"test\"\ndatadir = {:?}\n\
                 [pools]\ntransparent = true\ntransparent_gap_limit = 20\n\
                 [wallets.exchange]\ntransparent_gap_limit = 1000\ntransparent_initial_scan = 70000\n",
                dir.path()
            ),
            dir.path(),
        ));
        let wallet = out
            .split("[wallets.exchange]")
            .nth(1)
            .expect("the wallet table");
        assert!(wallet.contains("transparent = true"), "{wallet}");
        assert!(wallet.contains("transparent_gap_limit = 1000"), "{wallet}");
        assert!(
            wallet.contains("transparent_initial_scan = 70000"),
            "{wallet}"
        );
    }
}
