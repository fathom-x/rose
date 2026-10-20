//! Build and query an embedded rose node - no HTTP RPC server, no health server - through
//! `rosed::node::Node::call`, which dispatches with wire-identical semantics (same method
//! table, same error codes as the JSON-RPC server).
//!
//! Requires an initialized wallet datadir (`rose init`) and a reachable upstream (the
//! configured `[backend] server`, by default a local zebrad). Run with:
//!
//! ```sh
//! cargo run --release --example embedded -- <datadir>
//! ```
//!
//! NB the node needs a multi-thread tokio runtime (the scan and proving paths use
//! `tokio::task::block_in_place`).

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let datadir = std::env::args().nth(1).map(std::path::PathBuf::from);
    let config = rosed::config::AppConfig::resolve_overrides(&rosed::config::ConfigOverrides {
        datadir,
        ..Default::default()
    })?;

    let node = rosed::node::NodeBuilder::new(config).start().await?;

    // Wire-identical dispatch: the same call a JSON-RPC client would make as
    // {"method": "getblockcount", "params": []}, minus the HTTP transport.
    match node.call(None, "getblockcount", vec![]).await {
        Ok(height) => println!("fully-scanned height: {height}"),
        Err(e) => println!("getblockcount failed: {} (code {})", e.message, e.code),
    }

    node.shutdown().await;
    Ok(())
}
