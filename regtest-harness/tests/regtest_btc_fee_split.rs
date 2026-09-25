//! `fee_split = "output"` live (zecd's extension over `subtractfeefrom`): each recipient
//! named to pay the fee is charged its own output's block space at the send's rate, and the
//! sender's change pays everything else.
//!
//! 1. A `sendmany` to a P2WPKH and a P2TR recipient, both paying, at 10 sat/vB: the node's
//!    view of the transaction shows each output cut by exactly its own share - 31 vB and
//!    43 vB at 10 sat/vB, 310 and 430 sat - and the wallet was debited the rest of the fee.
//! 2. The same send with Core's equal split, for contrast: the recipients cover the whole
//!    fee between them and the sender is debited exactly the amounts.
//!
//! The engine path is the same over either chain source, so this runs over bitcoind only.
//! Skips cleanly without a bitcoind or a zecd built without the `bitcoin` feature.

use serde_json::{json, Value};
use zecd_regtest_harness::btc::{provisioned, BitcoinD, BtcBackend, ZecdBtc};

/// A BTC amount as satoshis.
fn sats(v: &Value) -> u64 {
    (v.as_f64().expect("an amount") * 1e8).round() as u64
}

/// The value the node's decoded transaction pays `address`.
fn paid_to(decoded: &Value, address: &str) -> u64 {
    decoded["vout"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["scriptPubKey"]["address"] == json!(address))
        .map(|o| sats(&o["value"]))
        .unwrap_or_else(|| panic!("no output to {address}: {decoded}"))
}

async fn wallet_balance(zecd: &ZecdBtc) -> u64 {
    let b = zecd
        .call("getbalances", json!([]))
        .await
        .expect("getbalances");
    sats(&b["mine"]["trusted"]) + sats(&b["mine"]["untrusted_pending"])
}

#[tokio::test(flavor = "multi_thread")]
async fn btc_fee_split_output_charges_each_recipient_its_own_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(bitcoind) = provisioned(dir.path()) else {
        return;
    };
    let node = BitcoinD::start(&bitcoind, &dir.path().join("btcdata")).await;
    node.mine(101).await;
    let mut zecd = ZecdBtc::prepare(
        dir.path().join("zecddata"),
        BtcBackend::Bitcoind,
        &node,
        &["btc"],
    );
    zecd.init_ok("btc", &["--birthday", "0"]);
    zecd.start().await;
    zecd.wait_height(101).await;
    let addr = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress");
    node.call("sendtoaddress", json!([addr, 1.0]))
        .await
        .expect("fund");
    node.mine(1).await;
    zecd.wait_height(102).await;
    zecd.wait_wallet_balance("btc", 1.0).await;

    let wpkh = node
        .call("getnewaddress", json!(["", "bech32"]))
        .await
        .expect("a P2WPKH address");
    let wpkh = wpkh.as_str().unwrap().to_string();
    let tr = node
        .call("getnewaddress", json!(["", "bech32m"]))
        .await
        .expect("a P2TR address");
    let tr = tr.as_str().unwrap().to_string();

    // 1. By output.
    let before = wallet_balance(&zecd).await;
    let txid = zecd
        .call(
            "sendmany",
            json!(["", {&wpkh: 0.1, &tr: 0.2}, null, "", [&wpkh, &tr], null, null, null, 10, null, "output"]),
        )
        .await
        .expect("sendmany fee_split output");
    let txid = txid.as_str().unwrap().to_string();
    node.wait_mempool_contains(&txid).await;
    let decoded = node
        .call("getrawtransaction", json!([txid, true]))
        .await
        .expect("getrawtransaction");
    assert_eq!(paid_to(&decoded, &wpkh), 10_000_000 - 310, "{decoded}");
    assert_eq!(paid_to(&decoded, &tr), 20_000_000 - 430, "{decoded}");
    let entry = node
        .call("getmempoolentry", json!([txid]))
        .await
        .expect("getmempoolentry");
    let fee = sats(&entry["fees"]["base"]);
    assert!(fee > 740, "the sender paid the rest of the fee: {entry}");
    // The wallet paid out the recipients' net amounts plus the whole fee less their shares.
    let after = wallet_balance(&zecd).await;
    assert_eq!(
        before - after,
        (30_000_000 - 740) + fee,
        "debit = what the recipients got + the fee"
    );

    // 2. Core's equal split, for contrast: the recipients pay the whole fee.
    let before = after;
    let txid = zecd
        .call(
            "sendmany",
            json!(["", {&wpkh: 0.1, &tr: 0.2}, null, "", [&wpkh, &tr], null, null, null, 10]),
        )
        .await
        .expect("sendmany equal split");
    let txid = txid.as_str().unwrap().to_string();
    node.wait_mempool_contains(&txid).await;
    let after = wallet_balance(&zecd).await;
    assert_eq!(
        before - after,
        30_000_000,
        "the sender is debited exactly the amounts"
    );
    node.mine(1).await;
    zecd.wait_height(103).await;
}
