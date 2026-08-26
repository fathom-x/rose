# The BDK-backed Bitcoin engine: status and roadmap

Architecture lives elsewhere - `mod.rs` for the engine-boundary rules, the BDK engine notes in the project docs for the design decisions, `chain.rs`'s module doc for the backend seam. This
file records what is deliberately not done yet and where the open divergences from Bitcoin
Core are headed, so a reader of this directory does not mistake a phase boundary for a design
decision (or vice versa).

Status: phases 1 and 2 are complete. A bitcoin wallet (`coin = "bitcoin"`, behind the
`bitcoin` cargo feature) derives BIP 84 keys from the shared seed, persists public
descriptors only, syncs against a local bitcoind (checkpoint-anchored block emission, a
mempool pass at tip for 0-conf, reorg recovery, restart resume), tracks Core's
trusted/untrusted confirmation semantics, and sends (per-send seed-derived signers,
`estimatesmartfee`-driven fees, inputs locked at 0-conf against the next selection).

## History accounting: the Zcash side's shape (Core's)

`listtransactions`/`gettransaction details` emit **one entry per wallet-relevant output** -
the same accounting as the Zcash side's `rpc/wallet_methods.rs::tx_entries`, which is also
Bitcoin Core's: a multi-recipient send produces one `send` entry per recipient with its own
`address`/`amount`/`vout` (a real outpoint index here, with no pool caveat), a payment to
one of the wallet's own external addresses shows as a send+receive pair, and change
(internal keychain) is hidden. The attribution walks each transaction's outputs through the
wallet's script-to-keychain lookup (`BtcTxDetail` on `BtcTxRecord`, built in
`actor.rs::tx_entries`; rendered by `rpc/btc_methods.rs::detail_json`/`tx_entry_json`).
Entries also carry `label` (the stateless `""`) and `bip125-replaceable` (`"yes"` only for
an unconfirmed, explicitly-signaling transaction); `gettransaction`'s top-level `amount` is
the sum of the details, so a self-payment nets to zero and change never distorts it. Still
omitted, matching the Zcash side: `walletconflicts` and `abandoned`.

## Not yet implemented

Everything here is refused with a clear error rather than silently ignored or half-done:

- **`subtractfeefromamount` and explicit `fee_rate`** on `sendtoaddress`/`sendmany`.
- **`walletpassphrase`** - a passphrase-encrypted bitcoin wallet cannot send yet (the seed
  is only decrypted by the identity-file custody model at startup).
- **Address types other than bech32** (BIP 84 is the engine's only derivation): issuance is
  bech32-only, and a restore of a seed whose history lives on BIP 44/49/86 derivations will
  not see those funds. Additional descriptor templates are the fix, once wanted.
- **BIP-157 (kyoto) light mode** - the planned second backend, giving lightwalletd-grade
  privacy with no server at all; `chain.rs` documents where its `AnySource`-style enum seam
  grows.
- **Health/readiness integration** - `/healthz`/`/readyz`/`/status` speak Zcash-sync
  vocabulary and do not aggregate bitcoin wallets' sync state yet.
- **`rescan` / `export-ufvk` / `derive-address`** refuse bitcoin wallets (each names why and
  what to do instead); a bitcoin equivalent of offline address derivation and the
  wipe-and-rescan flow is future work.

Deliberate posture, not a gap: the fee fallback (1 sat/vB on test networks, hard refusal on
mainnet without an `estimatesmartfee` answer) mirrors bitcoind's own `fallbackfee` defaults.
