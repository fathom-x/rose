# The BDK-backed Bitcoin engine: status and roadmap

Architecture lives elsewhere - `mod.rs` for the engine-boundary rules, the BDK engine notes in the project docs for the design decisions, `chain.rs`'s module doc for the backend seam. This
file records what is deliberately not done yet and where the open divergences from Bitcoin
Core are headed, so a reader of this directory does not mistake a phase boundary for a design
decision (or vice versa).

Status: phases 1, 2 and 3 are complete. A bitcoin wallet (`coin = "bitcoin"`, behind the
`bitcoin` cargo feature - off for a plain `cargo build`, on in the shipped Docker images,
which carry both engines; `--no-default-features --features bitcoin,server,cli` builds this
engine alone, with no Zcash crate in the tree) derives BIP 84 keys from the shared seed, persists public
descriptors only, syncs against a local bitcoind (checkpoint-anchored block emission, a
mempool pass at tip for 0-conf, reorg recovery, restart resume), tracks Core's
trusted/untrusted confirmation semantics, and sends (per-send seed-derived signers,
`estimatesmartfee`-driven fees, inputs locked at 0-conf against the next selection).
Phase 3 adds the **kyoto** backend (`server = "kyoto"`): a BIP-157/158 compact-block-filter
light client over P2P, with no server and no credentials to provision. **Watch-only
wallets** pair with a spender through the account xpub: `zecd export-xpub` prints it with
its key origin, `zecd init --xpub` builds a seedless wallet from it (any number beside the
one spender), `keys.toml` pins it, and the wallet syncs, reports and refuses to spend
exactly as a UFVK watch-only Zcash wallet does. Import is BIP 84 first-account keys only,
the one derivation the engine has; a bare xpub (no key origin, as most wallets show it) is
accepted as that account and pinned with the all-zero fingerprint. On **mainnet** an xpub
import or a seed restore requires `--birthday` (a date or height; `--birthday 481824` asks
for the full scan from SegWit activation explicitly): the alternative is ~485k blocks of
filters that a kyoto first sync must finish in one run, since `bip157` persists nothing
until it completes. The testnets keep the warned from-activation default.

## Restores and the address lookahead

BDK derives and watches a fixed number of addresses past the last revealed index of each
keychain - its *lookahead*, 25 by default - and attributes an output only to an address in
that window; a payment found at an unrevealed index reveals up to it and pushes the window
on. On a restore or an `init --xpub` import nothing is revealed yet, so the lookahead is
the BIP-44 gap limit: the longest run of never-paid addresses the scan can bridge. A
wallet whose history skipped more than that between payments **silently misses** the later
funds - over kyoto too, where the recovery scan asks the node to watch 100 scripts per
keychain but the wallet's own index still decides what an output belongs to. Set
`[wallets.<name>] lookahead` above the wallet's widest gap before restoring (the engine
applies it at every load, and kyoto's recovery hint follows it upward);
`regtest_btc_lookahead.rs` pins both halves. The Zcash side's knob is
`[pools] transparent_gap_limit`.

## The two backends are not equivalent

Choosing `kyoto` buys privacy and drops a dependency; it also gives up capabilities the
bitcoind backend has. The differences are behavioral, not cosmetic:

| | `bitcoind` | `kyoto` |
|---|---|---|
| Credentials | rpcauth/cookie, cleartext-locality gated | none - nothing secret on the wire |
| 0-conf receives | yes (mempool pass at tip) | **only with the `[mempool]` feed** - a relay connection to the trusted peer (`p2p`, the default) or a mempool.space websocket (`mempool_space`, opt-in), both matched locally (see below) - since filters are block-derived, and with the feed off (`sources = []`) or no peer to relay from, a payment is first seen in its block |
| Eviction reporting | yes | only via the feed - `p2p_snapshot` mempool snapshots, or the websocket's `removed` deltas - settled at the next scan tip; **none** without it |
| Rebroadcast of unconfirmed transactions | at each new tip, skipping what the node's mempool holds, verdicts classified (see below) | at each new tip, skipping what the feed reports held when one runs, else blind - every unconfirmed transaction re-announced; no verdicts either way |
| Fee estimation | `estimatesmartfee` | the `[fees]` oracle chain (mempool.space, then Esplora), falling back to a relay floor + recent-block estimate |
| Birthday at `init` | dials once for the tip | **defaults to today**, offline; `--birthday` overrides |
| Fresh-wallet scan start | the birthday | the recorded birthday anchor, else a shipped checkpoint at/below the birthday (see below) |

`init` could anchor a birthday over kyoto by starting a node and syncing headers, but that
turns an instant offline command into a minutes-long one. Instead a fresh kyoto wallet
defaults to **today** - a new wallet's funds cannot predate its own creation, so the
current date serves exactly as well as the tip - recorded offline as if the operator had
passed today's date (regtest, whose timestamps mean nothing, defaults to genesis instead).
`--birthday` overrides with a height or a `YYYY-MM-DD` date. On mainnet either resolves
offline to a `(height, hash)` anchor from the **shipped per-day table** (`btc/birthdays.rs`
over `birthdays-main.bin`, one entry per UTC day since SegWit activation, generated by
`scripts/btc-birthday-table.py` from a trusted node and cut a thousand blocks below its
tip): a date to the first block of the previous day, a height to the last day entry at or
below it, and past the table's end its newest entry as the first scan's floor (the kyoto
`recovery_floor` consults the table, so that floor ages with the build rather than with
the fixed shipped checkpoint), the date recorded in `keys.toml` (`birthday_time`) so the
first sync can refine it. A test-network date resolves offline against the shipped scan
floor with the date recorded the same way,
while over a bitcoind upstream it binary-searches the node's headers with a one-day safety
margin - approximate every way, and safely so: an early birthday only scans more.

Kyoto anchors a recovery on a `HashCheckpoint` - a height *and* a hash - while `init`
records only a height, so the birthday alone cannot start a scan. What can is the
**per-wallet birthday anchor**: a resolved `(height, hash)` pair in the
engine's wallet database (`store.rs::save_birthday_anchor`, chain-derived cache). The
bitcoind `init` paths record it on the dial they already make (the fresh-wallet tip anchor
and the date search - which is also what lets a wallet initialized against bitcoind switch
to kyoto and keep a short first scan); a kyoto wallet starts its first scan at the shipped
floor and resolves the anchor against its *own* synced headers in the background
(`kyoto.rs::resolve_birthday_anchor` - one header fetch for a height target, the shared
interpolated `HeightSearch` for a date, bracketed one above the scan start because
`bip157`'s header tree never holds the recovery anchor itself), then the actor persists it
- only while the wallet is still checkpoint-less, so a resolution that loses the race to
the first update never restarts a synced client - and restarts the
scan there. Once resolved, every later first-scan attempt starts at the birthday.

Every recorded anchor - init's and the resolver's alike - respects a **per-network reorg
depth** (`kyoto.rs::anchor_reorg_margin`: 6 on mainnet and regtest, 100 on the testnets,
whose difficulty-reset block storms reorg tens of blocks): the anchor hash is trusted
verbatim by the next first scan and nothing clears a bad one, so a block that could still
reorg out is never recorded. Init caps the anchor below the birthday when the birthday
itself sits tip-proximate (`init::init_anchor_height`); the resolver instead *waits* until
the synced chain extends the margin past a height target before recording it, so a
partially-synced header chain cannot cap an anchor low.

The shipped floors (`scan_floor`, one per public network - mainnet, testnet3, testnet4)
remain as the trusted base a resolution chains from and the start for anchor-less wallets:
any hash at or below the birthday will do, and each shipped block predates zecd's **first
release**, so it sits below the birthday of every generated wallet that will ever exist on
its network. Testnet3 needs its floor *more* than mainnet, not less: its chain is over 5M
blocks, so a first sync from genesis effectively never finishes. Correctness never depends
on the values - `recovery_floor` applies a floor per wallet, only when that wallet's
birthday is at or above it, and falls back to the full BIP 84 history otherwise (SegWit
activation on mainnet, genesis on the testnets; regtest ships no floor - its chains stay
tiny). The floors are **fixed anchors, not per-release moving targets**: because each
predates the *first* release, a wallet generated by any release has a birthday above every
build's floor, and every build resolves the same wallet the same way. Bumping a floor would
strand a not-yet-synced wallet from an older release below the newer floor (its birthday
would no longer clear it), silently demoting it to the full-history path - so the constants
stay put for backward compatibility, and the growing floor-to-tip gap is absorbed by the
birthday anchor instead of a moving floor.

### The first sync is all-or-nothing, which is why the scan floor exists

`bip157` 0.6.x **persists nothing**. `Builder::data_dir` takes a path and `node.rs`
destructures it as `data_path: _`; even the peer-book writer is `#[allow(unused)]`. The only
durable resume point is therefore the *wallet's* BDK checkpoint - and that advances only when
an `Update` is applied, which kyoto emits only on reaching the tip. A first sync that does not
finish in one run starts over from the beginning on the next.

That is what makes `BTC_KYOTO_SCAN_FLOOR` load-bearing rather than an optimization. A
generated wallet's birthday cannot predate the release that generated it, so its scan starts
at a checkpoint shipped with the build instead of at SegWit activation. Measured against a
local node at height 964388, for a wallet with `--birthday 964300`:

| | filters to fetch | outcome |
|---|---|---|
| From SegWit activation | 254,784 | never finished; restarted from 483823 each run |
| From the scan floor (960000) | 4,389 | completed, `Percent complete: 100` |

After that first completion the wallet has a checkpoint, so restarts take `ScanType::Sync`
and fetch only the blocks since - `CFHeaders: (8/8)` on a verified restart. The missing header
store then costs only a short header re-download per start.

The birthday anchor (above) is what keeps that table's good row good as the fixed floors
age: once a wallet's anchor is resolved and persisted, an interrupted first sync restarts
at the birthday rather than at the floor, so the all-or-nothing window shrinks to the
birthday-to-tip band regardless of how far the floor has receded. A **restored** wallet
with no `--birthday` still faces the long scan - its history may genuinely predate any
anchor - but a restore given an explicit height or date gets the same anchor treatment as
a generated wallet.

### A rejected header batch parks the node, so zecd redials from an older checkpoint

`bip157` keeps its header tree in memory and, on a batch it cannot accept, sends a
`Warning::UnexpectedSyncError`, bans the peer, and carries on with the tree it has. When
the rejection was the tree's own mistake that is a permanent stall: no `Update` ever
arrives, nothing on the update stream says why, and the wallet reports `Ready` at whatever
height it last applied. The mistake exists (2026-09-03, the testnet4 wallet, stuck 27
blocks behind on a hash the network had abandoned): `BlockTree::accept_header` requires a
header that extends a *fork* to carry the fork parent's `bits`. That is true between
mainnet retargets and false on every min-difficulty network, where the 20-minute rule
lets CPU miners produce `1d00ffff` blocks between ASIC blocks at the real target - so a
fork whose second header is ASIC-mined, the usual shape of a testnet4 reorg, is rejected as
`InvalidPow` and never reorged onto. Upstream master has the same code.

zecd handles it at its seam rather than patching the crate (`kyoto.rs`, module doc):

- The warning drain classifies the warning (`fatal_sync_warning`) and fails the update
  stream with `KyotoFailure::HeaderSync`. The actor treats that like a bitcoind transport
  failure - drop the connection, redial with backoff - and the redial builds a **fresh**
  tree from the wallet's checkpoint chain, whose tip carries no bits requirement, so the
  fork is accepted on the retry. The outage is honest while it lasts: `Down`, then
  `Syncing`, never `Ready`.
- bdk_kyoto's `ScanType::Sync` starts that tree 7 blocks back, enough for a shallow fork.
  A deeper one (testnet reorgs run tens of blocks) would restart *on* the stale branch and
  fail again, so the actor counts consecutive header-sync failures and escalates: from the
  second failure each redial is a `ScanType::Recovery` from an older checkpoint on the
  wallet's own chain (`resync_depth`: 16, 64, 256... blocks below the tip;
  `resync_checkpoint` picks the wallet's checkpoint at or below that height), bottoming
  out at the first-scan start - the recorded birthday anchor, else the shipped floor. A
  delivered update resets the count. The recovery scan watches the same script lookahead a
  first scan does, a superset of `Sync`'s, so the rescanned band cannot miss an address
  revealed since. **A reorg deeper than the anchor** is the one case the bottom does not
  cover: the anchor's own block has left the chain, so every redial from it fails (a peer
  answers a locator it does not know from genesis, and the batch does not connect). A
  redial that already bottomed out at the anchor and failed again marks it suspect
  (`resync_bottomed_at_anchor`; a checkpoint-less wallet gets two tries): the actor clears
  the recorded anchor (`Persister::clear_birthday_anchor`) and the next redial starts from
  the network's recovery floor - the shipped floor, or genesis where there is none - whose
  headers do sync; the wallet unwinds the dead blocks from the update, and the resolution
  task re-records an anchor against the new chain (a synced wallet without an anchor now
  resolves one on connect and records it without a restart). When the light client follows
  the fork by itself instead - an idle client handed the whole replacement chain at once -
  no redial fails, so after any update that reorged the wallet's tip the actor re-resolves
  the birthday against the light client's headers (`KyotoConn::re_resolve_anchor`) and
  re-records the anchor if it moved; the wallet's own chain cannot be asked, because BDK
  keeps a checkpoint below the lowest conflict a sparse update names. `regtest_btc_reorg_deep`
  pins it over both backends; over bitcoind the emitter finds no agreement point among
  the wallet's checkpoints and re-emits from the birthday on the new chain.

The `HeaderSync`/`Stream` split on `KyotoFailure` is deliberate: a node that merely stopped
or lost its peers redials at the same depth, so a flaky peer does not walk the restart point
down the chain. The fix that removes the workaround belongs upstream (2140-dev/kyoto).

## Witness data over kyoto

`bip157` requests blocks as `MSG_BLOCK` by default, which a peer serves witness-stripped
(BIP 144). Every received transaction would then reach the wallet without its witness:
`gettransaction.hex` incomplete, and a resubmission of it after a reorg - the recipient's
rebroadcast Core's rule calls for - rejected by every node for the missing witness.
`KyotoEndpoint::connect` asks for `MSG_WITNESS_BLOCK` (`fetch_witness_data`), at the cost
of the witness bytes on each block download. Found by `regtest_btc_reorg_deep`, whose
kyoto leg resubmits an orphaned *received* transaction and checks the wallet's hex against
the node's.

## Watching live reorgs on testnet4

Regtest pins the mechanics; testnet4 supplies the real thing, daily: CPU miners contest
min-difficulty tips, and `scripts/btc-miner.py` mines a lone block for every unconfirmed
wallet transaction - exactly the block a competing miner orphans. Two daemons watch the
same wallet over both backends: the bitcoind-backed one from `deploy/zecd.btc-testnet4.toml`
and a watch-only kyoto sibling from `deploy/zecd.btc-testnet4-view.toml`, built from the
spender's exported xpub and peered with the same compose node's filter-serving P2P port.
`scripts/btc-reorg-watch.py` polls the node (`getbestblockhash`, `getchaintips`) and each
wallet (`getwalletinfo`, its history) and logs one line per event: `REORG` when the node's
tip is replaced, `FORK` for a newly rejected branch, `WALLET` for each wallet's height and
hash against the node's, `TX MOVED` / `TX UNCONFIRMED` / `TX CONFIRMED` / `TX GONE` for a
wallet transaction whose block changed; `--send-every N` adds a small self-payment every N
minutes so most locally mined blocks carry a wallet transaction. A day of that log is the
live evidence the reorg suite cannot produce - the first entry came fifteen minutes in
(2026-09-10 17:22 UTC): the watcher's self-payment, mined by the local miner into 151812
together with a coinbase paying the wallet, was reorged out by a competing chain; both
backends re-anchored the payment in the new 151813 and dropped the orphaned coinbase
within 20 s, the kyoto side by way of the min-difficulty header error and a plain redial.

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

The cost of a page is the page, not the history: `listtransactions` positions
every transaction (chain position and visible-entry count, no fee or serialization), sorts,
and builds only the records inside Core's `count`/`skip` window, trimming a record at either
boundary to the entries within it (`actor.rs::tx_history`); `gettransaction` builds the one
transaction it names (`Wallet::get_tx`) and is the only reader that serializes hex;
`getwalletinfo.txcount` counts without building. `received_by_address` still walks every
transaction once per call, bounded by the revealed address set.

## Chain and fee reads, and the rest of Core's shapes

A Bitcoin wallet answers the chain and fee reads a Core client polls, from the wallet's own
state rather than a proxy of the node: `getblockchaininfo` (the wallet's checkpoint as
`blocks`/`headers`/`bestblockhash`, `chain` in Core's names - `test` for testnet3 - and
`initialblockdownload` while catching up; no `time`/`mediantime`, which the wallet does not
track), `getnetworkinfo` (the Zcash handler's shape, `connections` from the chain source),
`estimatesmartfee` (bitcoind's estimator at the requested target and mode; over kyoto the
`[fees]` chain a send prices from, which answers one horizon, so the target is echoed; a
`source` extension names who answered, and no estimate is Core's `errors` shape),
`getreceivedbyaddress`, and `listsinceblock` (everything above the cursor block plus
everything unconfirmed; a well-formed hash the wallet's chain does not hold reads as "from
the start" so a reorged cursor re-reads rather than wedging, the Zcash handler's rule).
`listunspent` carries `scriptPubKey` and Core's inferred `desc`
(`wpkh([fingerprint/84'/coin'/0'/keychain/index]pubkey)#checksum`) and takes
`query_options` (an unknown key is `-3`, never ignored); `getaddressinfo` adds `labels: []`,
`pubkey`, `desc`, `hdmasterfingerprint` and the script fields `validateaddress` now reports
too (`scriptPubKey`, `isscript`, `iswitness`, `witness_version`, `witness_program`, and
`error`/`error_locations` for an invalid address); `getwalletinfo` says `descriptors: true`;
and a malformed txid is `-8` on `gettransaction` as on `abandontransaction`.

## Rebroadcast of unconfirmed transactions

A transaction the wallet holds can drop out of the network's view while the wallet's own
state stays right. The shape that happens on its own is a reorg: BDK's `TxBuilder` sets
`nLockTime` to the tip height on every send (anti-fee-sniping, as Core's wallet does), so a
send built at tip 102 and mined at 103 is non-final if the chain reorgs back to 101 - and
Core does not hold non-final transactions across a reorg, `removeForReorg` drops them from
the mempool. The receive that shared the orphaned block goes straight back into the
mempool; the wallet's send vanishes from the node, while the wallet keeps it unconfirmed
with its inputs still spent. Until something resubmits it, the funds are in limbo.

The actor's `rebroadcast_pass` is that something. It runs after every sync pass that reaches
a tip the wallet has not rebroadcast at yet - once per new block and once per reconnect,
never on a timer (a peer keeps a rejected txid in its recent-rejects filter until the next
block, so a faster cadence would only spin) - and resubmits every canonical unconfirmed
wallet transaction, parents first. **Received payments included**, as Bitcoin Core's
`ResubmitWalletTransactions` does: a signed transaction that was broadcast is public data
anyone may relay, the sender has no veto short of double-spending it (which makes the
resubmission fail), and a recipient whose sender's wallet never rebroadcasts would
otherwise wait on them indefinitely. This is a deliberate divergence from the Zcash
rebroadcast loop, which retransmits only transactions spending the wallet's own notes.

The two backends differ here as they do elsewhere:

- **bitcoind** knows its mempool, so the pass skips anything the node already holds (the
  emitter's mempool pass fetches the whole set) and classifies each verdict. `-27` already
  in chain: nothing to do, the block is on its way. `-25` missing inputs, when no input
  waits on an **own unconfirmed parent**: a conflict spent the inputs and confirmed, the
  transaction can never confirm as things stand, so it is marked evicted - a send's inputs
  are freed, a dead receive stops counting toward the unconfirmed balance (BDK evictions
  are not final: a later block or mempool sighting re-canonicalizes the transaction).
  One case BDK cannot express on its own: a receive **whose own block reorged out**. BDK
  keeps a transaction whose anchor left the best chain canonical no matter what evictions
  it is given (`bdk_chain`'s leftover canonicalization path never consults
  `last_evicted`; `actor.rs::bdk_keeps_a_reorged_out_transaction_canonical_despite_evictions`
  pins it), and offers no way to drop an anchor from a live graph. So every eviction the
  actor applies - this verdict, the emitter's mempool report, `abandontransaction` - goes
  through `BtcActor::retire`: a tombstone in the engine database
  (`Persister::retire_tx`), and when any retired transaction holds an anchor, a reload of
  the wallet (`reload_wallet`, rebuilding the connection from the unchanged checkpoint),
  whose loader strips each retired transaction's out-of-chain anchors while merging the
  changeset log. The end state is BDK's own contract: no in-chain anchor, `last_evicted`
  past `last_seen`, not canonical - and a transaction that confirms after all gains an
  in-chain anchor the strip leaves alone. Over bitcoind this rarely has to fire for a
  reorged-out receive: the emitter applies every block, and BDK's block apply inserts any
  transaction that conflicts with one the graph holds (`is_tx_or_conflict_relevant`), so
  the confirmed conflict enters the graph and canonicalization retires the orphan on its
  own; the tombstone path covers what the node evicts for other reasons.
  The reorg suite funds the orphan from an output the wallet never held and
  asserts the retirement over both backends. The
  same text on a child of an own unconfirmed send is a dependency, not a conflict, and just
  waits for the parent. Everything else retries at the next tip: `non-final` (the reorg case, which
  clears by itself when the locktime height arrives) quietly, any other policy rejection
  with one WARN then DEBUG on repeats.
- **kyoto** has no mempool and no verdicts (peers stopped sending `reject` with BIP 61's
  removal). Its one piece of evidence that a reorged-out receive was double-spent is
  time: a receive is only ever unconfirmed on this backend because a reorg unwound it, a
  valid one is re-mined within a block or two, a conflicted one never is - and the
  conflict itself, spending the sender's outputs to pay someone else, touches no wallet
  script, so the light client never fetches its block. So a once-confirmed received
  transaction still unconfirmed after the network's reorg depth of tips
  (`kyoto::anchor_reorg_margin`: 6 on mainnet and regtest, 100 on the testnets) is
  retired (`expire_reorged_receives`). Own sends are exempt - their inputs are wallet
  scripts, so a conflict spending them is filter-visible and BDK retires them directly -
  and so is anything the wallet only ever saw unconfirmed (no anchor: BDK's own
  seen-versus-evicted accounting applies). Every unconfirmed send is re-announced at each
  new tip on a detached task:
  a peer that already holds the transaction never asks for it, and the light client's
  broadcast timeout must not hold the actor. The pass reads the mempool question three
  ways - known held, known absent, unknown - so a kyoto mempool view (below) narrows the
  candidate set without the pass changing shape. Unconfirmed receives are rare there in
  the first place (no mempool means a payment is first seen in a block), so the set is
  own sends plus whatever a reorg unconfirmed. Note that a light client follows work,
  not an operator's `invalidateblock`: it reorgs only once the replacement chain outgrows
  the old one, so its resubmission comes later than bitcoind's after the same reorg
  (`regtest_btc_reorg.rs` pins both timings).

The pass also covers a kyoto broadcast no peer answered in time, because the send records
it (see the broadcast-timeout paragraph below), and `abandontransaction` is the release
valve for a recorded transaction that never relays: Core's shape and codes, applied to the
transaction and its unconfirmed descendants as an eviction, which frees their inputs for
the next send. Core refuses to abandon a transaction that is in the mempool; over bitcoind
the last pass's mempool set enforces that, over kyoto nothing can, so the operator is
trusted. Over kyoto the abandonment also **restarts the light client**: `bip157`'s
in-memory broadcast queue holds the signed bytes and re-announces them to every peer that
completes a handshake, with no API to forget one, so the operator's own client would
otherwise keep pushing the transaction it was just told to drop. A new node has an empty
queue; the redial is immediate and resumes from the wallet's checkpoint. For that to hold,
each kyoto node runs on a `tokio` runtime the connection owns and shuts down with it -
`bip157`'s own `shutdown()` only returns from the node loop, and the per-peer tasks it
spawned would otherwise keep their sockets and their handle on the broadcast queue, serving
the abandoned transaction to the next `getdata` (seen live before the runtime teardown). What remains is
the risk Core documents for its own `abandontransaction`: a peer that already received the
bytes may relay them, and if the transaction confirms after all the block re-canonicalizes
it (an eviction is not final).

## Commit, then relay

A send is recorded before it is relayed (`actor.rs::commit_before_relay`, then
`relay_committed`): the signed transaction is applied at 0-conf and **persisted** before a
byte of it goes to the upstream. It used to be the other way round - relay, then apply and
persist - which left a window where a crash between the two produced a wallet that did not
know its own send: the inputs looked unspent, the next send double-spent them, and over
kyoto nothing ever closed it (bitcoind's mempool pass at reconnect rediscovers an own send;
a filter client has no such pass). Bitcoin Core's `CommitTransaction` has the same order for
the same reason. The record then follows the relay's verdict:

- **Relayed**, or **queued** by the kyoto light client: the record stands; the txid is the
  answer.
- **Rejected** by the node (bitcoind only - kyoto has no verdicts): the node's own code and
  message pass through, exactly as before, and the verdict is read the way the rebroadcast
  pass reads it (`classify_rejection` over the transaction's `Parents`) before the record is
  touched. A transaction the wallet funded - every own send, and a caller-built spend of
  wallet outputs - is withdrawn through `retire` (an eviction plus its tombstone, in one
  database transaction): the same bytes can never be accepted, so its inputs are free for a
  differently built send. Two verdicts leave the record standing: `-27` already-in-chain,
  which only says the scan is behind the block (a payment to this wallet mined before its
  scan reached it), and any verdict on a transaction with foreign parents (a received
  payment relayed on the sender's behalf), which proves nothing about it - it propagates on
  its own, and the scan re-sights or retires it.
- **No verdict** (a transport failure - the node hung up, the light client stopped): the
  bytes may or may not have reached the network, and only the record can tell the wallet's
  next send that the inputs are spoken for, so it **stands** and the txid is returned with a
  WARN. That is Core's posture too (it logs the failed relay and keeps the transaction for
  its resubmission loop); here the rebroadcast pass resubmits it at the next tip or
  reconnect, and `abandontransaction` releases the inputs if it never relays. A bitcoind
  connection is dropped for redial as before - and the record survives the redial: the
  emitter is seeded with the wallet's unconfirmed set, so the first mempool pass reports a
  never-relayed send as "evicted", and the mempool pass **never retires a transaction the
  wallet funded** on that report (it used to, freeing the inputs for a double-spend of a
  transaction that may be on the network). Core keeps an own transaction that left the
  mempool until a conflict confirms or the operator abandons it; so does zecd. The `-4` "retry" error is now reserved for a
  send refused *before* anything is committed - no upstream connection, no seed, a persist
  failure - and for the relay of a foreign transaction via `sendrawtransaction`, which the
  wallet has nothing to commit for.
- A **persist failure** before the relay withdraws the sighting in memory (an eviction
  stamped at the sighting's own second - BDK keeps a transaction canonical only while
  `last_evicted < last_seen`, pinned by
  `actor.rs::an_eviction_at_the_sighting_timestamp_withdraws_the_record`) and answers `-4`
  naming the cause; nothing was broadcast, so the inputs really are free.

`sendrawtransaction` differs from a send in its answer, not its record: it returns the
txid only once the bytes were relayed, as Core never returns one without mempool
acceptance. A kyoto announcement no peer requested, or a bitcoind broadcast with no
verdict, is `-25` naming what became of the transaction - recorded and rebroadcast when it
is the wallet's, and for a foreign one (nothing records it) the light client is restarted
so its queue does not announce it later behind the error (`restart_light_client`, shared
with `abandontransaction`). `sendrawtransaction` takes the send's commit path when the hex
is a wallet transaction the wallet does not hold **canonical**; one it does (a resubmission of an own send or a received
payment) is relayed as is with the verdict reported verbatim, since a `-27` on a confirmed
transaction must not evict it. The gate is the canonical view, not the raw graph: an
abandoned or retired transaction is still in the graph, and resubmitting its bytes must
re-canonicalize the record before the relay (a sighting stamped strictly past the
eviction - `commit_before_relay` stamps at least `last_evicted + 1`, since the clock's
second granularity makes "later" a floor rather than a given), or the node would hold a
transaction whose inputs the wallet still counts as free. Every withdrawal stamps its
eviction no earlier than the sighting it withdraws (`seen_at.max(now)`), because
`SystemTime` can step backwards between the two reads.

Live coverage is `regtest_btc_send_outcomes.rs` (the `btc-e2e` job), over the bitcoind
backend: a send the node refuses (`-minrelaytxfee` above the send's rate) leaves balance,
UTXO set and history untouched; a send whose broadcast dies without a verdict (the
harness's `RpcProxy` drops exactly the `sendrawtransaction` request, so the sync pass and
the redial keep working) returns its txid recorded, locks its input against a retry, and is
resubmitted by the rebroadcast pass once the path clears; and an abandoned unrelayed send
resubmitted through `sendrawtransaction` is recorded again even while the path is down
(answering `-25`), and relayed once it clears.

## Send pricing and fee subtraction (Core's optional send parameters)

`sendtoaddress`/`sendmany` honor Core's optional fee parameters, at Core's positions (which
differ between the two methods, as in Core):

- **`fee_rate`** (sat/vB, Core's 3-decimal precision - `amount.rs::value_to_sat_per_kvb`)
  prices the send verbatim, with no estimation dial at all. On the kyoto backend this is
  the one way to price a send without trusting either an HTTP fee oracle or the peers'
  coarse signals. Bounded on both sides: a rate under the 1 sat/vB relay floor is refused up
  front like Core's `minrelaytxfee` check (under the floor no node relays the result, and
  over kyoto the unminable transaction would still be recorded at 0-conf, locking its
  inputs), and an explicit rate still passes the shared sanity ceiling at the `do_send`
  chokepoint - a fat-fingered 100000 sat/vB burns funds exactly like a dishonest signal.
- **`conf_target`** / **`estimate_mode`** are **refused** when engaged (the wallet
  estimates at one fixed target and cannot honor them; silently ignoring a named target
  would mischarge) - which also covers Core's own `-8` for combining either with
  `fee_rate`.
- **`subtractfeefromamount`** / **`subtractfeefrom`**: the listed recipients pay the fee
  out of their own amounts (fee / n each, the first paying recipient in recipient order
  covering the remainder - Core's split keys on output order, not the array's order;
  `actor.rs::subtract_fee_from_amounts`), so the sender is debited exactly
  the stated total and "send the whole balance" works. BDK's `TxBuilder` has no
  subtract-fee mode, so `build_subtract_fee_psbt` converges on one: a zero-fee build picks
  the inputs (selection must target the amounts alone - the defining property of a
  subtract-fee send), then rate-priced rebuilds over those pinned inputs walk the fee to a
  fixed point, accepting a changeless build whose fee overshoots by at most a dust bound
  (the no-fixed-point shape where BDK folds a sub-dust surplus into the fee, as Core
  does).
- **`verbose`** (position 10 on `sendtoaddress`, 9 on `sendmany`) answers Core's
  `{txid, fee_reason}`: Core's own strings where zecd prices the same way (`PayTxFee set`
  for an explicit `fee_rate`, `Fallback fee` for the test-network floor), else the source
  that answered (`estimatesmartfee`, or the `[fees]` tier name on kyoto) - Core's
  estimator-horizon strings describe a computation zecd does not do.
- **`replaceable`** (position 5 on both) is honored, not ignored: omitted or `true` keeps
  BDK's BIP 125-signalling default (Core's `-walletrbf` default); `false` builds every input
  with `nSequence = 0xFFFFFFFE`, locktime still enforced for anti-fee-sniping, and
  `bip125-replaceable` reads back `"no"`.

Two refusals bound every send before a signer exists, whatever priced it:

- **The recipients' total** may not exceed the 21M BTC supply cap (`-3`, Core's "Invalid
  amount"). Each amount is range-checked at the RPC boundary, but BDK sums the recipients
  with `Amount`'s panicking `+`, so an unbounded `sendmany` total used to kill the actor.
  Recipients are validated before the fee lookup, so a bad address costs no oracle round
  trip and answers the same `-5` offline as online.
- **The absolute fee** may not exceed `[fees] max_tx_fee_sat` (default 10,000,000 sat =
  0.1 BTC, Core's `-maxtxfee` default), with Core's message and code (`-6`, as Core's
  `SendMoney` surfaces every `CreateTransaction` failure). The rate ceiling bounds sat/vB;
  a large consolidation at a sane rate can still carry a surprising total, and this is the
  number the operator pays. Both backends, estimated and explicit rates alike.

### Fee bumping (`bumpfee`)

`bumpfee "txid" ( options )` replaces an unconfirmed own send with a higher-fee version of
itself (BIP 125), in Core's shape (`{txid, origfee, fee, errors}`) and with Core's
precondition codes, checked in Core's order: a txid the wallet does not hold is `-5`; a
mined one, or one conflicted with a mined one, `-4`; one already replaced `-4` naming the
replacement; one with an unconfirmed wallet descendant `-8` (replacing it would evict the
child); one that does not signal BIP 125 `-4`; one spending a foreign input `-4` (there is
no signer for it). A watch-only wallet is `-4` - there is no `psbtbumpfee`.

The replacement is BDK's `build_fee_bump`: every original input and recipient output kept,
the change output dropped and coin selection re-run, taking more (confirmed) inputs only
when the change cannot absorb the higher fee. The rate is the caller's `fee_rate`, else
Core's default (`feebumper.cpp`'s `EstimateFeeRate`): the original's rate rounded up, plus
1 sat/kvB, plus the wallet's 5 sat/vB incremental relay fee - or the upstream's estimate
when that is higher. An unavailable estimate is not an error here, since the increment
alone is a well-defined bump. Both BIP 125 fee rules hold: BDK enforces the rate (at least
1 sat/vB above the original, `-8` otherwise), and zecd the total (the original's fee plus
1 sat/vB of the replacement's own signed size) - a replacement that sheds its change output
can clear the first and fail the second, so a default bump is rebuilt once at the rate that
clears it and an explicit rate is refused with Core's `-8` "Insufficient total fee". The
sanity ceiling and `[fees] max_tx_fee_sat` apply as on every send (the cap answers `-4`
here, as Core's `bumpfee` does).

Then the send path: per-call signers, commit before relay, and the relay's outcome settles
the record. The replacement's sighting is stamped strictly after the original's, because
BDK resolves two conflicting unconfirmed transactions by the later sighting and breaks a
tie by txid - a bump in the same second as its send would otherwise lose half the time.
The original stays in the wallet's graph, non-canonical: if the node rejects the
replacement it is retired and the original is canonical again, and if the original
confirms after all (over kyoto, a peer that never took the replacement) its block
re-canonicalizes it. `replaceable = false` makes the replacement non-signalling, so it
cannot be bumped again. `conf_target`, `estimate_mode`, `outputs` and
`original_change_index` are refused rather than ignored, and an unknown option key is
Core's `-3`. Live: `regtest_btc_bumpfee.rs`, both backends.

## Not yet implemented

Everything here is refused with a clear error rather than silently ignored or half-done:

- **`walletpassphrase`** - there is no unlock for a bitcoin wallet, so `zecd init --encrypt`
  refuses a seed-holding one (it could never send or be rebuilt by `rescan`); the seed is
  decrypted only by the identity-file custody model at startup. A wallet encrypted before
  that refusal existed still starts locked and cannot send, and says so: `encrypted` and
  `locked` on `/status`, `unlocked_until: 0` on `getwalletinfo`.
- **Address types other than bech32** (BIP 84 is the engine's only derivation): issuance is
  bech32-only, and a restore of a seed whose history lives on BIP 44/49/86 derivations will
  not see those funds. Additional descriptor templates are the fix, once wanted.
- **CPFP of an incoming payment** and **`psbtbumpfee`**. Ancestor-aware funding
  (`ancestors.rs`, Core 26's behaviour) covers the wallet's own chains: any send that
  spends an unconfirmed own output pays what its unconfirmed ancestry lacks at the send's
  rate, so a cheap send - replaceable or not - is unstuck by the next send that spends its
  change. What remains is an incoming payment stuck at a low rate: the wallet cannot price
  a stranger's parents (over kyoto it never sees them), so an unconfirmed receive is never
  selected, as Core's default refuses untrusted outputs. Doing that needs Core's
  `send`-with-`inputs` coin control plus a parent-fee source (the node's
  `getmempoolentry` over bitcoind; over kyoto only the mempool.space feed carries prevout
  values). Over kyoto a child is announced like any send; a parent under the peers' relay
  floor needs package relay, which bip157's broadcast does not do. `psbtbumpfee` (the watch-only half of Core's pair) waits on the
  wallet's PSBT surface. The history RPCs also omit Core's `walletconflicts`/
  `replaced_by_txid`: a replaced transaction simply leaves the wallet's canonical view.
- **A mempool for the kyoto backend** - the `[mempool]` feed covers it since
  2026-09-10 (`mempool_feed.rs` + `p2p_feed.rs`), from either of two sources
  named in `sources` (a preference order; the first that can run for the wallet wins),
  defaulting to `["p2p"]` - the source that peers with the node the wallet already syncs
  from.
  BIP-158 filters cover blocks only, so
  without it an incoming payment is invisible until it confirms and `getbalances`'
  `untrusted_pending` stays empty; nothing in BIP-157 fixes that.
  **`"p2p"` (2026-09-11)** is zecd's own relay connection to one node over the Bitcoin
  P2P protocol - by default the wallet's `kyoto://<ip>:<port>` trusted peer,
  `p2p_peer = "<ip>:<port>"` overriding it (a DNS-seeded wallet with no override runs no
  P2P feed): a minimal client of our own (version handshake announcing `relay = true` at
  protocol 70015, below wtxid relay, so announcements come by txid; `inv` -> `getdata` by
  witness txid, in batches of 1000; `tx`; `ping`/`pong`; unknown messages ignored) that
  requests **every** announced transaction and hands each to the actor, which matches it
  locally - outputs by `is_mine`, inputs by outpoints the wallet holds (the wire carries no
  prevout scripts). The node learns "a wallet at this IP wants relay", what any full-node
  peer tells it, and relays everything to every such peer, so it cannot tell which
  transactions matter; bandwidth is raw transaction size, roughly 150-300 MB a day on
  mainnet, negligible on testnet4. `p2p_snapshot = true` adds BIP 35 `mempool` requests at
  connect and every 5 minutes: the node answers with an `inv` of its whole mempool, fetched
  like any announcement (closing the pre-connect blind spot) and reported as a snapshot the
  actor diffs against what the feed had reported held - the P2P source's only eviction
  signal, since Core never announces one. It is opt-in because Core answers `mempool` only
  for a peer with the `mempool` permission (`-whitelist=mempool@<wallet host>` on the node)
  or with `-peerbloomfilters`, and **disconnects** an unpermissioned peer that asks. Why a
  client of our own: `bip157` sends `relay: false` and drops transaction inventory, and its
  maintainer closed the request to expose relay (2140-dev/kyoto#220) suggesting a side-car;
  this is that side-car, on a connection of its own beside kyoto's.
  **With snapshots on, kyoto sends wait for the mempool view** (`-4` until
  `getwalletinfo.mempool_feed.snapshot_applied`, re-armed on every feed redial). The case
  it exists for is a wallet started with no history - an empty datadir, a `rescan`, an
  enclave whose rootfs is RAM: a filter client learns of its own earlier unconfirmed sends
  only once they are mined, so their inputs look unspent and the next send could
  double-spend them. The snapshot at connect cannot help, since its transactions were
  matched against a wallet that did not yet hold the outputs they spend; so once that
  wallet reaches tip it asks for a **full** snapshot (the connection forgets what it
  already fetched and re-requests BIP 35), and only that one opens sends. A snapshot is
  delivered only once every transaction it fetched has arrived or drawn a `notfound`, so
  each was matched first. Without a snapshot-taking feed nothing is blocked - the actor
  warns at start, loudly for a wallet with no history.
  **`"mempool_space"`**: the wallet holds one long-lived websocket to a
  mempool.space instance (`wss://mempool.space/api/v1/ws`, per-network paths like
  `/testnet4/api/v1/ws`, no key; `mempool_space_url` overrides it, `ws://` allowed for a
  self-hosted instance on the same terms as the `[fees]` overrides) subscribed with
  `{"track-mempool": true}`, and reads its `mempool-transactions` deltas -
  `{sequence, added, removed, replaced, mined}`, every `added` entry a full Esplora-shape
  transaction. Everything is matched **locally**: a bridge task owns the socket (the kyoto
  update-bridge shape, since the read is not cancel-safe) and feeds a channel the actor
  drains; each added transaction is rebuilt into a `bitcoin::Transaction` and its txid
  **checked against the reported one** (a reconstruction that does not round-trip is
  dropped and counted, never applied), `is_mine` runs over outputs and over the inputs'
  `prevout` scripts, and a match is applied with `apply_unconfirmed_txs` - so a payment
  shows in `untrusted_pending`, `listtransactions` and `listunspent 0` before its block,
  and the filter scan anchors it later without duplication. A `removed` txid the wallet
  holds unconfirmed is evicted with `apply_evicted_txs` (BDK evictions are not final; a
  later sighting re-canonicalizes) - **settled at the next scan tip rather than on
  arrival**, because the server also drops a transaction when a block mines it and the scan
  can trail that by a minute; a genuinely evicted transaction is retired within a block. A
  transaction the feed reports held is skipped by the rebroadcast pass, the way the
  bitcoind pass skips what that node holds. No address and no txid of interest ever leaves
  the wallet; what the server learns is that a wallet is online at this IP for as long as
  the socket lives, strictly less than any per-address backend and removable outright with
  a self-hosted instance. Trust is the existing 0-conf posture: the oracle's mempool is not
  our peers' and could lie, and a lie only moves `untrusted_pending`, never confirmed
  state. **Deltas only**: there is no snapshot on subscribe, so whatever is already in the
  mempool at connect is invisible until it confirms - a blind spot the scan closes within a
  block or two, and the reason a reconnect needs no catch-up. **Off by default** because of
  the cost: 2 to 20 KB of JSON per transaction, several GB a day at mainnet ingress
  (negligible on testnet4), plus the always-on connection; kyoto only (`config check` warns
  when the section is set on a bitcoind wallet, which has a real mempool, or named on a
  network with no instance and no override); the feed dials directly, not through
  `[backend] proxy`, like the fee oracles. State on `getwalletinfo.mempool_feed`
  (`disabled` / `connecting` / `connected`, the endpoint, last delta time, delta / matched /
  dropped counters). Coverage: `mempool_feed.rs` (parse + reconstruction + txid check +
  relevance, the websocket path end to end against an in-process fake feed, and the P2P
  path end to end against an in-process fake node - handshake, announcement, ping, mempool
  snapshot, close and redial), `p2p_feed.rs` (frame codec, version, announcement filter),
  the config parse/check/show tests, the `#[ignore]`d live shape test
  `the_public_feed_still_answers_in_the_shape_we_parse`, and for the P2P source a live
  regtest suite, `regtest_btc_p2p_mempool.rs` (a Core run with
  `-whitelist=mempool@127.0.0.1` and `p2p_snapshot_interval_secs = 10`: the feed connects
  on the node's P2P port, a relayed payment shows at 0-conf and confirms without a second
  history entry, a `bumpfee` replacement supersedes its original, and a receive
  double-spent away from the wallet - which relay never shows it - is evicted by the
  snapshot at the next scan tip). `p2p_snapshot_interval_secs` (default 300, minimum 5)
  bounds how stale a P2P eviction can be, at one whole-mempool `inv` from the node per
  request. The websocket source has no regtest suite (regtest has no mempool.space). The
  rest of the P2P design in `TODO.md` - broadcasting
  on a separate connection so a send never goes through the server, a local fee estimate
  built from the relay stream, Tor for the broadcast hop - is not built.
- **`[rpc] bind` is one address.** A host that must serve both loopback clients and a
  container across the docker bridge has to choose `0.0.0.0` (every interface, wrong on a
  public host) or the bridge gateway alone and repoint every local client (`--zecd-url`,
  `curl`). A list of bind addresses would remove the choice; daemon-wide, not engine-specific,
  noted here because the kyoto/UI deployments are where it bites.
- **Health/readiness** - covered since 2026-09-10: `/readyz` counts every Bitcoin wallet
  (ready iff its actor is alive and `conn_state` is `ready`, i.e. the chain source reported
  the tip; `connected` mode accepts `syncing`), `/status` lists each with `coin`, `server`,
  `conn_state` and `synced_height`. The engine measures no lag against a tip it has not
  reached, so `max_scan_lag` does not apply and there is no `scan_lag` field. Per wallet,
  `getwalletinfo` carries the same connection state as the zecd extension
  `upstream_connected` (false once a hung or unreachable upstream is noticed - the bitcoind
  client's per-request deadline is `chain::RPC_DEADLINE`, 15s - true again after a
  reconnect), the wallet birthday and how it resolved (`birthday.height`, its `time` - the
  birthday block's own time once the chain source answers, else the offline record - and
  the scan `anchor` once recorded), and `listdescriptors.timestamp` carries the same time
  as Core's rescan-from time.
- **`derive-address`** derives BIP 84 receiving addresses offline (`btc/derive.rs`),
  from the wallet's own public key material, `--mnemonic`, or `--xpub`; an index
  past the wallet's `lookahead` is derived with a warning. `export-ufvk` refuses a bitcoin
  wallet, pointing at `export-xpub`. (`rescan` covers bitcoin wallets since 2026-09-05: it deletes
  the BDK database and the kyoto cache, the next spawn rebuilds from the seed or the pinned
  xpub, and `--birthday` moves the recorded birthday first; a passphrase-encrypted bitcoin
  wallet is refused, since nothing could decrypt its seed to rebuild.)

Deliberate posture, not a gap: the fee fallback (1 sat/vB on test networks, hard refusal on
mainnet when the upstream has no answer) mirrors bitcoind's own `fallbackfee` defaults. On
the kyoto backend "the upstream" is the configurable chain in `[fees] sources`
(`btc/fees.rs`): **mempool.space**, then a **Blockstream-style Esplora**, then the light
client's own relay floor and an **estimate from recent blocks' fee averages** (each
anchored to a coinbase the merkle root of a PoW-validated header commits to, so a peer
cannot inflate one without mining): a recency-weighted quantile per confirmation target
over a ring of up to 24 blocks, blended toward the relay floor unless recent blocks were
full (`fee_samples.rs`). A background sampler keeps the ring warm once a wallet starts
pricing sends, so a send no longer downloads blocks, and an HTTP oracle's answer far above
what those blocks paid is disbelieved and falls through to the next tier. Two HTTP oracles rather than
one because they are run by different operators and compute their numbers differently -
mempool.space projects blocks from its own mempool view, Esplora reports a node's
`estimatesmartfee` - so one being down no longer drops the send straight to the peers'
signals. The estimate's character does change when the fallback engages, which is the
accepted cost of having one.

That chain **always produces a number** while it ends in `peer_median`, so the mainnet
refusal is a bitcoind-backend rule in practice: the relay floor bottoms out at
`FeeRate::BROADCAST_MIN` (1 sat/vB) when no peer has sent a `feefilter`, and subsidy-only
blocks average zero. A kyoto send therefore prices rather than refuses, and with both
oracles unreachable in a busy fee market that price can be low enough that the transaction
sits unconfirmed, holding its inputs locked at 0-conf behind it. That is the accepted trade
- guessing beats refusing to spend - and the explicit per-send `fee_rate` argument (above)
is the override. An operator who prefers the opposite trade drops `peer_median` from
`sources`, which restores the refusal.

Those HTTP lookups are the only time a kyoto wallet contacts a server: they happen only
while building a send and carry no wallet data. Both endpoints are overridable
(`[fees] mempool_space_url` / `esplora_url`), which is the real answer to that disclosure -
pointed at instances the operator runs, the fee lookup reaches infrastructure they control,
the same posture `kyoto://<peer>` gives block data. It is also how a tier reaches a network
the public instances do not serve: Blockstream runs **no testnet4 Esplora**, so on the
network the dev stack targets that tier is skipped unless an override names one (`zecd
config check` reports it rather than leaving the chain quietly shorter than it reads).
`sources = ["peer_median"]` is the no-server posture outright. **Every rate from every
source** - the caller's `fee_rate`, `estimatesmartfee`, either HTTP oracle, the kyoto
signals - passes one shared sanity ceiling at
the `do_send` chokepoint (`fees::enforce_sanity_ceiling`, 2000 sat/vB), so a dishonest signal or a
broken oracle becomes a refusal naming the number, never a payment. The ceiling is the
backstop; the peers' feefilter has a tighter bound of its own. `bip157` reports only the
**maximum** filter across connected peers, so on a DNS-seeded wallet one stranger's free
claim could otherwise price every send at the ceiling. The filter may therefore lift the
estimate to at most the greater of 10 sat/vB and twice the block-derived estimate - 10 sat/vB
alone when no block could be read (`kyoto.rs::combine_fee_signals`). The 10 sat/vB bound also
keeps fee-less blocks (regtest, a quiet testnet) from capping the relay floor to nothing. A send that undershoots one peer's inflated filter still propagates through any honest
peer, which is all relay needs.

Both fallback signals - the peers' BIP-133 feefilter and the tip-block average - are
peer-supplied, which is the strongest reason to name a **trusted peer you control**
(`server = "kyoto://<your node>:8333"`, e.g. the node
`deploy/docker-compose.btc-mainnet.yml` runs with `-peerblockfilters`). Naming any peer
makes the light client whitelist-only, so every signal in that threat model then comes from
your own node: the feefilter is your node's actual mempool policy (genuinely informative in
a busy market, not an adversarial claim), the block behind the fee average is served by a
node you run, and the eclipse concern collapses along with the dishonest-peer one.
DNS-seeded discovery stays the zero-config default for anonymous peers, where a sanity
ceiling is what bounds a dishonest answer.

Two kyoto requests on the send path carry timeouts of their own, because the underlying
`bip157` calls have none and the actor services commands one at a time - an unbounded wait
would wedge every other command for that wallet, and the shutdown flush with them:

- **Broadcast (30s).** `submit_package` resolves only when a peer sends a `getdata` for the
  announced txid; with no connected peer, nothing resolves it. On timeout the send is
  **recorded at 0-conf anyway and returns its txid**, with a WARN: kyoto keeps the
  transaction queued and announces it to every peer that connects from then on, and the
  actor's rebroadcast pass re-announces it at each new tip, so it may well still relay -
  and a wallet that had dropped it could then double-spend the same inputs on a retry,
  which is the unrecoverable outcome. Recording it makes the failure mode the recoverable
  one instead: the inputs stay locked until the transaction confirms or the operator
  releases them with `abandontransaction`. That is Core's order of operations (commit,
  then relay), and it is the order every send takes now - see "Commit, then relay"
  below - so a transport failure (the light client itself having stopped) keeps the
  record too, for the same reason.
- **Recent blocks for the fee estimate (10s).** Only on a cold ring (the background sampler
  keeps it warm after the first estimate); falls back to the peers' relay floor alone, which
  is the same degradation path an outright fetch error takes.
