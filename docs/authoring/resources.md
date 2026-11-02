# Author resources and actions

A Surface owns browser UI/document state; Resources expose scoped data and host
services; Actions declare public operations; Tasks use the existing Execution/Event
lifecycle. Internal functions stay ordinary code. Workers are optional, for
backend execution or independently authorized background lifetimes.

## Declare once, grant separately

Declare Surface storage in surfaces[].web.storage, settings in
surfaces[].web.settings, and connectors in surfaces[].web.network.
Storage/settings require surface.resources.v1; WebSocket also requires
net.websocket.v1, network permission and connection approval. The Host derives
authority from the authenticated Surface, owner, active fingerprint, management
revision, revoke epoch and session. A Surface cannot borrow Worker declarations.
Verified summaries and inventory project these signed ceilings.

The SDK describePluginResources reports declarations, session read/write limits
and budgets, not grants or adapter availability. Control requests are 96 KiB,
values 64 KiB, pages 100 entries, transactions 64 statements. Operations have a
5 second bound, watches 25 seconds, file transfers 5 minutes, live resources 16
per Surface and 256 per Host, WebSocket messages 1 MiB. Expiry may shorten them.

## Private data without a forwarding Worker

Import pluginKV, pluginDatabase, pluginFiles and pluginSettings from the plugin
entrypoint. They use the production same-origin handler and existing Host brokers.

- KV supports read/put/delete/list, atomic batches of 64 changes and snapshot
  watches. Empty expected ETag means create only. ETags identify bytes, not
  monotonic revisions: equal content permits ABA. Keep application revisions
  explicitly when needed.
- SQLite supports parameterized query/exec and bounded atomic transaction batches.
  Transactions cannot hold locks across browser awaits or include files, remote
  services or another database. Unsafe JavaScript integers fail.
- Settings get/patch/watch retain existing revisions and redacted secret metadata.
  There is no arbitrary secret-read API.
- File read/write cover small byte arrays; readable/writeFrom use binary streams
  and browser Blobs without per-chunk Base64 RPC. Selected-file handles also
  support streaming under their exact approved authority.

Watches return coalesced complete snapshots with bounded long polling and a
one-second observation interval. They are not a change log and may omit
intermediate writes. Abort/iterator close releases reservations. Closing one
Surface never revokes a sibling.

## Writes, streams and durable data

Errors preserve not_committed, committed or unknown. Unknown writes never
replay automatically. KV conflicts keep drafts. Private uploads stage to disk
then atomically replace the file after authorization/generation checks. Failure
preserves the old file. Selected-file writes may partially persist and report
unknown explicitly.

Downloads stage a consistent snapshot before streaming, avoiding a namespace
lock during slow clients. Staging shares a per-owner namespace budget of twice
its quota. Chunks are 64 KiB. This adds disk IO: it is bounded streaming, not
zero-copy. Cumulative allocations are not peak live memory. Broker benchmarks
measure storage throughput, not end-to-end latency or universal overhead.

Private files namespace schema 2 adds chunks and automatically migrates the exact
released schema 1 transactionally. Crash recovery/idempotent reopen preserve data;
retained snapshots are validated read-only without changing their bytes. KV and
control schemas stay unchanged. Hosts never manipulate this layout.

## Actions, tasks and Worker extensions

Generated createActions selects sync/operation/subscription from the manifest;
registerAction binds Surface handlers. Existing execution observation does not
restart work. Execution cancellation and event cursors remain authoritative.
Surface methods target the exact live app; application code owns revision/undo.

The Rust Worker SDK adds conditional KV, cursor pages and bounded SQL transactions
under storage.transactions.v1. Host admission rejects extended request fields
without that declaration. Earlier request/response shapes stay unchanged. Atomic
KV batch currently belongs to the Surface API. ABI and runtime wire do not change.

## Real-time connections

The SDK openPluginWebSocket resolves the approved connector through the Host.
The browser connects to its authenticated Surface origin; the platform relays
native messages to the exact authorized endpoint. Discovery requires Fetch
Metadata. Upgrade permits browsers that omit it but always requires exact Origin
and the bound session cookie. No wildcard origin or ambient credentials are used.

Receive buffers are bounded to 32 messages and 1 MiB. The SDK implements
cancellation, explicit close and send backpressure, never reconnecting or
replaying automatically. Applications request fresh snapshots or resume their
own protocol after overflow. A missing optional resource does not disable
unrelated UI or private data.

## Reference applications

The data editor demonstrates independent windows, snapshots, CAS saves, retained
conflicted drafts, explicit reload, revision-checked AI edits and undo. The monitor
uses full-snapshot messages, explicit reconnect and retained last state. The files
app demonstrates sequential imports, progress/cancel and per-file outcomes;
verification checks byte counts, not hashes. Its task lifetime is the page. Use
an authorized Worker operation for work that must outlive the page.
