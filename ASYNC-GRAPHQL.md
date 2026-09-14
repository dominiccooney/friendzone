# Async GraphQL and the Cline plugin

Rerun the guest script from **Settings → Guests → Set up guest**, then restart
guest Cline. Setup installs `friendzone.js` in `${CLINE_DIR:-~/.cline}/plugins`
and writes the broker origin/guest name to `friendzone.json` beside that folder.
The plugin is self-contained: no npm dependencies, no guest fz binary. Other
plugins are untouched; an unmanaged file with the same name is a setup error.
Managed files receive first-update backups. Removing those two files disables
the integration after restarting Cline; it does not cancel submitted jobs.

## Tools

- `friendzone_submit_graphql`: `request_key`, `query`, `variables`, optional
  `operation_name`. Returns a request ID immediately, not after human approval.
- For large content, pass an **absolute guest `request_file` path** instead of
  inline GraphQL. File shape: `{"query":"…","variables":{},"operationName":null}`.
- `friendzone_get_request`: status, HTTP status, and the upstream response string.
  Large results return a preview plus an absolute guest result-file path.
- `friendzone_list_requests`: outstanding and completed requests for this session.
- `friendzone_cancel_request`: cancels pending/queued work, not a running mutation.
- `friendzone_remove_result`: removes a finished job and releases storage. It
  does not undo anything upstream.

`request_key` is a non-unique, human-readable correlation label. **Every submit
call creates a fresh job and a fresh approval**, even for identical content/key.
This permits explicit retries but cannot make them safe. If submission times out,
list existing jobs before retrying; a retry may create a duplicate upstream
effect. Client disconnects after acceptance do not cancel jobs. Unknown mutations retain full
GraphQL input coverage: the broker does not need a new tool for each mutation.

Queries classified by the existing parser execute without approval. Mutations
and unclassified inputs require **Approve once** in the existing Inbox. Saved
ordinary-comment permissions currently apply only to the proxy path, not jobs.
The broker uses exactly one configured GitHub Bearer escrow entry pinned to
`api.github.com`; missing/ambiguous credentials reject submission. Jobs never
accept an arbitrary endpoint, Authorization header or redirect destination.

## Session updates

Tool discovery is sessionless: setup registers all five tools without reading
guest configuration, creating timers, contacting the broker or emitting messages.
Missing or invalid configuration therefore does not hide tools. It is reported
when a tool actually executes.

Execution resolves the real session from Cline's tool context, falling back to
the setup session when present. Without either, execution fails before I/O.
A conflicting tool/setup session is rejected; there is no last-session fallback
and tool input cannot set the session. One session-bound snapshot contains the
broker configuration, result paths and notification observer. It is initialized
on first execution, or on session-bound setup to resume notifications. Config
edits become effective on session/plugin reload, not halfway through a request.

Each initialized session polls every 15 seconds while its sandbox is alive. Terminal
states emit `steer_message` with `{sessionId, prompt}` through Cline's plugin host
bridge. The prompt contains only the job ID/status and a get-result instruction:
no query, file content, GitHub message or token is promoted into a steer prompt.
The result is fetched as tool output, which remains untrusted upstream content.

**Cline sandbox lifetime matters:** Cline's default plugin idle timeout is 30
minutes, measured from host calls into the sandbox. The plugin does not override
that global setting. If requests remain pending for 20 minutes since the last
Friendzone message, it emits one grouped reminder containing only IDs/statuses.
Cline starts a normal turn when the session is idle; Friendzone's no-op lifecycle
hooks make that turn a host-to-sandbox call, refreshing ordinary sandbox liveness.
Further reminders occur no more than every 20 minutes while work remains active.
The reminder distinguishes pending, approved and sending jobs; it never implies
that an approved job still needs another decision.

This is best-effort, not a daemon contract: a closed/failed session, unavailable
bridge, or a session that stays busy/aborting can prevent the reminder turn and
allow normal sandbox reaping. Reinitialization catches up from durable jobs.
Closing the session/hub still stops polling.
Get/list recover the accepted job; they never resubmit. HTTP 4xx/5xx (including
499), GraphQL errors and other terminal states all trigger the same observer.
New 4xx/5xx outcomes are stored as `upstream_error`; older `response_received`
records containing those codes remain terminal and display as HTTP errors.

Release `ebfa82b` briefly configured `CLINE_PLUGIN_IDLE_TIMEOUT_MS=90000000`.
Current setup no longer sets it. Rerunning setup recognizes only that exact value
when ownership is proven by the previous managed environment metadata, restores
the prior Windows user value, and removes it from the generated shell activation.
Other user-authored values are preserved. Existing hubs retain inherited values
until restarted; this migration does not kill them.

Notification checkpoints persist per broker/guest/session in Cline's data
directory (`CLINE_DATA_DIR` respected). Resuming the same session discovers
completed jobs; a different session never receives its updates. The bridge has
no delivery acknowledgement: a process crash between emitting and checkpointing
can duplicate an update. It cannot duplicate execution. A missing bridge leaves
get/list available and logs a diagnostic; older Cline without plugin support
needs upgrading. No inferred minimum release number is claimed.

Contract checked against Cline commit `dd50b97192e21e08408ee2ad1c5190aaf56d610e`:
[background-terminal example](https://github.com/cline/cline/blob/dd50b97192e21e08408ee2ad1c5190aaf56d610e/sdk/examples/plugins/background-terminal.ts),
[sandbox tool/bridge contract](https://github.com/cline/cline/blob/dd50b97192e21e08408ee2ad1c5190aaf56d610e/sdk/packages/core/src/extensions/plugin/plugin-sandbox-bootstrap.ts),
[discovery paths](https://github.com/cline/cline/blob/dd50b97192e21e08408ee2ad1c5190aaf56d610e/sdk/packages/shared/src/storage/paths.ts).
Sessionless contribution discovery is defined in
[plugin-tools.ts](https://github.com/cline/cline/blob/dd50b97192e21e08408ee2ad1c5190aaf56d610e/sdk/packages/core/src/services/plugin-tools.ts),
which calls setup with `{ workspaceInfo }`, not a session.
The intended runtime is Cline's Node plugin sandbox on Linux/Windows; bridge
delivery to an actual installed Cline session still requires guest acceptance
testing. Import/discovery tests load the standalone file using native dynamic
import and Cline's pinned `importPluginModule` under Node and Bun, then run
sessionless contribution discovery. The CommonJS
export is `module.exports = plugin`: wrapping it in `{ default: plugin, plugin }`
causes Cline to select an object without a `name` and reject the plugin before
tool registration. A VM test which selects `module.exports.default` does not
test this boundary.

## Limits and durability

This is separate from the **unchanged 64 KiB, 120-second proxy review**:

| Limit | Async jobs |
|---|---|
| GraphQL JSON payload | 10 MiB |
| Review lifetime | 24 hours |
| Upload deadline | 15 seconds |
| Upstream execution | 90 seconds, serial worker |
| Response body | 4 MiB; larger/interrupted response is incomplete |
| Retained jobs | 100; explicit removal, no automatic eviction of keys |
| Active requests | at most 32 globally / 8 per guest, further limited by storage reservation |
| Durable store | 256 MiB including reserved response space |

Lexical/nesting/structural display budgets still apply. Large strings such as
base64 file contents are shared by display reference instead of repeatedly
copied into the structural expansion budget. The original input is retained
and mutations still require approval. This is not a staged-file/diff publication
UI or a binary Git push implementation.

`async-jobs.json` in the broker data directory stores submitted content, token
binding digests (not tokens), state, and results. It is private host data; Unix
files are owner-only. Windows relies on data-directory ACLs, as existing stores
do. The simple bounded store is atomically replaced per transition. Use only one
broker per data directory. It is not a transactional filesystem/database against
power-loss in all environments, and it is not encrypted storage.

`Sending` is persisted **before** sending to GitHub. On restart:
- Pending/approved jobs become cancelled, not sent; submit again if needed.
- Sending jobs become uncertain; never automatically replayed.
- Completed/denied/cancelled jobs and results remain retrievable.

Guest policy gains a durable incarnation field. Back up `containers.json` before
upgrading: older builds reject that new field rather than silently misreading it.
Downgrading requires a matching policy backup, not deleting approval state.

Guest approval/IP/Kill is checked at submission, each guest API access, and
execution admission. Changing a pin or killing/resuming invalidates queued work;
removing/re-adding a name gives it a new durable incarnation so it cannot read
the old guest's jobs. Token changes before admission block execution. A later
policy change cannot undo an already-admitted GitHub write. Results after a
network failure require upstream inspection, not blind retry. If result storage
fails, the durable Sending record is intentionally not re-executed.

## Guest HTTP interface

All requests use the bootstrap listener and the same approved guest Basic
identity/IP pin as MCP. No management routes are added to that listener.

`POST /guest/jobs` takes the submission plus `session_id`; `GET /guest/jobs`
lists, `GET /guest/jobs/{id}` fetches, `POST /guest/jobs/{id}/cancel` cancels,
and `DELETE /guest/jobs/{id}` removes a terminal record. Other than submit, add
`?session_id=...`. No response is cacheable. Session IDs route work; they are
not a security boundary against code already running as the same guest.

The plugin connects directly to the configured bootstrap origin using Node's
HTTP(S) APIs, never through a proxy and never following redirects. Existing host
firewall/isolation requirements still apply. Setup contains only public config.

## Validation boundary

Tests use isolated broker data/ports, fake GitHub tokens/local upstreams, explicit
temporary guest homes and mocked Windows user-environment writes. They do not
install into the developer's Cline, restart a live broker, change host networking
or send real GitHub mutations.

The publication acceptance test submits a large `createCommitOnBranch`, approves
and executes it, reads the retained commit result, then independently submits,
approves and executes `createPullRequest`. It verifies the expected-head and head
branch inputs and proves that later worker ticks and broker reloads replay neither
write. Changes to async publication are not considered complete unless this full
workflow passes; isolated parser or tool-discovery tests are insufficient.

`tests/plugin_loader.test.cjs` imports and calls sessionless `setup` to collect
tool descriptors, but never executes an agent tool or uses guest configuration.
Run it with `node --test` or `bun test`. The optional `FZ_CLINE_PLUGIN_IMPORT`
points at Cline's actual `plugin-module-import.ts` with its dependencies present.
`tests/fixtures/prepare_plugin_loader.ps1 -Directory <empty absolute temp path>`
prepares the pinned loader and integrity-checked Jiti 2.7.0 for this check without
installing Cline or running npm scripts. It requires Bun or Node with TypeScript
stripping to import the upstream `.ts` file.

For installed-artifact checks, set `FZ_PLUGIN_TEST_ARTIFACT_DIR` to an absolute
temporary directory when running `cargo test --locked --release bootstrap::tests`,
then run the import suite with the same variable. This exercises bytes extracted
from the Linux bootstrap and written by the mocked Windows installer. Optionally
set `FZ_TEST_PWSH` to the absolute PowerShell 7 executable to add it alongside
PowerShell 5.1. Without those variables, the optional checks explicitly skip.