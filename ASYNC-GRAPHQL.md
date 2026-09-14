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
- `friendzone_remove_result`: removes a finished job and releases storage. This
  **also removes its deduplication key**; do not resubmit the removed operation.

Keep `request_key` stable for one intended operation. If submission times out,
submit the **same content and key** again to recover its ID, or list requests.
Different content/session with the same guest-scoped key is rejected. Client
disconnects after acceptance do not cancel jobs. Unknown mutations retain full
GraphQL input coverage: the broker does not need a new tool for each mutation.

Queries classified by the existing parser execute without approval. Mutations
and unclassified inputs require **Approve once** in the existing Inbox. Saved
ordinary-comment permissions currently apply only to the proxy path, not jobs.
The broker uses exactly one configured GitHub Bearer escrow entry pinned to
`api.github.com`; missing/ambiguous credentials reject submission. Jobs never
accept an arbitrary endpoint, Authorization header or redirect destination.

## Session updates

The plugin polls every three seconds while its Cline sandbox is alive. Terminal
states emit `steer_message` with `{sessionId, prompt}` through Cline's plugin host
bridge. The prompt contains only the job ID/status and a get-result instruction:
no query, file content, GitHub message or token is promoted into a steer prompt.
The result is fetched as tool output, which remains untrusted upstream content.

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
The intended runtime is Cline's Node plugin sandbox on Linux/Windows; bridge
delivery to an actual installed Cline session still requires guest acceptance
testing. Import-only tests now load the standalone file using native dynamic
import and Cline's pinned `importPluginModule` under Node and Bun. The CommonJS
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

The existing lexical/nesting/display budgets still apply. Very large arguments
can exceed structured-display limits: raw input is retained without truncation,
and mutations still require approval. This is not a staged-file/diff publication
UI or a binary Git push implementation.

`async-jobs.json` in the broker data directory stores submitted content, token
binding digests (not tokens), state, and results. It is private host data; Unix
files are owner-only. Windows relies on data-directory ACLs, as existing stores
do. The simple bounded store is atomically replaced per transition. Use only one
broker per data directory. It is not a transactional filesystem/database against
power-loss in all environments, and it is not encrypted storage.

`Sending` is persisted **before** sending to GitHub. On restart:
- Pending/approved jobs become cancelled, not sent; submit a new key if needed.
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

`tests/plugin_loader.test.cjs` loads but never calls `setup` or an agent tool.
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