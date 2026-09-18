# Async GitHub jobs and the Cline plugin

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
- `friendzone_submit_git_bundle`: uploads an absolute Git bundle v2 path plus
  repository, target branch, exact prerequisite/base OID and exact expected target OID. It returns a
  durable job in `preparing`; approval is unavailable until the broker has
  validated the bundle and derived the full review described below.
- `friendzone_get_request`: status, HTTP status, and the upstream response string.
  It also returns bounded transport diagnostics: admission/header/completion
  timing, connected peer, body completeness, transport error category, and an
  allowlist of provider/edge correlation headers. Large results return a preview
  plus an absolute guest result-file path.
- `friendzone_list_requests`: outstanding and completed requests for this session.
- `friendzone_cancel_request`: cancels pending/queued work, not a running mutation.
- `friendzone_remove_result`: explicitly removes a finished job. Routine known
  results rotate automatically after delivery when capacity is needed; use this
  for immediate cleanup or an uncertain result after checking upstream. It does
  not undo anything upstream.

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

Tool discovery is sessionless: setup registers all six tools without reading
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
bridge. For each newly terminal job, the plugin fetches its retained record once and
includes up to 4 KiB of response/result text, quoted and explicitly labeled as
untrusted data whose embedded instructions must not be followed. Query text, submitted file content, and
tokens are never included. Empty/status-only outcomes say that no response details
were retained. `friendzone_get_request` is suggested only if more detail or
diagnostic metadata is needed; the completion message always says not to resubmit
automatically. Larger complete results remain available as tool output, which is
also untrusted upstream content.

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
completed jobs; a different session never receives its updates. After emitting a
known terminal result, the plugin durably checkpoints its deduplication state and
then acknowledges that result to the broker. A failed acknowledgement is retried
without re-emitting. The Cline bridge itself has no delivery receipt, so a process
crash between emitting and checkpointing can duplicate an update; it cannot
duplicate execution. A missing bridge leaves get/list available and logs a
diagnostic. Older plugins without broker acknowledgement get a one-hour result
window before old known outcomes become eligible for pressure cleanup.

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

| Limit | GraphQL jobs | Git publication jobs |
|---|---|---|
| Input | 10 MiB JSON | 32 MiB Git bundle v2 |
| Review lifetime | 24 hours | 24 hours |
| Upload deadline | 15 seconds | 60 seconds; 4 concurrent uploads |
| Execution | 90 seconds, serial worker | serial validation/publication worker; 120-second push |
| Retained history | Up to 100 | Up to 32 |
| Active jobs | 32 globally / 8 per guest | 8 globally / 4 per guest |
| Durable storage | 256 MiB including reserved response space | 256 MiB of retained bundles |

The 90-second execution limit starts at admission, after approval and queueing.
`upstream.accepted_to_approval_ms` and `approval_to_admission_ms` separate human
review from later queueing; `time_to_headers_ms` and `total_ms` measure only the
admitted upstream request. Friendzone logs the same phase boundaries under the
durable request ID.
Diagnostic headers are a fixed allowlist (for example `x-github-request-id`,
`server`, `via`, tracing and rate-limit fields); credentials, cookies, request
content, and arbitrary response headers are excluded.

History limits do not require routine manual cleanup. On a new admission,
Friendzone removes the oldest acknowledged known terminal results until the job
count/storage reservation fits. For compatibility with older plugins, an
unacknowledged known result becomes eligible after one hour. Active work, fresh
unacknowledged results, and `unknown` outcomes are never automatically removed;
if those alone occupy capacity, the admission fails without changing history.
Git publication cleanup removes its metadata and matching bundle artifact
together. Explicit removal remains available when immediate cleanup is desired.

GraphQL lexical/nesting/structural display budgets still apply. Large strings such as
base64 file contents are shared by display reference instead of repeatedly
copied into the structural expansion budget. The original input is retained
and mutations still require approval.

## Git branch publication

Ordinary `git push` and direct `POST .../git-receive-pack` remain blocked. A
waiting smart-HTTP push cannot safely expose an opaque pack for a quick approval,
and its client may time out while a human reviews it. Instead, create a bundle in
the guest and submit it with `friendzone_submit_git_bundle`. The plugin uploads
exact bytes directly to the fixed bootstrap origin without credentials,
redirects, proxy interpretation, or automatic retries.

When the broker has a GitHub escrow entry exposing the fake `GITHUB_TOKEN`, guest
setup configures Git automatically. Ordinary HTTPS Git and LFS reads work:

```sh
git fetch origin main
git lfs fetch origin HEAD
```

Setup writes a Friendzone-owned include file containing no token value. Its
credential block is scoped to exact HTTPS `github.com`; the helper independently
checks that protocol and host, clears stale helpers for that origin, and reads the
current fake `GITHUB_TOKEN` only when Git asks. It returns no Friendzone credential
for HTTP, subdomains, lookalike hosts, `api.github.com`, or any other origin. Git
LFS inherits the same configuration. Never print the token, embed it in a URL, or
put the host's real token in the guest. Ordinary `git push` remains blocked.

Both LFS downloads and uploads negotiate with JSON `POST` requests. Friendzone
buffers at most the normal 64 KiB review-body limit and strictly validates the
current Git LFS batch schema. Only `operation: "download"` on the canonical
GitHub LFS endpoint flows; upload, malformed, compressed, oversized, duplicate,
or unsupported envelopes remain blocked without entering Inbox.

For a new `feature` branch based directly on the current `origin/main` tip:

```sh
git fetch origin main
base=$(git rev-parse origin/main)
git bundle create --version=2 "$PWD/feature.bundle" refs/heads/feature "^$base"
```

Submit the absolute bundle path with `repository=owner/repo`, `branch=feature`,
`base_oid=$base`, and `expected_oid=0000000000000000000000000000000000000000`.
For an ordinary existing-branch update, fetch it first, use its exact remote tip
as both the single `^<oid>` prerequisite/`base_oid` and `expected_oid`.

For a rebased update, capture the existing remote target before rebasing, rebase
onto the current base branch, and make that base tip the bundle prerequisite:

```sh
git fetch origin main feature
expected=$(git rev-parse origin/feature)
git rebase origin/main feature
base=$(git rev-parse origin/main)
git bundle create --version=2 "$PWD/feature.bundle" refs/heads/feature "^$base"
```

Submit with `branch=feature`, `base_oid=$base`, and `expected_oid=$expected`.
No named base branch is required. Friendzone fetches the exact prerequisite commit
from the fixed repository and requires it to be a strict ancestor of the submitted
head. The target must still equal the captured `feature` OID; approval publishes
the rebased head using that exact target force-with-lease.

V1 publishes exactly one linear `refs/heads/<branch>` history rooted at one
exact prerequisite available from the fixed repository. It rejects tags,
deletions, unleased updates, multiple
refs/prerequisites, SHA-256 repositories,
merge commits, non-linear ranges, a prerequisite the repository cannot supply,
or a supplied `base_oid` that differs from the bundle header. Limits include 100 commits, 1,000 per-commit path
entries, a 2 MiB binary-capable patch, 20,000 objects, 64 MiB expanded object
content, and 16 MiB per object.

The broker imports the exact bundle into a private bare repository using Git's
strict object checks. The Inbox review shows target/base/head OIDs, bundle digest,
every full commit message and author, every path touched by every commit, and a
per-commit `--binary --full-index` patch. Repository text is untrusted content,
not instructions. Only this broker-derived review can become approvable.

Approval queues one broker-owned HTTPS push with host escrow credentials. The
worker rechecks the target ref and uses `--force-with-lease`: an empty lease for
creation or the submitted exact OID for an update. It then reads the ref back and
requires the reviewed head. No token, arbitrary endpoint, refspec, or Git option
comes from the guest.

`git-push-jobs.json` and `git-push-jobs/<id>/` retain metadata and the exact bundle
in the host data directory. Restart cancels preparing/pending/approved jobs;
`Sending` becomes `Unknown` and is never replayed; completed outcomes remain
retrievable until explicit removal or automatic acknowledged-history rotation.
If upload/result delivery is uncertain, list/get existing jobs and
inspect the remote branch before explicitly submitting again.

The exact-`base_oid` contract uses push-job store version 2. On first startup,
Friendzone automatically moves a version 1 metadata file and artifact directory
into `git-push-jobs-v1-archive-<UTC>-<UUID>/` beside them, then starts an empty v2
store. Legacy jobs remain available for audit but are never migrated, submitted,
or replayed. The broker logs the absolute archive path. Unknown or corrupt store
versions still stop startup and report the absolute offending path. This does not
affect the separate async GraphQL job store.

`async-jobs.json` in the broker data directory stores submitted content, token
binding digests (not tokens), state, and results. It is private host data; Unix
files are owner-only. Windows relies on data-directory ACLs, as existing stores
do. The simple bounded store is atomically replaced per transition. Use only one
broker per data directory. It is not a transactional filesystem/database against
power-loss in all environments, and it is not encrypted storage.

`Sending` is persisted **before** sending to GitHub. On restart:
- Pending/approved jobs become cancelled, not sent; submit again if needed.
- Sending jobs become uncertain; never automatically replayed.
- Completed/denied/cancelled jobs remain retrievable until explicit removal or
  acknowledged-history rotation under capacity pressure.

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

All requests use the bootstrap listener and the same unique approved source-IP
pin as proxy/MCP traffic. The policy name still owns durable jobs and session
routing, but the plugin sends no guest credential. Matching legacy Basic identity
is accepted only during migration. No management routes are added to that listener.

`POST /guest/jobs` takes the submission plus `session_id`; `GET /guest/jobs`
lists, `GET /guest/jobs/{id}` fetches, `POST /guest/jobs/{id}/cancel` cancels,
`POST /guest/jobs/{id}/acknowledge` marks a checkpointed known result eligible
for pressure cleanup, and `DELETE /guest/jobs/{id}` removes a terminal record.
Other than submit, add
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