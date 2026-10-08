# Friendzone

The `fz` binary provides a local HTTPS-intercepting proxy with GitHub
read/write policy, credential escrow with exact-fake substitution, MCP
forwarding with host-side OAuth, certificate bootstrap, request log,
and a web UI with settings.

New here? See [QUICKSTART.md](QUICKSTART.md) for the run-this-open-that
cheat sheet.

**Security prerequisite:** proxy variables are not confinement. Before
running untrusted agents, follow [NETWORK-ISOLATION.md](NETWORK-ISOLATION.md)
for host-enforced egress restrictions, UI isolation, staged bootstrap,
negative tests, and console-based recovery. The UI is privileged and not
authenticated for guest access. Friendzone is not yet a hardened sandbox.

## Run the broker

One broker serves any number of containers:

```powershell
cargo run -- broker --proxy-addr HOST_VNIC_IP:8080 --ui-addr 127.0.0.1:8081 --bootstrap-addr HOST_VNIC_IP:8082
```

Open <http://127.0.0.1:8081>. The CA certificate and private key are created
under the operating system's local application-data directory in
`friendzone/`. The private key is never served by the bootstrap endpoint.

### Local credential storage

API keys and broker-owned Cline/MCP OAuth records use the current OS account's
credential store by default: Windows Credential Manager (local-machine
persistence, not roaming), macOS login Keychain, or Linux Secret Service
(such as GNOME Keyring or KWallet). The broker caches them in memory; saves
publish that cache only after the credential store commits. Unlock the store
before running the broker. A missing, locked, or unavailable initialized store
stops startup; there is no automatic plaintext fallback.

Stop the old broker before upgrading. On first startup, an existing
`secrets.json` is copied into the OS store, read back and checked, then removed
before listeners start. Migration failures leave the file intact and stop
startup. Conflicting OS/file values are never
silently merged or overwritten. Removal is not secure erasure of old disk
blocks, backups, or snapshots; rotate credentials if those copies are exposed.

OS records are scoped to the canonical data-directory path and the current
OS account. Keep that directory in place: copying it alone to another machine,
user, or path does not move credentials. `os-secret-store.json` contains only a
version marker, and `secret-store.lock` prevents multiple brokers from writing
the same profile. Secret payloads are chunked to fit Windows' per-entry limit;
one manifest selects the complete snapshot. If obsolete-record cleanup fails
after a successful save, it warns and retries at the next save or startup.

**Headless hosts, including a GCE VM without a login keyring, must explicitly
select the existing plaintext backend until cloud storage is configured:**

```sh
fz broker --secret-store=file --data-dir /var/lib/friendzone
```

This mode warns at startup and retains `secrets.json`. It cannot reopen a data
directory already initialized for OS storage; use a separate profile. Protect
the filesystem and backups as before. The backend changes only on restart;
there is no cloud-provider auto-detection.

This storage change does **not** move `friendzone-ca-key.pem`, encrypt process
memory, or change environment-variable/Cline-linked credential sources. The CA key
still needs private filesystem permissions. An OS store does not protect
against a compromised broker, administrator, or other applications authorized
to access the current account's credentials. Management remains loopback-only
and unauthenticated, so local shell access is still trusted-operator access.

To test credential storage, run `cargo test --all-targets`. That uses isolated
test stores, never your saved OS credentials. In a disposable OS account, run
the opt-in native-store check with
`cargo test --bin fz secret_store::tests::native_store_large_snapshot_and_cleanup -- --ignored --exact`.
It creates only a temporary Friendzone namespace and deletes its records.

The UI must bind to loopback on its own fixed port. Proxying to that port is
denied (including CONNECT and hostname aliases); guests must never receive
network access or an alternate relay to the management API. Outside the VM,
allow only the proxy and bootstrap/MCP ports on the broker's guest-facing IP.
The separate bootstrap port must remain reachable for setup and recovery.

The proxy also rejects HTTP requests and CONNECT tunnels to loopback
(`127.0.0.0/8`, `localhost`/`.localhost`, `::1`, and IPv4-in-IPv6 loopback),
except on the configured `--bootstrap-addr` port. For example, accidentally
proxying a guest's `http://127.0.0.1:25463/health` now returns **403**, never
contacts the host Cline hub, and logs the reason without creating a review.
The exception does not bypass guest approval, IP pinning, Kill, or the
management-port block. It is a port exception, not a redirect: bootstrap
must actually listen on the requested address. Keep `NO_PROXY`/`no_proxy`
set for guest loopback and restart old guest processes to stop those requests
reaching the proxy at all. This is not a DNS-rebinding or general LAN guard;
see the network isolation guide for the remaining limitations.

GCE metadata and link-local infrastructure must also stay on the guest's own
instance. Setup adds bypasses for `metadata`, `metadata.google.internal`,
`169.254.169.254`, `fd20:ce::254` (bare and bracketed), `169.254.0.0/16`, and
`fe80::/10`. The proxy independently returns **403** for these destinations,
including HTTP, CONNECT, normalized numeric aliases, and IPv4-in-IPv6 forms,
on every port. The bootstrap exception never permits infrastructure access.
This prevents a guest metadata request from returning the broker instance's
identity. Restart the broker to load the policy; rerun guest setup, activate
the environment, and restart guest processes to load the bypasses. See the
network isolation guide for client compatibility and DNS limitations.

## Containers

Guest setup uses selective routing: Windows receives a live PAC URL and Git
receives URL-scoped proxy settings from configured escrow hosts. Other hosts
go direct. Setup does not install global HTTP_PROXY/HTTPS_PROXY; Cline CLI,
curl, and other non-PAC clients need explicit proxy settings or the generated
compatibility profile when using escrow. See [guest routing](GUEST-BOOTSTRAP.md#selective-routing).
Direct networking is not governed by Friendzone's Kill or request policies.

Containers are dynamic. Setup supplies a human-readable guest name, while
runtime proxy, MCP, and async-job traffic is identified by its unique explicit
source-IP pin. **Unknown containers are denied**: setup first creates a join
request in the Inbox, and nothing flows until you click **Approve + pin IP**.
Pins must be unique. This requires host-enforced anti-spoofing and separate
source addresses; guests behind the same NAT address cannot use IP identity.
Pins are editable under **Settings → Guests**. Clearing a pin leaves a wildcard
policy for legacy named clients but disables credential-free runtime access.
The advanced **Set up guest → Preapprove a name** option similarly needs an
explicit Pin before new credential-free clients can connect. Legacy Basic guest
names remain accepted during migration only when they agree with the source-IP
owner. Kill/Resume stops traffic reversibly; Remove forgets the container (its
log rows remain for audit).

Each guest also has a **Cline API access** mode, chosen on its card under
**Settings → Guests** and saved with its other policy. **Basic** (the default
for every new or restored guest) allows inference, the model catalog, and
account basics on `api.cline.bot`: `POST /api/v1/chat/completions`,
`/api/v1/images`, `/api/v1/search/*`, `GET /api/v1/ai/cline/recommended-models`,
`GET /api/v1/users/me`, `/users/me/plan`, `/users/{id}/balance|usages|payments`,
`PUT /api/v1/users/active-account` (organization switching), and
`GET /api/v1/organizations/{id}`, `/balance`, `/members/{id}/usages`. Basic also
allows `GET /banners/v2/messages` with any query string,
`GET /api/v1/users/me/remote-config`, and `HEAD /` for link content-type probes.
Root `GET` and unrelated metadata paths remain denied. These are ordinary
reads, not CORS preflight requests. In basic
mode `GET /api/v1/session` is answered locally with an empty list, so cloud
sessions appear to not exist; creating, attaching, driving or deleting them,
the Hub WebSocket upgrade, integrations, connectors, plans and every other path
on the host return 403 and are logged as blocked. **Full** forwards everything
on the host. In both modes `/api/v1/api-keys` and
`/api/v1/organizations/{id}/api-keys` are denied: a guest can never mint,
list or delete long-lived Cline API keys. The gate is applied by host to every
decrypted request whether or not it carries a credential, before escrow
substitution, so a denied request never leaves with a real token. It governs
`api.cline.bot` always, plus every other host pinned by a Cline credential
entry: the gate follows the credential, so if you edit the Cline entry to also
pin a staging API origin (making the broker substitute your account token
there), the same allowlist applies there without further configuration. Hosts
no Cline entry pins receive no account token and are not gated. Cline sign-in
is only offered for entries pinned to `api.cline.bot`.
Switching a guest to Full asks for confirmation; use Basic for untrusted guests.

Inbox is for decisions: pending requests, guest joins, then recent outcomes.
Approved/killed guests and saved comment permissions live under
**Settings → Guests**, alongside the single expandable **Set up guest** flow.
The guest list reports **Approved** or **Killed**; actionable joins appear only
in Inbox as **Awaiting approval**.
These describe network authorization, not whether an agent is working, idle,
or online. Last observed guest traffic is shown separately; administrative
actions do not count as traffic. The selected Inbox/Log/Settings tab is
remembered in this browser for the same UI origin.
Guests use alphabetical order unless you drag them into a saved order. Incoming
traffic updates their counts and timestamps without moving cards or replacing
their controls, so the Cline API access dropdown stays usable during requests.

Approvals, IP pins, Cline API access, and kill state are saved atomically in `containers.json`
in the broker data directory and restored on startup. Removal is persisted
too. Failed writes return an error and leave the previous policy in effect;
if Kill cannot be saved, stop the guest externally rather than assuming it
was killed. A malformed/unsupported policy file stops startup instead of
silently resetting permissions. Run only one broker per data directory and
keep that directory inaccessible to guests.

Unreviewed join requests, logs, request counts, and traffic timestamps are
not persisted. After restart, an approved guest may correctly show **No guest
traffic observed this broker session** until it contacts the broker. Restored
IP pins are never automatically changed to match a new address.

**First upgrade:** previous builds held approvals only in memory. They need
to be approved once in this version before later restarts can restore them;
changing the data directory also starts a separate policy store.

## Set up a guest

Use **Settings → Guests → Set up guest**. Select Linux or Windows, copy the `curl` download
command, and run the downloaded script in the guest account. No guest binary,
compiler, or platform-specific build is needed. Linux requires Python 3;
Windows requires curl.exe and PowerShell 5.1 or 7.

The script saves the CA, credential-free proxy URL, loopback exclusions and fake credentials, merges
Cline provider settings, and persists user configuration. Kali/Debian/Ubuntu
gets idempotent profile hooks plus a narrowly elevated native-root installation;
Windows gets user-scoped environment values plus the current-user
Windows Internet proxy used by many .NET clients (not machine-wide WinHTTP).
It also installs the exact Friendzone CA into the guest user's Windows Trusted
Root store (`CurrentUser\Root`), not the machine-wide store. Prior proxy settings
and Friendzone-owned certificate bytes are recorded for ownership-aware rollback.
Close guest Cline
before running the script because it updates that application's settings, then
restart Cline from the activated environment.

The former setup subcommand is removed. Existing guest environment files and
profile hooks are reused. See [GUEST-BOOTSTRAP.md](GUEST-BOOTSTRAP.md) for the
script endpoints, persistence details, trust model and rollback.

## Try the proxy locally

Start the broker, then in another shell:

First preapprove a `reviewer` label in Settings and pin it to `127.0.0.1`.

```powershell
curl.exe --proxy http://127.0.0.1:8080 `
  --cacert "$env:LOCALAPPDATA/friendzone/friendzone-ca.pem" `
  https://example.com/
```

The request appears under the IP-pinned `reviewer` guest in the UI and request log.
The UI kill button rejects subsequent requests from that container until
resumed.

### Proxy transport and tracing

Friendzone shares one upstream connection pool across guests, normally negotiates
HTTP/2 with HTTP/1.1 fallback, streams ordinary provider responses without
buffering, and never retries an uncertain POST. As a targeted timeout workaround,
exact HTTPS `api.cline.bot:443` connections advertise HTTP/1.1 only; other origins
retain normal H2 negotiation. This avoids sharing Cline inference requests on the
H2 connections implicated by traces while preserving concurrent H1 connections.
The selection is fixed at broker startup. Its request log and stderr diagnostics
separate connection/send, response-header, first-byte, streaming, and completion
phases and retain typed I/O/TLS/HTTP/2 failures without bodies, query strings,
credentials, arbitrary headers, or raw HTTP/2 HEADERS frames.

Friendzone can also export OTLP/HTTP protobuf spans. Incoming W3C context becomes
the parent of `friendzone.proxy.request`; its `friendzone.proxy.upstream` child is
injected into the provider request. Both carry `friendzone.request.id` for the UI
log. Stock Cline currently exports OpenTelemetry logs/metrics only—not distributed
traces—so true automatic Cline-to-proxy parentage requires temporary Node
auto-instrumentation or another client that injects `traceparent`.

See [Trace commands and Cline proxy timeouts](TRACING.md) for the exact-command
wrapper, broker configuration, Cline instrumentation, the portable Windows
Jaeger viewer, JSON export, privacy, and a phase-by-phase diagnosis table. The
turnkey path uses the existing bootstrap listener to relay approved guest trace
batches to loopback Jaeger, so it requires no Docker or additional guest
firewall port.

## Automated test guests

Use the management REST API on the broker host (`http://127.0.0.1:8081` by
default). It shares the UI's privileged, unauthenticated loopback listener;
do not expose it to guests or untrusted callers. Remote orchestrators can run
these calls on the host through SSH rather than opening the management port.

| Operation | Request | Success |
| --- | --- | --- |
| Register and approve a guest | `POST /api/containers` with `{"name":"test-42","ip":"192.0.2.42"}` | `201 Created` |
| Remove a guest | `DELETE /api/containers/test-42` | `204 No Content` |
| Remove all guests | `POST /api/reset` (no body required) | `204 No Content` |
| Inspect guests and audit history | `GET /api/state` | `200 OK` |

Registration approves and pins the guest in one durable transaction, before
it boots. `ip` accepts an IPv4 or IPv6 address; omitted or `null` leaves an
existing pin unchanged (a new guest has no pin). Credential-free proxy use
requires a unique explicit pin. Duplicate registration preserves the guest's
other settings, including Kill; use a new name or remove it before reusing it.
Names are trimmed and must be nonempty without `:` or `@`. Malformed input
returns `400`/`422`; policy conflicts or save failures return `500` without
applying any registration or reset. Removal and reset are safe to repeat.

Reset removes approved, killed, and pending guests, their IP pins, Cline access
settings, and comment permissions. It cancels waiting proxy/upload reviews and
invalidates queued jobs before upstream admission; workers record cancellation
on their next pass. Credentials, CA files, MCP configuration, and audit/job
history remain intact. A reconnecting guest is unapproved again. Reset does not
stop instances or retract requests already sent upstream.

For trusted test workloads that need unrestricted GitHub access, start the
broker with:

```sh
fz broker --allow-all-github
```

This disables human review for all GitHub requests through the proxy, including
REST writes, GraphQL mutations, direct Git pushes, and LFS uploads. Broker-owned
GraphQL jobs, validated Git bundle publication, and GitHub attachments also run
without human approval. Their format, size, credential, and publication checks
still apply. Guest approval, IP pins, Kill, destination restrictions, credential
substitution/leak prevention, Cline access, and Linear review remain enforced.
GitHub still enforces the credential's scopes and repository permissions.

The mode is off by default, is not saved in the data directory, and changes only
on broker restart. It grants approved guests the host credential's GitHub power;
do not use it for untrusted agents. On headless hosts without a keyring, explicitly
add `--secret-store=file` as described above.

## GitHub policy

The following review rules apply without `--allow-all-github`.

For operations that need human review or large GraphQL payloads, use the
[async Cline plugin](ASYNC-GRAPHQL.md), installed by the guest setup script.
It returns a job ID immediately and steers the originating session on completion.
Completed known results are acknowledged only after the plugin durably checkpoints
their completion message, then the oldest acknowledged history rotates automatically
when capacity is needed. Routine jobs do not require manual deletion. Active work,
fresh undelivered results, and uncertain outcomes are never automatically removed.
The limits and connection-lifetime behavior below describe the proxy path.

### Git HTTPS authentication

Git's `Authorization: Basic base64(username:fake-token)` is supported. The
broker matches the **entire password** to an Authorization escrow entry's
fake, checks its host pin, and re-encodes `username:real-token`. The username
is preserved; the entry's API `Bearer ` prefix is **not** part of the Basic
password. Existing API Bearer substitution is unchanged. Missing secrets
and known fakes sent to non-pinned hosts are denied; anonymous requests and
unrelated/malformed credentials do not cause token injection.

GitHub CLI's `Authorization: token <fake>` is also recognized for GitHub
Bearer escrow entries. It goes through the same exact-token, host-pin and
current-secret checks, then uses the configured upstream Bearer header.
This does not inject credentials into anonymous or unrelated requests.

When a GitHub escrow entry exports the fake `GITHUB_TOKEN`, guest setup makes
plain Git authentication automatic without modifying repository or user-global
Git configuration. Normal reads work after setup and a fresh shell:

```sh
git fetch origin main
git lfs fetch origin HEAD
```

Setup writes a Friendzone-owned Git include containing the helper logic but no
token value, then activates it through the managed environment. The credential
block and helper both require exact HTTPS `github.com`; the helper returns
`x-access-token` plus the current fake `GITHUB_TOKEN` only for that origin and
clears stale earlier helpers there. It returns nothing for HTTP, subdomains,
lookalike hosts, `api.github.com`, or other origins. Git LFS inherits this setup.
Do not print the token, put it in a remote URL, or use the host's real token.

Friendzone parses the bounded Git LFS batch body because both downloads and
uploads use `POST`. Only a strict `operation: "download"` batch on the canonical
GitHub LFS route flows automatically. Upload, malformed, compressed, oversized,
or unsupported LFS batches remain blocked and cannot be manually approved.

`GET .../info/refs?service=git-receive-pack` is push-service **discovery**, not
a write. GitHub can return `401` with a Basic challenge before Git retries
with credentials, even on a public repository. The log's `allowed` verdict
means Friendzone forwarded the request; its HTTP status is GitHub's response.
The subsequent binary `POST .../git-receive-pack` from ordinary `git push`
remains blocked: Friendzone does not quick-approve opaque pack bytes on a waiting
connection. To publish a branch for a PR, use the durable Cline
`friendzone_submit_git_bundle` workflow below.

### Reviewed Git branch publication

The guest creates a version-2 Git bundle with exactly one branch and one
prerequisite, then submits its absolute path through the Friendzone Cline plugin.
Friendzone imports and validates the exact objects in a private host-side bare
repository. Only after validation does Inbox show an approvable review containing
the repository/ref, expected/base/head OIDs, bundle SHA-256, full commit messages
and authors, every per-commit path entry, and an exact binary-capable patch.

For a new branch based directly on the current `origin/main` tip:

```sh
git fetch origin main
base=$(git rev-parse origin/main)
git bundle create --version=2 "$PWD/feature.bundle" refs/heads/feature "^$base"
```

Ask the agent to call `friendzone_submit_git_bundle` with that absolute path,
`repository=owner/repo`, `branch=feature`, `base_oid=$base`, and forty zeroes as
`expected_oid`. An ordinary existing-branch update uses its exact current remote
SHA as both the sole prerequisite/`base_oid` and `expected_oid`.
A rebased update uses the commit it actually rebased onto as the bundle
prerequisite and the target branch's pre-rebase remote SHA as `expected_oid`.
No named base branch is required. Friendzone fetches the exact `base_oid` from the
fixed repository, verifies it against the bundle prerequisite, and rewrites the
target only under the captured target lease.

V1 allows one merge-free, linear `refs/heads/*` history rooted at one exact
repository-known prerequisite, including an exactly leased rebased target update. It does not support
tags, deletes, unleased updates, merge commits, multiple refs,
SHA-256 object IDs, LFS, or arbitrary remotes/refspecs/options. The broker uses
the configured host GitHub credential, rechecks the target, pushes once with an
exact `--force-with-lease`, and reads the ref back. Restart never replays an
interrupted publication. See the [complete contract and limits](ASYNC-GRAPHQL.md#git-branch-publication).

### Upload files before posting descriptions or comments

The managed guest plugin provides `friendzone_upload_file`. Pass an absolute
guest `file_path` and `destination: "github"` or `"linear"`; GitHub also requires
`repository: "owner/repository"`. No issue, PR or comment ID is required, so
uploading works before creating one. An optional `content_type` overrides the
type inferred from common filename extensions.

1. Upload the file and approve its exact bytes/digest and destination in the
   host Inbox. The tool waits for approval, then returns `url` and `markdown`.
2. Use that URL in an issue/PR description, comment, or Linear document through
   the normal create/update tool. Uploading alone does not publish any text.

GitHub supports PNG, JPEG, GIF, SVG, MP4, MOV and WebM up to a conservative
10 MB per file. The host token must be a PAT or OAuth token with repository
write access; installation tokens cannot upload attachments. For an existing
GitHub credential, add **uploads.github.com** to its pinned hosts while retaining
**api.github.com**. New GitHub presets include both. The guest's fake
`GITHUB_TOKEN` selects the credential; no real token goes to the guest.

Linear accepts files up to 25 MiB. Add **Linear file uploads** under host
Settings → Credentials with a writable Linear API key. Its only pinned host is
**api.linear.app** and its guest variable is **LINEAR_API_KEY**. Rerun guest
setup and restart guest Cline to receive the fake and new tool. This is separate
from MCP OAuth: MCP credentials are not silently reused at another endpoint.
Linear URLs are private to Linear; upload separately to GitHub when embedding
in a GitHub description/comment.

The binary path preserves exact bytes without decoding, stripping metadata or
converting images. Raster images can be previewed in Inbox; SVG and other files
are download-only. Review files for sensitive data before approval.
Four concurrent transfers, a 60-second receive deadline and the existing
120-second review deadline bound resource use. The plugin permits enough time
for receiving, review and provider calls. No redirects or automatic retries
occur. Linear preparation is followed by a raw PUT with its required signed
headers, without the broker API credential.
Direct Linear API text writes also require one-shot review; the upload
credential does not turn the general proxy into an unreviewed mutation path.

List/get requests can recover returned URLs within the current broker session;
upload records and pending approvals are memory-only and are not replayed after
restart. Cancel only while pending. Removing a result does not delete the
uploaded remote file. If delivery is uncertain, inspect list/get and upstream
before submitting again. General binary proxy writes remain blocked; this path
does not add general binary, multipart or ordinary Git-push permission.

### Reads and manual review

GitHub reads (GET/HEAD/OPTIONS, `git-upload-pack`, and parsed GraphQL queries) flow through the
proxy. Potential writes wait in **Inbox → Requests**.
Open **Review**, inspect the complete URL, input values and literal
payload, then **Approve once** or **Deny**. Approval releases only that
immutable request through the normal escrow path, not a rule for future
requests. The log shows pending, denied, approved and upstream status.

**Approve once is the confirmation**: one click submits the loaded request's
fingerprint, without another dialog. Duplicate clicks are suppressed and the
broker rejects requests that have already been decided, cancelled or expired.
No failed decision or upstream request is automatically replayed by the UI.

`POST https://api.github.com/graphql` now has a **GraphQL operation** viewer:
selected query/mutation/subscription, actual fields behind aliases, expanded
fragments, resolved arguments, variable defaults, formatted document and
supplied variables. **All input values are visible immediately** as labeled
rows, including nested/unknown inputs; only response-only selections and
technical representations are collapsed. Comment text is shown literally, separately from its
target. The exact original body remains visible and is forwarded unchanged.
**GitHub GraphQL queries now flow automatically**, including aliases,
fragments, variables and introspection. Classification uses the selected
AST operation, not a name or the occurrence of `mutation` in strings.
In a multi-operation document, `operationName` must unambiguously select
the query. This relies on GitHub's read-only Query root; it is not a promise
about arbitrary GraphQL servers, nor full GitHub schema validation.
Malformed, ambiguous or unsupported input
shows a diagnostic and raw body instead of a partial structured summary.

The standard `gh` PR-query header `GraphQL-Features: merge_queue` is supported;
unknown feature switches still require review. The view shows elapsed time
and the remaining broker review window. A cancellation before that deadline
is not broker expiry: the client or its tool runner may have stopped waiting.
If doing a manual review, give **both the HTTP client and its enclosing tool**
more than 120 seconds (for example, `curl --max-time 180` for an intentional
curl test). Extending only the broker timeout cannot extend a client timeout.
Never automatically replay a timed-out mutation: inspect the retained outcome
and upstream state first.

**PR creation and review comments/threads/submission are allowed with manual
approval.** Open the pending request, inspect all inputs, then **Approve once**
or **Deny**. Review cards label branches, repository IDs, title/body, commit,
file/line and review event (`COMMENT`, `APPROVE`, `REQUEST_CHANGES`). These
mutations never inherit ordinary saved comment permissions. JSON REST PR
creation/review-comment requests use the same one-shot gate. GitHub token
permissions still apply. Publish the head branch first with the reviewed bundle
tool; ordinary binary `git push` remains blocked.
See [GRAPHQL-REVIEW.md](GRAPHQL-REVIEW.md) for supported syntax and the
operation/target model and the supported issue/PR-scoped comment permission.

For an eligible `addComment`, click **Resolve GitHub target**, inspect the
real repository/number/title, then **Allow future comments here**. This
saves a permission for **one guest + one target + one escrow credential**.
Future supported comments with different text are verified against GitHub
and reconstructed by the broker, without repeated approval. Other
operations or unsupported request shapes still go to Inbox. The current
waiting request still needs **Approve once** or **Deny** separately.
Use **Settings → Guests → Saved comment permissions → Revoke** to remove the permission.
Grants survive restart; guest removal removes them and token changes make
them inactive. See [the exact contract](GRAPHQL-REVIEW.md#verified-per-guest-comment-permissions).
Broker credentials never appear in the review; credential headers are
redacted. URLs and request bodies may themselves contain sensitive guest
data, so don't share screenshots casually. Payloads are untrusted text,
not instructions to the reviewer and not a broker-validated action summary.

The synchronous proxy queue is memory-only: 32 requests globally, 8 per guest, 64 KiB per body,
16 KiB of headers and 8 KiB of URL, with a 10-second upload and 120-second
decision deadline. Compressed, binary, multipart/form and direct git push
payloads remain blocked because this path cannot faithfully review them. The
separate bundle tool is durable and broker-parsed. Kill,
removal, approval/pin changes, expiry, or cancellation of the waiting HTTP
handler end the pending request; restart never replays it. A permission
change after the final admission check cannot undo already-admitted work.
No general approve-for-session/always rules or MCP write approval are added here.
Other origins remain logged and unpoliced.

**Outcomes in Inbox:** Pending contains only requests needing a decision.
Pending/Recent use compact tables with operation, repository/target hint, guest,
status, time and action. Missing repository information is labeled, not guessed.
HTTP 4xx/5xx show as errors, including older retained 499 responses.
Async `request_key` values are correlation labels, not deduplication keys. Every
explicit submission is a distinct job requiring its own decision.
Recent also includes [durable async jobs](ASYNC-GRAPHQL.md). For the proxy,
it retains the last 100 reviewed requests and their redacted details for
this broker session, separate from the busy traffic log. Open details stay
visible after approval/denial and update live: Approved, Sending, Response
received (with HTTP status), Denied, Expired, Cancelled, Blocked, or Upstream
error. A response is not a claim of application success (GraphQL can report
errors with HTTP 200). Reviewed GraphQL JSON responses up to 64 KiB are
observed as they stream to the guest; a nonempty `errors` array produces a
GraphQL error badge and retains bounded, explicitly untrusted error messages,
paths/locations, body size, partial-data presence, and allowlisted provider/edge
correlation headers. It never retains the complete response or arbitrary headers. Larger,
encoded or unparseable responses remain HTTP-only outcomes. If the handler
ends after admission without a response,
the badge says **No response received**. If headers arrived but the response
was not fully observed, it says **Response incomplete · HTTP …**. These report
what the proxy observed, not that the upstream operation failed. Recent is
read-only: no replay, reapproval or new permissions from old requests. Reload
preserves this server-side history; broker restart clears it. Bodies remain
host-only and are never included in SSE or desktop notifications.

**Retry caution:** clients may time out before 120 seconds, and the HTTP
stack may not immediately cancel its handler on a disconnect. Deny a stale
pending write before retrying; each retry needs independent approval and
may duplicate the upstream operation. A lost response after approval does
not prove failure: check upstream state before retrying. Approvals are
one-shot authorization, **not exactly-once delivery**.

**Desktop notifications:** click **Enable notifications** in Inbox and
grant the browser permission. Requires a supported desktop browser and a
secure context (the default `http://127.0.0.1:8081`/`localhost` qualifies).
Keep the UI open, including in a background tab. Notifications coalesce
bursts and remember recently notified IDs across reloads; clicking one
focuses Inbox, never approves a request. Their text contains no payload or
URL. Browser/OS notification settings can suppress them; the Inbox works
without permission. No push service or closed-browser delivery is included.
Automatically allowed queries create no pending item or notification; their
log rows say `read-only GitHub GraphQL query; automatically allowed`.

## MCP forwarding (read tools)

Use **Settings → MCP servers** to add, validate and apply a forward live,
or link a selected streamable-HTTP server from a host Cline settings file.
Select allowed tools and guests explicitly; the import grants neither by
default and never executes host commands. See [QUICKSTART.md](QUICKSTART.md)
for the flow and guest authentication example.

Advanced configuration lives in `mcp-forwards.json` in the broker data directory — the same
directory that holds the CA files. The broker prints the exact path at
startup ("Friendzone data: …" / "MCP forwards: none (to add some,
create …)"), and the Settings page shows it when no forwards exist.
Defaults per OS:

| OS      | Path                                                        |
|---------|-------------------------------------------------------------|
| Windows | `%LOCALAPPDATA%\friendzone\mcp-forwards.json`               |
| macOS   | `~/Library/Application Support/friendzone/mcp-forwards.json`|
| Linux   | `~/.local/share/friendzone/mcp-forwards.json`               |

(With `--data-dir`, it is `<data-dir>/mcp-forwards.json`.) Contents:

```json
[
  {
    "name": "linear",
    "url": "https://mcp.linear.app/mcp",
    "bearer_env": "FZ_LINEAR_TOKEN",
    "tools": ["list_issues", "get_issue", "list_comments"]
  }
]
```

Use **Save & apply** (or **Reload from disk** for external edits), not a
broker restart. Unchanged upstream sessions survive, including tool/guest
permission changes; new requests acquire the new snapshot and in-flight
calls finish with the old one. `guests: []` denies all; omitted/null means
all approved guests for legacy configurations. Set a guest-name list for
restricted sharing. Invalid configurations do not replace live forwards.

For a new imported or standalone OAuth server, **Add & authorize** saves it
and opens host sign-in in one step. After login, **Next: choose tools and
guests**, then **Save guest access**. Until then, the new server is private.
Existing server cards offer **Authorize in Friendzone** and **Choose tools
and guests**, plus a full, wrapping guest endpoint with **Copy URL**.
**Connect guest → Copy Cline configuration** uses the guest's unique source-IP
pin and includes no guest credential or upstream token.
The broker discovers protected-resource and authorization-server metadata,
registers a public client, uses PKCE S256 and a resource-bound grant, and
stores its own session on the host. Concurrent requests share one refresh
operation and retry once after an upstream 401. The settings page reports
login completion/failure and offers Reauthorize and Disconnect. A `"scope"` field on
the forward requests a narrower grant (e.g. `"read"` for Linear
read-only). Alternatively set the `bearer_env` variable to an API key.
Containers connect a streamable-HTTP MCP client to
`http://HOST_IP:8082/mcp/linear`. Only `tools/list` (filtered to the
allowlist) and allowlisted `tools/call` reach upstream; the token never
enters the container.

The optional Cline credential-link mode still reads current headers/access
tokens from its host file, with Cline owning refresh. **Authorize in
Friendzone** switches the forward to `"oauth": true`: Cline remains import
provenance only, with no credential fallback. Its refresh tokens/files are
never copied or modified. Tokens are pinned to the upstream URL; disconnect,
reconfiguration and superseded callbacks cannot resurrect them. Permissions
are not expanded by login. This OAuth implementation requires dynamic
public-client registration and a loopback host UI callback; confidential or
pre-registered clients and stdio/SSE imports are not supported yet.
For a remote broker, forward the loopback UI port to the machine displaying
Friendzone so that browser can return the MCP callback to the broker.

OAuth start endpoints return validated URLs to the admin UI, which opens them
in the browser displaying Friendzone. This works with a remote or headless broker.
The sign-in panel retains the complete URL with Open and Copy actions, plus the
registered callback for troubleshooting.

Guests are identified by their unique source-IP pin, not upstream OAuth. New
generated MCP transports have no guest `Authorization` header. An old guest
Cline entry showing “OAuth required” should be replaced with the generated
transport configuration and have stale `Authorization`, `oauth`, and
`oauthClient` fields removed. See [QUICKSTART.md](QUICKSTART.md) for recovery
steps.

## Credential escrow (inference and other APIs)

In the UI, Settings → Escrowed credentials: pick a provider preset
(Anthropic, Cline, GitHub, or Custom…) and paste the real key into the
single masked field — the only place a real key goes. The preset fills
the pinned hosts, credential header, prefix, and guest env var
(Anthropic uses `x-api-key` with no prefix; OpenAI-style APIs use
`authorization` with `Bearer `); each preset's hint says where to get
the key (for GitHub: a fine-grained PAT or `gh auth token`). The fake
key is always broker-generated, never typed. Entries can be edited
(fixing hosts/header keeps the fake, so guests keep working; pasting a
key rotates it) and deleted (the stored real key goes with the entry).

Cline credentials are **OAuth-only**. Add the entry with the key field empty
(the UI disables it for the Cline preset, and the broker rejects a pasted key
for any entry pinned to `api.cline.bot`), then click "Sign in with Cline…".
The broker uses the device-code flow:
it shows a short code, the admin UI opens the verification page in the browser
you are using, and the broker polls until you confirm it — no broker-local
browser, display server, callback, or editor redirect. Tokens are registered
with Cline's backend and auto-refresh from then on. Static Cline API keys
(`app.cline.bot → Settings → API Keys`) are not supported: a Cline entry has no
usable credential until it is signed in, a static key left in an older
secret store is ignored, and the guest never receives the entry's fake while
the entry is disconnected. Per-guest limits on what that account may do live on
the guest, not the credential (see Containers above).

The guest setup script saves the fakes as `friendzone-env.sh` (or `.ps1` on Windows);
source it in the agent's shell. When the fakes include `CLINE_API_KEY`,
setup also writes `~/.cline/data/settings/providers.json` (the settings
file Cline's CLI, IDE extension, and SDK share) as an OAuth-shaped facade: `auth.accessToken`
contains only `workos:<fake>`, its local expiry is far in the future, and
`tokenSource` is `"oauth"`. No real access token, refresh token or account ID
enters the guest. This lets account/Cloud UI take Cline's OAuth path while the
broker substitutes its current host token. Guest refresh is blocked because
refresh remains host-owned. The write is merge-safe: other providers, model
choice, and `lastUsedProvider` are preserved; a stale static `apiKey` from an
older setup is removed so it cannot shadow the facade. Run setup while guest
Cline is stopped, then restart it.

Cline Cloud's REST calls use the normal proxy. Its Hub connection also requires
a Cline build whose `NodeHubClient` sends `ws:`/`wss:` through the configured
`HTTP_PROXY`/`HTTPS_PROXY`; otherwise externally enforced guest isolation will
correctly block that direct WebSocket connection. Both need the guest's Cline
API access set to Full; in Basic mode the cloud-session list is empty and the
Hub upgrade is denied.

Non-PAC Cline clients must be launched with the explicit compatibility profile
described in the guest guide; normal direct-by-default activation is not enough
to use their fake credentials.

The environment includes `FZ_HOST`, `FZ_BROKER`, and both `NO_PROXY`/`no_proxy`
with the broker host, loopback addresses, and the GCE metadata/link-local
exclusions listed above.
`FZ_PROXY` names the explicit proxy; `FZ_PAC_URL` names the live selective PAC;
`FZ_PROXY_HOSTS` records the setup-time escrow host snapshot. These do not
implicitly configure standard environment-only HTTP clients.
Existing exclusions from both cases are merged without duplicates. This
keeps guest Cline hub requests on guest loopback instead of sending them to
the host proxy. `GIT_SSL_CAINFO` and other runtime CA variables are included.
On Kali/Debian/Ubuntu, Linux setup uses a narrow `sudo` step to install the exact
Friendzone root in the native system trust store and run
`update-ca-certificates`, with ownership checks, safe rotation, and rollback on
refresh failure. Programs compiled with private WebPKI-only roots must enable
native roots or accept an explicit custom CA; the OS cannot replace roots
embedded in a binary. Windows setup also makes Git's Schannel backend honor that
PEM using the scoped `http.schannelUseSSLCAInfo=true` environment config; it does
not disable TLS verification or edit user Git config files. It installs the CA
in the current user's Trusted Root store, not the machine-wide store.
Cargo receives the same PEM through its native `CARGO_HTTP_CAINFO` setting. On
Windows, Cargo revocation lookup is disabled because Friendzone's dynamic leaf
certificates have no public CRL/OCSP responder; all other TLS verification stays
enabled.
After updating an old env file, source it and restart guest processes that
inherited the old environment. These exclusions are not a security boundary.

Substitution requires an exact fake match on a pinned host: a random
key passes through untouched, and a fake sent toward any non-pinned
host is blocked as an attempted leak. Non-credential headers (e.g.
`anthropic-beta` feature flags, `anthropic-version`, `X-Task-ID`) pass
through untouched.

## Current scope

Working now: persistent container approval/IP pins/Kill, a searchable
10,000-event in-memory log, CONNECT interception and credential substitution;
parsed GitHub GraphQL reads, one-shot write review with desktop notifications,
reviewed durable Git branch-bundle publication, and narrow per-guest issue/PR
comment permissions; per-guest Cline API access (basic/full) with API key
management always denied; live MCP configuration,
tool/guest allowlists and host-side OAuth; OAuth-only Cline sign-in and token refresh;
script-only guest setup with persistent Linux profiles or Windows user
environment. Settings is organized into Guests, Credentials and MCP servers.

Not yet: shared/NATed-address guest identity,
general rulesets, transparent/direct `git push`, on-disk proxy logs, stdio MCP
forwarding, automatic Hyper-V/tart network provisioning,
general DNS-rebinding/LAN protection, or termination of already-forwarded
connections when Kill is pressed. Guest egress enforcement remains external.
