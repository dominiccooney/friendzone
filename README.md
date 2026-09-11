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

## Containers

Containers are dynamic; the launch command never names them. A container
is identified by the username in its proxy credentials. **Unknown
containers are denied**: first contact (traffic or the guest setup script) creates a
join request in the Inbox, and nothing flows until you approve it —
"Approve + pin IP" also locks the name to the address it connected
from, so containers cannot use each other's names. Pins are editable
under **Settings → Guests** (Pin…; empty = any address). The advanced
**Set up guest → Preapprove a name** option pre-approves a name (wildcard
address) before its VM boots; it does not install or configure the guest. Kill/Resume
stops traffic reversibly; Remove forgets the container (its log rows
remain for audit).

Inbox is for decisions: pending requests, guest joins, then recent outcomes.
Approved/killed guests and saved comment permissions live under
**Settings → Guests**, alongside the single expandable **Set up guest** flow.
The guest list reports **Approved** or **Killed**; actionable joins appear only
in Inbox as **Awaiting approval**.
These describe network authorization, not whether an agent is working, idle,
or online. Last observed guest traffic is shown separately; administrative
actions do not count as traffic. The selected Inbox/Log/Settings tab is
remembered in this browser for the same UI origin.

Approvals, IP pins, and kill state are saved atomically in `containers.json`
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

The script saves the CA, proxy/loopback exclusions and fake credentials, merges
Cline provider settings, and persists user configuration. Linux gets idempotent
profile hooks; Windows gets user-scoped environment values. Close guest Cline
before running the script because it updates that application's settings, then
restart Cline from the activated environment.

The former setup subcommand is removed. Existing guest environment files and
profile hooks are reused. See [GUEST-BOOTSTRAP.md](GUEST-BOOTSTRAP.md) for the
script endpoints, persistence details, trust model and rollback.

## Try the proxy locally

Start the broker, then in another shell:

```powershell
curl.exe --proxy http://reviewer:demo@127.0.0.1:8080 `
  --cacert "$env:LOCALAPPDATA/friendzone/friendzone-ca.pem" `
  https://example.com/
```

The request appears under the `reviewer` container in the UI and request log.
The UI kill button rejects subsequent requests from that container until
resumed.

## GitHub policy

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

Git must actually supply the fake token as its HTTPS password (through a
credential helper or prompt). Exporting `GITHUB_TOKEN` alone does not make
plain Git use it. The guest bootstrap does not install a Git credential
helper; do not put the real token in the guest. No global Git configuration
is changed by the broker.

`GET .../info/refs?service=git-receive-pack` is push-service **discovery**, not
a write. GitHub can return `401` with a Basic challenge before Git retries
with credentials, even on a public repository. The log's `allowed` verdict
means Friendzone forwarded the request; its HTTP status is GitHub's response.
**This auth support does not enable branch pushes:** the subsequent binary
`POST .../git-receive-pack` is still blocked. Creating a PR through the API
therefore still requires an already-published head branch.

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
permissions still apply, and creating a PR does not unblock binary git pushes.
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

The queue is memory-only: 32 requests globally, 8 per guest, 64 KiB per body,
16 KiB of headers and 8 KiB of URL, with a 10-second upload and 120-second
decision deadline. Compressed, binary, multipart/form and git push payloads
remain blocked because this UI cannot faithfully review them. Kill,
removal, approval/pin changes, expiry, or cancellation of the waiting HTTP
handler end the pending request; restart never replays it. A permission
change after the final admission check cannot undo already-admitted work.
No general approve-for-session/always rules or MCP write approval are added here.
Other origins remain logged and unpoliced.

**Outcomes in Inbox:** Pending contains only requests needing a decision.
Recent retains the last 100 reviewed requests and their redacted details for
this broker session, separate from the busy traffic log. Open details stay
visible after approval/denial and update live: Approved, Sending, Response
received (with HTTP status), Denied, Expired, Cancelled, Blocked, or Upstream
error. A response is not a claim of application success (GraphQL can report
errors with HTTP 200). Reviewed GraphQL JSON responses up to 64 KiB are
observed as they stream to the guest; a nonempty `errors` array produces a
GraphQL error badge without copying upstream payloads into history. Larger,
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
**Connect guest → Copy Cline configuration** includes the required guest Authorization header.
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

The Windows browser launcher passes URLs as data so OAuth query parameters
are not split at `&`. The sign-in panel retains the complete URL with Open
and Copy actions, plus the registered callback for troubleshooting.

Guests use the generated Basic `Authorization` header, not upstream OAuth.
An old guest Cline entry showing “OAuth required” should be replaced with the
generated transport configuration and have stale `oauth`/`oauthClient`
fields removed. See [QUICKSTART.md](QUICKSTART.md) for recovery steps.

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

For Cline, no key is needed: add the entry with the key field empty,
then click "Sign in with Cline…". The broker uses the device-code flow:
it shows a short code, opens the verification page in the host browser,
and polls in the background until you confirm the code — no callback,
no editor redirect. Tokens are registered with Cline's backend and
auto-refresh from then on.

The guest setup script saves the fakes as `friendzone-env.sh` (or `.ps1` on Windows);
source it in the agent's shell. When the fakes include `CLINE_API_KEY`,
setup also writes `~/.cline/data/settings/providers.json` (the settings
file Cline's CLI, IDE extension, and SDK share) registering the `cline`
provider with the fake key, so Cline inference works in the guest with
no `cline auth`. The write is merge-safe: other providers, the user's
model choice, and `lastUsedProvider` are preserved. The `cline` provider is
switched to a fake static `apiKey` (stale OAuth fields are removed), with
valid v1 store metadata and `tokenSource: "manual"`. Run setup while guest
Cline is stopped. Real OAuth refresh stays in the broker; substitution
adds Cline's `workos:` prefix to broker-owned OAuth access tokens.

The environment includes `FZ_HOST`, `FZ_BROKER`, and both `NO_PROXY`/`no_proxy`
with the broker host plus `localhost`, `127.0.0.1`, `::1`, and `[::1]`.
Existing exclusions from both cases are merged without duplicates. This
keeps guest Cline hub requests on guest loopback instead of sending them to
the host proxy. `GIT_SSL_CAINFO` and other runtime CA variables are included.
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
and narrow per-guest issue/PR comment permissions; live MCP configuration,
tool/guest allowlists and host-side OAuth; Cline sign-in and token refresh;
script-only guest setup with persistent Linux profiles or Windows user
environment. Settings is organized into Guests, Credentials and MCP servers.

Not yet: proxy password validation (identity is name + approval + IP pin),
general rulesets, binary git push review, on-disk logs, OS-secret-store
credentials, stdio MCP forwarding, automatic Hyper-V/tart network provisioning,
general DNS-rebinding/LAN protection, or termination of already-forwarded
connections when Kill is pressed. Guest egress enforcement remains external.
