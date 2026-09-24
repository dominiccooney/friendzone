# Friendzone quickstart

Cheat sheet: host first, then browser, then inside the container.
`HOST_IP` below is the host's address on the VM-facing interface.

**Before untrusted workloads:** this quickstart configures applications,
not VM confinement. Read [Network isolation and recovery](NETWORK-ISOLATION.md).
Build/test a clean image first, then enforce egress outside the guest: only
the broker's proxy and bootstrap/MCP ports, never the UI or other egress.
Keep host-console recovery available; do not lock down via your only SSH
connection or reopen Internet access for a potentially compromised guest.

## 1. Host: start the broker

```powershell
cd friendzone
cargo run -- broker --proxy-addr HOST_IP:8080 --ui-addr 127.0.0.1:8081 --bootstrap-addr HOST_IP:8082
```

Local demo without a VM? Use `127.0.0.1` everywhere `HOST_IP` appears.

| Listener  | Address           | Who uses it                                   |
|-----------|-------------------|-----------------------------------------------|
| proxy     | `HOST_IP:8080`    | containers (HTTP/HTTPS via `HTTP(S)_PROXY`)   |
| UI        | `127.0.0.1:8081`  | you, in the host browser                      |
| bootstrap | `HOST_IP:8082`    | guests (setup scripts, CA, fakes, MCP)         |

The broker rejects non-loopback UI binds and proxy traffic to its management
port. Proxied loopback destinations (including `127.0.0.1`, `localhost`, and
`::1`) are also denied except on the configured bootstrap port. A misplaced
guest hub health probe returns 403, not the host hub's response. Keep
`NO_PROXY`/`no_proxy` and restart stale guest clients to stop these probes
reaching the proxy in the first place. Host/switch policy is still required.
Hyper-V's Default Switch/NAT is convenient for clean-image setup but is not
isolation; the linked guide uses
a dedicated internal switch, static addresses, and explicit port ACLs.

## 2. Browser: open the UI and configure once

Open <http://127.0.0.1:8081>.

- **Guests**: open **Settings → Guests → Set up guest** and run the script
  in the guest — it appears in the
  Inbox as "awaiting approval"; click **Approve + pin IP** to admit it
  and bind the policy name to its unique source address. Unknown containers are
  denied until approved. Credential-free proxy/MCP/job access requires this
  explicit pin. Manual name preapproval is an advanced option inside the same
  setup flow; set a unique Pin before using it for runtime access.
- **Management and restarts:** approved/killed guests, Kill/Resume, Pin,
  Remove and saved comment permissions are in **Settings → Guests**.
  "Approved" means permitted to use the network,
  not "working" or "online". The last traffic timestamp is separate and is
  reset on broker restart. Inbox/Log/Settings selection survives browser
  reloads. Host approval/pin/kill/remove actions are saved in `containers.json`
  under the broker data directory; reuse that directory when restarting.
  Old in-memory approvals require one new approval after upgrading. Pending
  unreviewed joins are not saved and reappear when the guest reconnects.
  A save error leaves the previous policy in effect and appears beside the action;
  do not assume a failed Kill succeeded. Invalid saved policy stops startup.
- **Settings → Escrowed credentials** — pick a provider preset
  (Anthropic, Cline, GitHub, or Custom…), paste the real key in the one
  masked field, click Add. Hosts/header/env-var are prefilled by the
  preset; the fake key is broker-generated. The in-UI hint says where to
  get each key (for GitHub: a fine-grained PAT, or just `gh auth
  token`). For Cline, skip the key entirely: add the entry, then click
  "Sign in with Cline…" — a short code appears, the admin page opens the
  verification page in your current browser, you confirm the code, and the
  broker picks up
  the tokens in the background and auto-refreshes them. Edit fixes a wrong
  header/host without changing the fake; Delete removes the entry and
  its stored key together. Rerun guest setup after sign-in: it then writes a
  worthless OAuth-shaped facade into guest Cline settings, allowing account and
  Cloud UI to recognize sign-in without copying access or refresh credentials.
  Cloud Hub connections also require a guest Cline build with proxy-aware
  `ws:`/`wss:` support.
- **Settings → MCP servers** — find a server in host Cline or enter its
  name and upstream URL. **Add & authorize** creates it and starts host
  sign-in in one step. Complete login, then **Next: choose tools and guests**
  and **Save guest access**. Until that last step, a new server is private
  (not shared with any guest). For existing servers, use **Authorize in
  Friendzone** and **Choose tools and guests** on their card. Cancelling
  login does not delete the server; retry from its card. No settings change
  here requires restarting the broker.

Optional, before starting: MCP forwards live in `mcp-forwards.json` in
the broker data directory — the broker prints the exact path at startup
("Friendzone data: …"), and the Settings page shows it too. Defaults:
`%LOCALAPPDATA%\friendzone\` (Windows),
`~/Library/Application Support/friendzone/` (macOS),
`~/.local/share/friendzone/` (Linux):

```json
[
  {
    "name": "linear",
    "url": "https://mcp.linear.app/mcp",
    "oauth": true,
    "scope": "read",
    "tools": ["list_issues", "get_issue", "list_comments"]
  }
]
```

Use **Save & apply** in the UI, or **Reload from disk** after an external
edit. Neither restarts the broker. Invalid configurations leave the active
forwards untouched; unchanged upstream sessions survive permission edits.
New requests use new permissions; already admitted calls finish under the
old snapshot. Add `"guests": ["scratch-kali"]` to restrict a forward;
`"guests": []` denies everyone, while omitted/null retains legacy sharing
with all approved guests. An empty `tools` list denies all tool calls.

Cline import accepts nested `transport.type: "streamableHttp"` and legacy
streamable-HTTP entries. The path is prefilled from the broker user's Cline
settings location, honoring `CLINE_MCP_SETTINGS_PATH`, `CLINE_DATA_DIR`,
and `CLINE_DIR` in that order; edit it for another profile. It links the
**absolute host path**, reads current
headers/access tokens per request when using the optional Cline credential
link. That link leaves refresh ownership in Cline. The recommended OAuth
mode is **Authorize in Friendzone**: it creates a separate broker-owned
session, never copies Cline's refresh token, and no longer reads Cline's
credentials. Existing tool/guest permissions and Cline's own setup remain
unchanged. Stdio and SSE entries are explicitly unsupported.

Friendzone MCP OAuth supports protected-resource discovery (including the
WWW-Authenticate metadata hint), authorization-server metadata, dynamic
public-client registration, PKCE S256, the `resource` parameter, and
serialized token refresh with one retry after upstream 401. Tokens are
bound to the exact upstream URL and stored atomically on the host; a changed
URL, disconnect, removed forward, expired/replayed callback, or superseded
login cannot restore old credentials. Permission edits preserve the session.
The browser callback requires a loopback UI listener. Servers requiring
pre-registered/confidential clients are not supported by this flow yet.
Legacy broker OAuth sessions without URL binding require reauthorization.

### Sign-in opens a URL ending at `?response_type=code`

Older Windows builds opened OAuth URLs with `cmd /C start`, which treated
`&` query separators as command separators and dropped `redirect_uri` and
the other required parameters. The admin UI now opens the complete URL in
its browser instead of asking the broker host to launch one. The sign-in panel
also offers **Open sign-in page**, **Copy sign-in URL**, and the registered
callback URL for diagnosis. Paste the full sign-in URL into the browser
displaying Friendzone, not a terminal.
If the provider still rejects it, compare the callback shown in the panel;
do not substitute the guest MCP endpoint for an OAuth redirect URI.
When the broker is remote, forward the loopback UI port (8081 by default) to
the machine running that browser so the registered MCP callback reaches it.

### Reviewing a GitHub request

GitHub GraphQL queries flow without approval. If a guest submits a GitHub
write (a GraphQL mutation or REST write), keep the
host UI open and go to **Inbox → Requests → Review**.
Review the visible action, target and input values, then **Approve once** or
**Deny**. Nested and unknown input values are expanded; response-only fields,
headers and the exact raw representation remain available separately.
The original HTTP call waits up to two minutes; nothing is replayed on
restart. Approval uses the normal configured credential and requires its
upstream scopes; it does not override GitHub permissions or future requests.

Prefer the [async Cline plugin](ASYNC-GRAPHQL.md) for manual approval or large
GraphQL payloads. Rerun guest setup and restart guest Cline to install it.
It returns immediately and delivers completion to the originating session.

If proxy reviews cancel after 25–30 seconds rather than expire at two minutes,
check the guest HTTP client's timeout and its enclosing command/tool deadline.
Both must leave time for a human decision (e.g. 180 seconds). The broker cannot
keep a client waiting after it disconnects. Check the outcome and upstream
state before retrying a write; don't replay a possibly completed mutation.

Click **Enable notifications** in Inbox and allow the browser prompt for
desktop alerts. Click an alert to focus Inbox. This works with the UI open
in a background tab on localhost, not after closing the browser. Denied or
unsupported notification permission does not prevent manual review.

PR creation, inline review comments/threads, replies and review submissions
are allowed with **Approve once**, not automatically. Inspect the displayed
head/base branches, body, file/line and review event—`APPROVE` and
`REQUEST_CHANGES` are more than comment text. The host's token needs the
appropriate GitHub write scopes. Ordinary direct `git push` remains blocked.

Guest setup configures Git HTTPS to use the **fake** `GITHUB_TOKEN` automatically
for exact `https://github.com` origins. Friendzone substitutes it inside HTTP
Basic credentials while preserving the username and host restriction. An initial
`401` on `info/refs?service=git-receive-pack` is GitHub's authentication challenge,
not a Friendzone read-policy denial.
Authenticating discovery does not unblock ordinary `git push`. Publish a PR head
branch with the reviewed bundle tool below. See [Git authentication](README.md#git-https-authentication).

After rerunning setup and starting a fresh shell/Cline, ordinary commands work:

```sh
git fetch origin main
git lfs fetch origin HEAD
```

The managed helper file contains no token value. It clears stale helpers and
reads the fake environment token only for exact HTTPS `github.com`; it returns
nothing for other origins. Git propagates it to `git-lfs`. Friendzone allows only
strict LFS download batches; LFS uploads remain blocked. Never print
`GITHUB_TOKEN`, put it in a URL, or use the host's real token in the guest.

### Publish a branch for a PR

Rerun guest setup and restart guest Cline so it has
`friendzone_submit_git_bundle`. In the guest, create a version-2 bundle for one
linear branch based directly on the current remote base:

```sh
git fetch origin main
base=$(git rev-parse origin/main)
git bundle create --version=2 "$PWD/feature.bundle" refs/heads/feature "^$base"
```

Call `friendzone_submit_git_bundle` with the absolute bundle path,
`repository=owner/repo`, `branch=feature`, `base_oid=$base`, forty zeroes as
`expected_oid`, and a human-readable `request_key`.

The tool returns `preparing`; do not resubmit. Friendzone validates the exact
bundle, then the host Inbox shows commit messages, paths, OIDs, digest, and patch.
After **Approve once**, the broker rechecks the remote and publishes once with a
creation lease. Use `friendzone_get_request` for the verified result. For updates,
use the exact current target SHA as `expected_oid`. For a normal update it is also
the bundle prerequisite and `base_oid`. For a rebase onto `main`, capture
the remote target SHA before rebasing, use the actual `origin/main` commit you
rebased onto as the bundle's sole prerequisite and `base_oid`. No named base branch
is required. Friendzone fetches that exact commit from the repository and uses the
captured target SHA as the exact force-with-lease.

Routine completed jobs need no cleanup: after Cline durably checkpoints a completion
message, Friendzone may rotate the oldest acknowledged history when admitting new
work. It never automatically removes active work or uncertain outcomes.

Do not retry an uncertain submission or result blindly. List/get existing jobs
and inspect the remote branch first. Ordinary `git push`, unleased updates, tags,
deletes, merges, LFS uploads, multiple refs, and arbitrary remotes remain unsupported.

Queries use the actual parsed `query` operation, including fragments and
introspection. Ambiguous operation selection, unsupported directives/headers,
URL query parameters and malformed requests still require review or fail
closed. No query-body/field allowlist is needed on the supported transport.

For an eligible
single `addComment` using Friendzone's fake GitHub Bearer token:

1. Open the request and click **Resolve GitHub target**.
2. Inspect the verified repository, issue/PR number, title and credential.
3. Click **Allow future comments here** and confirm the guest/target scope.
4. Approve or deny the current waiting request separately.

Later supported comments on that target can have different text and need no
new approval; the broker rechecks GitHub and reconstructs a narrow mutation.
Other targets, bundled mutations or unsupported fields/headers still queue.
Revoke from **Settings → Guests → Saved comment permissions**. Permissions survive
restart and are removed with the guest; token changes need a new grant.
The review panel now parses and formats GraphQL, showing the selected
operation, actual fields (not just aliases), resolved arguments, variables,
and known target paths. `addComment` shows the comment separately from its
`subjectId`. That ID is opaque: it is **not** an issue/PR number. Explicit
`repository(owner, name).pullRequest/issue(number)` arguments are shown with
their repository context; these are unverified request values, not saved
permissions. Unknown targets stay unknown. See [GRAPHQL-REVIEW.md](GRAPHQL-REVIEW.md).
Only inspectable JSON/text or empty-body writes up to 64 KiB are supported on the
synchronous proxy path; ordinary binary git pushes remain blocked. **If the guest times out, deny its old
pending request before retrying.** Retried requests are separate and may
duplicate a write. See [GitHub policy](README.md#github-policy) for limits,
security boundaries and cancellation details.

## 3. Guest: download and run the setup script

In **Settings → Guests → Set up guest**, select the guest platform and name. The UI supplies
a short curl download command and a separate run command. Run both in the
guest, not the host. Linux uses Python 3's standard library; Windows uses
PowerShell. Neither needs an fz binary or Rust compiler.

For example, in a Linux guest:

```sh
curl --noproxy '*' -fsS 'http://HOST_IP:8082/bootstrap/setup?shell=sh&container=reviewer' -o friendzone-setup.sh
sh ./friendzone-setup.sh
```

If the Windows guest needs a Rust toolchain, install the
[Visual C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
prerequisite and Rust **before** running Friendzone setup. The Build Tools
bootstrapper's WinINet downloader does not work through the Friendzone proxy.
On an already-configured guest, temporarily disable the current-user WinINet
proxy while installing Build Tools, then restore its exact previous state
immediately afterward. Use the complete procedure in
[Windows Build Tools and Rust](GUEST-BOOTSTRAP.md#windows-build-tools-and-rust).
Do this only during trusted image provisioning, before the guest runs untrusted
work; do not reopen direct egress for a potentially compromised guest.

Then, in Windows guest PowerShell:

```powershell
curl.exe --noproxy "*" -fsS 'http://HOST_IP:8082/bootstrap/setup?shell=powershell&container=reviewer' -o friendzone-setup.ps1
& .\friendzone-setup.ps1
```

Friendzone dynamically issues HTTPS leaf certificates as a MITM proxy, but those
certificates have no public CRL/OCSP revocation responder. Windows clients that
require an online revocation check can therefore reject otherwise valid
Friendzone certificates. In the Windows guest, run the following from
PowerShell:

```powershell
inetcpl.cpl
```

In **Internet Properties**, open **Advanced → Security**, uncheck **Check for
server certificate revocation**, select **Apply**, and close the dialog. Restart
clients that were already running. This changes the Windows Internet setting for
the guest user and disables revocation checks for affected clients; CA-chain,
expiry, and hostname verification remain enabled. Use this only in the isolated,
Friendzone-managed guest—not on the broker host.

Without this setting, WinGet package downloads through Friendzone can fail like
this:

```text
PS C:\Users\qauser> winget install --id Git.Git -e --source winget
Found Git [Git.Git] Version 2.55.0.3
Downloading https://github.com/git-for-windows/git/releases/download/v2.55.0.windows.3/Git-2.55.0.3-64-bit.exe
An unexpected error occurred while executing the command:
InternetOpenUrl() failed.
0x80072f19 : unknown error
```

`0x80072f19` is WinINet error `12057`
(`ERROR_INTERNET_SEC_CERT_REV_FAILED`): certificate revocation checking failed.

The script updates the guest's Cline provider file, so close guest Cline before
running it. Existing model/other-provider settings are retained. Real keys
stay on the host. Download scripts only over a trusted host/network; the first
HTTP download is not authenticated. The script does not change the guest's
firewall. Runtime CA variables are configured on both platforms. On
Kali/Debian/Ubuntu, setup invokes `sudo` only to install the Friendzone root in
the native system trust store and run `update-ca-certificates`; run the setup
script itself as the guest user. On Windows it
also installs the exact Friendzone CA in the guest user's Trusted Root store
(`CurrentUser\Root`, not `LocalMachine\Root`) and makes Git's Schannel backend honor `GIT_SSL_CAINFO` without
disabling certificate verification or changing Git configuration files, and
sets Cargo's native `CARGO_HTTP_CAINFO` to the same managed CA bundle. Cargo's
Windows-only revocation lookup is disabled because dynamically issued
Friendzone certificates have no public revocation responder; chain and hostname
verification remain enabled.
It also configures the current user's Windows Internet proxy so WinINET-aware and
modern .NET clients can route through Friendzone without relying on environment
variables. Existing bypass entries are preserved. This is not machine-wide
WinHTTP configuration. Setup tracks roots it installed, rotates only those roots,
and removes only those exact roots during rollback. Restart applications that
cache proxy or trust settings.

## 4. Guest: activate and approve

Linux prints an activation command; source it in the current terminal or open
a new login shell. Managed hooks persist across bash/zsh starts without being
added again on reruns. Zsh reads .zshenv for non-interactive shells; bash uses
BASH_ENV inherited from an activated parent. Plain sh and service launchers
need explicit environment inheritance.

Windows activates its PowerShell process, saves user environment variables, sets
the current-user Windows Internet proxy, and trusts the CA in `CurrentUser\Root`.
Restart guest applications; sign out/in for other Windows launchers to acquire
a fresh environment. Machine environment, WinHTTP, and execution policy are unchanged.

Approve/pin the guest in the host Inbox, then restart guest Cline. The generated
environment includes broker and loopback NO_PROXY entries, both proxy cases on
Linux, fake provider keys and runtime CA paths. Linux setup also installs the
native root. A Rust binary compiled with WebPKI-only roots must still be rebuilt
with native-root support; system configuration cannot alter roots embedded in a
binary. See
[GUEST-BOOTSTRAP.md](GUEST-BOOTSTRAP.md) for rollback and persistence details.

Read-only checks (use your guest name):

```sh
curl --noproxy '*' -i http://HOST_IP:8082/health
curl --noproxy '' --proxy http://HOST_IP:8080 -i http://HOST_IP:8082/health
```

The first should return 200 before approval. The second requires **Approve + pin
IP** and should then return 200. A 403/407 explains pending approval, Kill,
missing/ambiguous pin, or source-IP mismatch. Do not disable TLS verification.

## 5. Diagnose a timeout (optional)

Start the portable Jaeger viewer and traced Friendzone from the host repository:

```cmd
tools\trace-viewer.cmd Broker -BrokerAddress HOST_IP
```

Then, from an activated and approved guest:

```sh
curl --noproxy '*' -fsS "$FZ_BROKER/bootstrap/trace-command.sh" -o trace-command.sh
sh ./trace-command.sh cline --verbose --timeout 0 "minimal prompt that reproduces the timeout"
```

The wrapper takes a complete command: it does not insert `cline` or flags. It can
also run `node script.cjs`, `cline --help`, or any other executable. Every
command gets an outer duration/exit span; Node-based commands additionally get
HTTP/Undici spans. Open <http://127.0.0.1:16686> and select **cline-guest**. Trace
batches use Friendzone's existing bootstrap port; Jaeger remains host-loopback
only and no firewall exception is added. See
[Trace commands and Cline proxy timeouts](TRACING.md) for export and interpretation.

If the wrapper reports an invalid tracing asset, the host is still running an
older broker. Stop it, start the `Broker` command above, redownload the wrapper,
and retry. The completed one-time package install is reused.

## 6. Container: point the agent at MCP forwards

In the host UI, each MCP server card has **Copy URL** next to its
guest-facing URL; copying it requires no guest selection. The upstream URL
is Linear's (or another provider's) server, not the URL to add in guest Cline.
Use **Settings → MCP servers → Connect guest → Copy Cline configuration** for
the guest endpoint and copyable Cline JSON for each forward. Select the
guest and merge the generated entry into its Cline MCP settings; do not
overwrite other servers. The broker host/port default comes from the
bootstrap listener, not the UI address. For wildcard binds enter the host
IP/DNS name reachable from the guest. The panel warns about missing
approval, sharing, tools, killed guests and loopback-only listeners;
generating/copying a configuration does not grant access.

**Uses host Cline's credentials** means Friendzone reads the token saved by
host Cline and relies on Cline to refresh it. **Authorize in Friendzone**
switches the forward to an independent broker-owned OAuth session. Neither
mode requires an upstream OAuth login in the guest. If the browser still
shows the old “Cline link” wording after updating/restarting the broker,
reload the page (hard-refresh if necessary).

There is **one endpoint per forwarded server**, not one combined endpoint.
Use a streamable-HTTP MCP client from the uniquely IP-pinned guest. The endpoint
is `$FZ_BROKER/mcp/<name>`; no guest Authorization header is needed. Cline guest
settings example:

```json
{
  "mcpServers": {
    "linear-via-friendzone": {
      "transport": {
        "type": "streamableHttp",
        "url": "http://172.31.208.1:8082/mcp/linear"
      }
    }
  }
}
```

Approval, IP pinning, kill state, forward guest allowlist, and tool allowlist
all apply. No upstream credential is given to the guest.

### Guest Cline says “requires OAuth authorization”

That can be a missing or ambiguous source-IP pin, not missing Linear OAuth.
Older Friendzone required a Basic guest header, which Cline could interpret as
an OAuth challenge. Replace the old transport with the credential-free entry
from **Connect guest**, removing `Authorization`, `oauth`, and `oauthClient`
fields. Do not run `authorizeMcpServerOAuth` for Friendzone inside the container.
Authorize the **upstream** in the host Friendzone UI.
Forward paths are case-sensitive: `Linear` uses `/mcp/Linear`.

## 7. Smoke test — what should happen

From the container (or the host with `127.0.0.1`):

```sh
# GitHub read: flows (verdict "allowed" in the log)
curl https://api.github.com/repos/cline/cline

# GitHub write: 403 with "GitHub writes are gated..."
curl -X POST https://api.github.com/repos/x/y/issues/1/comments -d '{}'

# Inference: fake key goes in, real key substituted at the broker
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -d '{"model":"claude-sonnet-4-5","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}'

# Leak canary: fake key toward any other host is blocked
curl https://example.com/ -H "x-api-key: $ANTHROPIC_API_KEY"   # 403
```

Watch it all live at <http://127.0.0.1:8081> → Log. Kill/Resume the
container from Inbox.

The log retains 10,000 application events in memory, with server-side
search and **Older matches** pagination. Counts show eviction; restart
clears history. Successful CONNECT handshakes and normal 407 challenges
are omitted, while authorization/policy denials carry a status and reason.
Git's initial anonymous proxy probe now receives 407 (not a new IP-named
guest); its authenticated CONNECT is intercepted, and decrypted Git reads
flow while writes remain gated.

## Recap card

| Where     | What                                                              |
|-----------|-------------------------------------------------------------------|
| Host      | `cargo run -- broker --proxy-addr HOST_IP:8080 --ui-addr 127.0.0.1:8081 --bootstrap-addr HOST_IP:8082` |
| Browser   | `http://127.0.0.1:8081` — Inbox for decisions; Settings for guests, credentials and MCP |
| Guest     | Settings → Guests → Set up guest → curl script → run → activate → Approve + pin IP in host Inbox |

