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
| bootstrap | `HOST_IP:8082`    | containers (`fz` binary, CA, fakes, MCP)      |

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

- **Containers**: either pre-add one (Inbox → Add container, e.g.
  `reviewer`), or just run `fz setup` in the guest — it appears in the
  Inbox as "awaiting approval"; click **Approve + pin IP** to admit it
  and lock the name to its address. Unknown containers are denied until
  approved.
- **Overview and restarts:** "Approved" means permitted to use the network,
  not "working" or "online". The last traffic timestamp is separate and is
  reset on broker restart. Inbox/Log/Settings selection survives browser
  reloads. Host approval/pin/kill/remove actions are saved in `containers.json`
  under the broker data directory; reuse that directory when restarting.
  Old in-memory approvals require one new approval after upgrading. Pending
  unreviewed joins are not saved and reappear when the guest reconnects.
  A save error leaves the previous policy in effect and appears in the Inbox;
  do not assume a failed Kill succeeded. Invalid saved policy stops startup.
- **Settings → Escrowed credentials** — pick a provider preset
  (Anthropic, Cline, GitHub, or Custom…), paste the real key in the one
  masked field, click Add. Hosts/header/env-var are prefilled by the
  preset; the fake key is broker-generated. The in-UI hint says where to
  get each key (for GitHub: a fine-grained PAT, or just `gh auth
  token`). For Cline, skip the key entirely: add the entry, then click
  "Sign in with Cline…" — a short code appears, the verification page
  opens in your browser, you confirm the code, and the broker picks up
  the tokens in the background and auto-refreshes them. Edit fixes a wrong
  header/host without changing the fake; Delete removes the entry and
  its stored key together.
- **Settings → MCP forwards** — find a server in host Cline or enter its
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
the other required parameters. The fixed launcher passes the whole URL as
data, not shell text. The sign-in panel also offers **Open sign-in page**,
**Copy sign-in URL**, and the registered callback URL for diagnosis. Paste
the full sign-in URL into the host browser address bar, not a terminal.
If the provider still rejects it, compare the callback shown in the panel;
do not substitute the guest MCP endpoint for an OAuth redirect URI.

### Reviewing a GitHub request

GitHub GraphQL queries flow without approval. If a guest submits a GitHub
write (a GraphQL mutation or REST write), keep the
host UI open and go to **Inbox → Requests awaiting review → Review request**.
Inspect the full URL, headers and body, then **Approve once** or **Deny**.
The original HTTP call waits up to two minutes; nothing is replayed on
restart. Approval uses the normal configured credential and requires its
upstream scopes; it does not override GitHub permissions or future requests.

Click **Enable notifications** in Inbox and allow the browser prompt for
desktop alerts. Click an alert to focus Inbox. This works with the UI open
in a background tab on localhost, not after closing the browser. Denied or
unsupported notification permission does not prevent manual review.

PR creation, inline review comments/threads, replies and review submissions
are allowed with **Approve once**, not automatically. Inspect the displayed
head/base branches, body, file/line and review event—`APPROVE` and
`REQUEST_CHANGES` are more than comment text. The host's token needs the
appropriate GitHub write scopes. Binary git pushes are still blocked.

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
Revoke from **Saved comment permissions** in Inbox. Permissions survive
restart and are removed with the guest; token changes need a new grant.
The review panel now parses and formats GraphQL, showing the selected
operation, actual fields (not just aliases), resolved arguments, variables,
and known target paths. `addComment` shows the comment separately from its
`subjectId`. That ID is opaque: it is **not** an issue/PR number. Explicit
`repository(owner, name).pullRequest/issue(number)` arguments are shown with
their repository context; these are unverified request values, not saved
permissions. Unknown targets stay unknown. See [GRAPHQL-REVIEW.md](GRAPHQL-REVIEW.md).
Only inspectable JSON/text or empty-body writes up to 64 KiB are supported;
binary git pushes remain blocked. **If the guest times out, deny its old
pending request before retrying.** Retried requests are separate and may
duplicate a write. See [GitHub policy](README.md#github-policy) for limits,
security boundaries and cancellation details.

## 3. Container: bootstrap

**Preferred: host UI → Settings → Set up a guest.** Choose the guest-reachable
host/name, inspect the script, copy either the Linux (sh/bash/zsh) or Windows
PowerShell command, and run it **in the guest**, with guest Cline stopped.
This downloads the exact matching build and runs setup with persistent guest
configuration. Linux adds profile hooks once; Windows sets user environment,
not machine environment. No sudo, firewall or system trust-store changes.
Start a fresh shell or use the printed activation command; on Windows sign
out/in to refresh GUI launchers. [Full behavior and rollback](GUEST-BOOTSTRAP.md).

The manual path below is useful when no matching guest build is hosted yet.

Cross-OS note: `/bootstrap/fz` is the *host's* binary. On a Linux guest
of a Windows host, build `fz` in the guest instead (needs rust +
build-essential):

```sh
git clone https://github.com/dominiccooney/friendzone
cd friendzone && cargo build --release
sudo ./target/release/fz setup --broker http://HOST_IP:8082 --install
```

On a guest matching the host platform:

```sh
curl -o fz http://HOST_IP:8082/bootstrap/fz
chmod +x fz
sudo ./fz setup --broker http://HOST_IP:8082 --install
```

Running under `sudo` is fine: setup detects the invoking user and
writes the CA, env file, and Cline settings into *their* home
(`~/.config/friendzone/`, `~/.cline/`), owned by them and
readable by that user — only the CA trust-store install needs root.
The CA/env are public; the merged Cline provider file is owner-only.

This installs the CA into the trust store and writes two files next to
each other (path is printed; typically `~/.config/friendzone/`):

- `friendzone-ca.pem` — the CA for runtimes with their own bundle
- `friendzone-env.sh` — the fake credentials, as `export` lines

If a `CLINE_API_KEY` fake exists, setup also writes
`~/.cline/data/settings/providers.json` registering the `cline`
provider with the fake key — Cline CLI/IDE inference works immediately,
no guest OAuth login. Run setup while guest Cline is stopped: model choice,
other providers and last-used choice are preserved, but this provider's
OAuth fields are removed so stale access tokens cannot override the fake.
The v1 store includes `version`, `modes`, UTC `updatedAt`, and a valid
`tokenSource: "manual"`. Older setup output lacked valid metadata, causing
Cline to discard the store; rerun the updated setup to repair it.

## 4. Container: agent shell environment

`fz setup` writes everything — proxy vars (with this guest's identity),
CA bundle vars, and the fake keys — into one file. Activate it:

```sh
. ~/.config/friendzone/friendzone-env.sh
```

The file also exports `FZ_HOST` and `FZ_BROKER`, both proxy-variable cases,
and `NO_PROXY`/`no_proxy` for the broker host and guest loopback:
`localhost`, `127.0.0.1`, `::1`, and `[::1]`. Existing exclusions from both
variables are merged without duplicates. Cline hub health checks and other
guest-local HTTP requests must stay inside the guest, not be sent to the
host proxy's loopback. `GIT_SSL_CAINFO` trusts the intercepted origin certificate;
`GIT_PROXY_SSL_CAINFO` alone was not sufficient for an HTTP proxy.

If you used an older generated env file, update/rebuild the **guest** `fz`,
rerun setup with the same broker/container arguments, and source the new file.
No broker restart or CA reinstall is needed for this environment fix. Restart
the guest Cline CLI/hub (or its service) with the new environment: changing a
shell variable cannot update already-running processes. For an immediate
temporary repair, after sourcing the old file in the guest shell:

```sh
export NO_PROXY="localhost,127.0.0.1,::1,[::1]${NO_PROXY:+,$NO_PROXY}${no_proxy:+,$no_proxy}"
export no_proxy="$NO_PROXY"
```

This is a client-routing fix, not access control: a guest can override it.
Keep the host-enforced network restrictions in place, and do not expose
host-local services through the proxy expecting `NO_PROXY` to protect them.

Add the environment-file source line to the agent's shell profile so it persists.
The served scripts automate that step, or run setup as the normal guest user with
`--persist-profile`. Windows defaults to `friendzone-env.ps1` and persists
user environment; `-NoProfile` processes inherit it from fresh launchers. The
container identity defaults to the guest hostname; pass
`--container reviewer` to `fz setup` to match a name you added in the
UI. Then check everything:

```sh
./fz doctor --broker http://HOST_IP:8082 --proxy http://reviewer:x@HOST_IP:8080
```

Doctor checks broker health **directly**, ignoring proxy environment
variables. Its proxy reachability check is **TCP only**: a pass does not
verify container approval, proxy forwarding, or CA trust. If setup says
"awaiting approval", open the **host's** UI at <http://127.0.0.1:8081> and
approve the container in the Inbox before trying agent traffic.

### Troubleshooting: doctor reports 403 after sourcing the env file

Older builds sent even the broker health check through `HTTP_PROXY`, so
an unapproved container produced a misleading "broker reachable" failure.
Compare the direct and proxied paths (use your actual container name):

```sh
# Expect HTTP 200 and "ok", even before approval.
curl --noproxy '*' -i http://HOST_IP:8082/health

# A 403 body explains the proxy denial: pending approval, wrong IP pin, etc.
curl --noproxy '' --proxy http://reviewer:x@HOST_IP:8080 -i http://HOST_IP:8082/health
```

Approve the name in the host Inbox; if already approved, check its IP pin
and Kill/Resume state. Rebuild the guest binary with `cargo build --release`
after updating it to include the fix. `fz setup` also contacts the broker
directly, so rerunning setup after sourcing the env works before approval.
There is no need to disable TLS verification or globally bypass the proxy.

## 5. Container: point the agent at MCP forwards

In the host UI, each MCP server card has **Copy URL** next to its
guest-facing URL; copying it requires no guest selection. The upstream URL
is Linear's (or another provider's) server, not the URL to add in guest Cline.
Use **Settings → MCP forwards → Copy Cline setup** for
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
Use a streamable-HTTP MCP client with explicit guest Basic authorization.
The endpoint is `$FZ_BROKER/mcp/<name>`; proxy credentials are not a
substitute for its `Authorization` header. Cline guest settings example
(replace the URL and choose the matching guest name; the base64 below is
`scratch-kali:x`, not a secret):

```json
{
  "mcpServers": {
    "linear-via-friendzone": {
      "transport": {
        "type": "streamableHttp",
        "url": "http://172.31.208.1:8082/mcp/linear",
        "headers": { "Authorization": "Basic c2NyYXRjaC1rYWxpOng=" }
      }
    }
  }
}
```

Approval, IP pinning, kill state, forward guest allowlist, and tool allowlist
all apply. No upstream credential is given to the guest.

### Guest Cline says “requires OAuth authorization”

That can be a missing guest `Authorization` header, not missing Linear OAuth.
Older Friendzone returned 401 for missing Basic credentials, which Cline
interprets as an OAuth server. The current broker returns a clear 403 instead.
Copy the whole guest configuration from **Connect from Cline**, including
the header, not just the URL. If reusing an old Cline entry, remove its
`oauth` and `oauthClient` fields (or add the generated entry under its new
name), then reconnect. Do not run `authorizeMcpServerOAuth` for Friendzone
inside the container. Authorize the **upstream** in the host Friendzone UI.
Forward paths are case-sensitive: `Linear` uses `/mcp/Linear`.

## 6. Smoke test — what should happen

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
| Browser   | `http://127.0.0.1:8081` — add container, escrow entries, connect MCP |
| Container | fetch `fz` → `fz setup --install` → export proxy vars + source `friendzone-env.sh` → `fz doctor` |

