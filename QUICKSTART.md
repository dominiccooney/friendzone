# Friendzone quickstart

Cheat sheet: host first, then browser, then inside the container.
`HOST_IP` below is the host's address on the VM-facing interface.

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

## 2. Browser: open the UI and configure once

Open <http://127.0.0.1:8081>.

- **Containers**: either pre-add one (Inbox → Add container, e.g.
  `reviewer`), or just run `fz setup` in the guest — it appears in the
  Inbox as "awaiting approval"; click **Approve + pin IP** to admit it
  and lock the name to its address. Unknown containers are denied until
  approved.
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
- **Settings → MCP forwards** — add a streamable-HTTP server or preview
  a host Cline MCP settings file, select a server, **Validate / discover
  tools**, then explicitly select allowed tools and guests. **Add forward
  & apply live** does not restart the broker. For standalone OAuth servers,
  use the advanced editor to add the forward, then Connect (OAuth).

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
    "bearer_env": "FZ_LINEAR_TOKEN",
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
headers/access tokens per request, and does not copy secrets or execute
commands. Cline retains OAuth refresh ownership: reconnect/refresh in host
Cline when needed. Removing/disabling the source or changing its URL fails
closed until reviewed. Stdio and SSE entries are explicitly unsupported.

## 3. Container: bootstrap

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
and `NO_PROXY`/`no_proxy` for the broker host only (preserving existing
exclusions). `GIT_SSL_CAINFO` trusts the intercepted origin certificate;
`GIT_PROXY_SSL_CAINFO` alone was not sufficient for an HTTP proxy.

Add that line to the agent's shell profile so it persists. The
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

