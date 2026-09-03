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

- **Inbox → Add container** — name it (e.g. `reviewer`); the name is the
  proxy username and the unit of kill/logging.
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
- **Settings → MCP forwards → Connect (OAuth)** — if you configured
  `mcp-forwards.json` (see below), click Connect; log in when the
  browser opens. Done — the session stays on the host and auto-refreshes
  near expiry. Reauthorize/Disconnect from the same row.

Optional, before starting: MCP forwards live in
`%LOCALAPPDATA%\friendzone\mcp-forwards.json` (Windows) or
`~/Library/Application Support/friendzone/` (macOS):

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

Restart the broker after editing it.

## 3. Container: bootstrap

```sh
curl -o fz http://HOST_IP:8082/bootstrap/fz
chmod +x fz
sudo ./fz setup --broker http://HOST_IP:8082 --install
```

This installs the CA into the trust store and writes two files next to
each other (path is printed; typically `~/.config/friendzone/`):

- `friendzone-ca.pem` — the CA for runtimes with their own bundle
- `friendzone-env.sh` — the fake credentials, as `export` lines

If a `CLINE_API_KEY` fake exists, setup also writes
`~/.cline/data/settings/providers.json` registering the `cline`
provider with the fake key — Cline CLI/IDE inference works immediately,
no `cline auth`. Existing Cline settings are merged, never clobbered.

## 4. Container: agent shell environment

```sh
export HTTP_PROXY=http://reviewer:x@HOST_IP:8080
export HTTPS_PROXY=http://reviewer:x@HOST_IP:8080
export NODE_EXTRA_CA_CERTS=~/.config/friendzone/friendzone-ca.pem
export REQUESTS_CA_BUNDLE=~/.config/friendzone/friendzone-ca.pem
. ~/.config/friendzone/friendzone-env.sh    # fake API keys
```

`reviewer` = the container name from step 2; the password is unused
(any value). Then check everything:

```sh
./fz doctor --broker http://HOST_IP:8082 --proxy http://reviewer:x@HOST_IP:8080
```

## 5. Container: point the agent at MCP forwards

Any streamable-HTTP MCP client works; the URL is
`http://HOST_IP:8082/mcp/<name>`. Claude Code example:

```sh
claude mcp add --transport http linear http://HOST_IP:8082/mcp/linear
```

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

## Recap card

| Where     | What                                                              |
|-----------|-------------------------------------------------------------------|
| Host      | `cargo run -- broker --proxy-addr HOST_IP:8080 --ui-addr 127.0.0.1:8081 --bootstrap-addr HOST_IP:8082` |
| Browser   | `http://127.0.0.1:8081` — add container, escrow entries, connect MCP |
| Container | fetch `fz` → `fz setup --install` → export proxy vars + source `friendzone-env.sh` → `fz doctor` |

