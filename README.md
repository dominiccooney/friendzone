# Friendzone

The `fz` binary provides a local HTTPS-intercepting proxy with GitHub
read/write policy, credential escrow with exact-fake substitution, MCP
forwarding with host-side OAuth, certificate bootstrap, request log,
and a web UI with settings.

New here? See [QUICKSTART.md](QUICKSTART.md) for the run-this-open-that
cheat sheet.

## Run the broker

One broker serves any number of containers:

```powershell
cargo run -- broker --proxy-addr HOST_VNIC_IP:8080 --ui-addr 127.0.0.1:8081 --bootstrap-addr HOST_VNIC_IP:8082
```

Open <http://127.0.0.1:8081>. The CA certificate and private key are created
under the operating system's local application-data directory in
`friendzone/`. The private key is never served by the bootstrap endpoint.

## Containers

Containers are dynamic; the launch command never names them. A container
is identified by the username in its proxy credentials, and appears in
the UI the moment it first connects. You can also add one ahead of time
(Inbox → "Add container") so its section exists before the VM boots, and
remove one after tearing down its VM (its log rows remain for audit).
Kill/Resume stops a container's traffic reversibly; Remove forgets it.
Give every container a distinct username — it is the unit of identity,
logging, and the kill switch.

## Set up a guest

The broker also exposes its current-platform binary at
`http://HOST_IP:8082/bootstrap/fz`. On a matching guest:

```text
curl -o fz http://HOST_IP:8082/bootstrap/fz
chmod +x fz                  # Unix guests
./fz setup --broker http://HOST_IP:8082 --install
```

For a guest with a different OS or architecture, copy an appropriate `fz`
build into the VM, then run:

```text
fz setup --broker http://HOST_IP:8082 --install
```

Without `--install`, setup saves the certificate and prints manual and
per-runtime instructions. Installation may require an elevated shell.

Configure the explicit proxy with per-container credentials:

```text
HTTP_PROXY=http://reviewer:CHANGE_ME@HOST_IP:8080
HTTPS_PROXY=http://reviewer:CHANGE_ME@HOST_IP:8080
```

For runtimes that use their own CA bundle, point them at the downloaded file:

```text
NODE_EXTRA_CA_CERTS=/path/to/friendzone-ca.pem
REQUESTS_CA_BUNDLE=/path/to/friendzone-ca.pem
```

Check the setup:

```text
fz doctor --broker http://HOST_IP:8082 \
  --proxy http://reviewer:CHANGE_ME@HOST_IP:8080
```

`fz doctor` reports checks not implemented by this first slice as `INFO`, not
`PASS`.

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

GitHub reads (GET/HEAD/OPTIONS and `git-upload-pack`) flow through the
proxy; writes are blocked with a note until the pending-request inbox
exists. Other origins are logged and unpoliced.

## MCP forwarding (read tools)

Create `mcp-forwards.json` in the broker data directory:

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

Then authorize it in the UI: Settings → MCP forwards → "Connect
(OAuth)". The broker discovers the server's OAuth endpoints, registers
itself, opens your browser to log in, and stores the session on the
host — no pasting secrets. Sessions carry the refresh token: the broker
refreshes near expiry and retries once on an upstream 401, so agents
never see a reauth seam. The settings page shows the session's expiry
and offers Reauthorize and Disconnect. An optional `"scope"` field on
the forward requests a narrower grant (e.g. `"read"` for Linear
read-only). Alternatively set the `bearer_env` variable to an API key.
Containers connect a streamable-HTTP MCP client to
`http://HOST_IP:8082/mcp/linear`. Only `tools/list` (filtered to the
allowlist) and allowlisted `tools/call` reach upstream; the token never
enters the container.

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

`fz setup` fetches the fakes into the guest as `friendzone-env.sh`;
source it in the agent's shell.

Substitution requires an exact fake match on a pinned host: a random
key passes through untouched, and a fake sent toward any non-pinned
host is blocked as an attempted leak. Non-credential headers (e.g.
`anthropic-beta` feature flags, `anthropic-version`, `X-Task-ID`) pass
through untouched.

## Current scope

Working now: multi-container identity with dynamic add/remove and a
reversible kill switch; GitHub read/write policy (reads flow, writes
block with a note); credential escrow with exact-fake-match,
host-pinned substitution and leak blocking, provider presets, and
add/edit/delete from the settings UI; Cline account sign-in with
background token refresh; MCP forwarding of streamable-HTTP servers
with tool allowlists and host-side OAuth (discovery, dynamic client
registration, PKCE, refresh, reauthorize/disconnect); guest bootstrap
of the CA, `fz` binary, and fake credentials.

Not yet: proxy password validation (the username is trusted labeling,
not authentication), new-container acknowledgement gating, the
pending-request inbox (GitHub writes 403 instead of queueing),
rulesets, on-disk log retention, OS-secret-store credentials,
stdio MCP servers, Hyper-V/tart network provisioning
(egress default-deny is the VM network's job), and terminating
connections already in progress when the kill switch is pressed.
