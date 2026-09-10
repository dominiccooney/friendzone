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

## Containers

Containers are dynamic; the launch command never names them. A container
is identified by the username in its proxy credentials. **Unknown
containers are denied**: first contact (traffic or `fz setup`) creates a
join request in the Inbox, and nothing flows until you approve it —
"Approve + pin IP" also locks the name to the address it connected
from, so containers cannot use each other's names. Pins are editable
per container (Pin…; empty = any address). "Add container"
pre-approves a name (wildcard address) before its VM boots. Kill/Resume
stops traffic reversibly; Remove forgets the container (its log rows
remain for audit).

The overview reports **Approved**, **Awaiting approval**, or **Killed**.
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

The broker exposes its own binary at `http://HOST_IP:8082/bootstrap/fz`
— right only when the guest matches the host's OS/arch.

For a guest with a different OS (e.g. a Linux VM on a Windows host),
build `fz` inside the guest from the repo:

```text
git clone https://github.com/dominiccooney/friendzone
cd friendzone && cargo build --release
sudo ./target/release/fz setup --broker http://HOST_IP:8082 --install
```

Optionally copy the built binary to the host's `<data-dir>/guest-bin/`
(e.g. as `fz-linux-x86_64`) and restart the broker; further guests of
that platform can then skip the build and fetch it from
`/bootstrap/fz/fz-linux-x86_64` (`GET /bootstrap/targets` lists what is
available; the broker prints it at startup).

On a guest matching the host platform:

```text
curl -o fz http://HOST_IP:8082/bootstrap/fz
chmod +x fz
sudo ./fz setup --broker http://HOST_IP:8082 --install
```

`/bootstrap/fz` also takes a platform query — `?linux`, `?win`,
`?macos` — which serves a matching build from `guest-bin/` (the bare
URL always serves the host's own binary). Setup ends by announcing the
container to the broker: if it is not yet approved, setup says so and
the join request is already waiting in the UI inbox.

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

Use **Settings → MCP forwards** to add, validate and apply a forward live,
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
**Copy Cline setup** includes the required guest Authorization header.
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

`fz setup` fetches the fakes into the guest as `friendzone-env.sh`;
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

Working now: multi-container identity with join-request approval, IP
pinning, dynamic add/remove, and a
reversible kill switch; request log with HTTP status, inference token
counts, 10,000-event in-memory retention, server-side search and pagination;
407 proxy authentication negotiation, CONNECT identity propagation and
decrypted GitHub policy; in-UI MCP forwards editing with live
reload; GitHub read/write policy (reads flow, writes
block with a note); credential escrow with exact-fake-match,
host-pinned substitution and leak blocking, provider presets, and
add/edit/delete from the settings UI; Cline account sign-in with
background token refresh; MCP forwarding of streamable-HTTP servers
with tool allowlists and host-side OAuth (discovery, dynamic client
registration, PKCE, refresh, reauthorize/disconnect); guest bootstrap
of the CA, `fz` binary, and fake credentials.

Not yet: proxy password validation (identity is name + approval + IP
pin, not a secret), the
pending-request inbox (GitHub writes 403 instead of queueing),
rulesets, on-disk log retention, OS-secret-store credentials,
stdio MCP servers, Hyper-V/tart network provisioning
(egress default-deny is the VM network's job), and terminating
connections already in progress when the kill switch is pressed.
