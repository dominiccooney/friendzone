# Friendzone

This first slice provides the `fz` binary, a local HTTPS-intercepting proxy,
certificate bootstrap, request log, and web UI.

## Run the broker

```powershell
cargo run -- broker --proxy-addr HOST_VNIC_IP:8080 --ui-addr 127.0.0.1:8081 --bootstrap-addr HOST_VNIC_IP:8082
```

Open <http://127.0.0.1:8081>. The CA certificate and private key are created
under the operating system's local application-data directory in
`friendzone/`. The private key is never served by the bootstrap endpoint.

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

Set the named env var to a bearer token (for Linear: an API key or OAuth
token; the read-only endpoint `https://mcp.linear.app/mcp/readonly` is a
good fit). Containers connect a streamable-HTTP MCP client to
`http://HOST_IP:8082/mcp/linear`. Only `tools/list` (filtered to the
allowlist) and allowlisted `tools/call` reach upstream; the token never
enters the container.

## Inference via the broker

Set `FZ_ANTHROPIC_API_KEY` and/or `FZ_OPENAI_API_KEY` on the host. The
proxy substitutes the real key into requests to `api.anthropic.com` /
`api.openai.com`, so containers can run inference holding only a fake
key. The substitution is pinned to those hosts.

## Current scope

This slice does not yet validate proxy passwords or require new-container
acknowledgement, enforce rulesets, substitute credentials, retain logs on disk,
parse GitHub semantics, forward MCP servers, provision Hyper-V/tart
networking, or terminate connections already in progress when the kill
switch is pressed.
