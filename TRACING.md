# Trace commands and Cline proxy timeouts

Friendzone exports traces but does not embed a trace database or UI. The
repository supplies one Windows command that starts a verified portable Jaeger
executable as the collector, in-memory store, and trace viewer, then starts
Friendzone with export enabled.

There is no Docker, database, Windows service, or collector configuration file.

## 1. Start traced Friendzone on the Windows host

From the repository root:

```cmd
tools\trace-viewer.cmd Broker -BrokerAddress HOST_IP
```

Use the same `HOST_IP` that the guest uses for Friendzone. For a host-only local
test, omit `-BrokerAddress`; it defaults to `127.0.0.1`.

On first use, the command downloads the official Jaeger 2.21.0 Windows AMD64 ZIP
(about 65 MB) to `%LOCALAPPDATA%\Friendzone\trace-viewer` and verifies pinned
SHA-256 hashes for both the archive and `jaeger.exe`. It then:

- starts Jaeger OTLP/HTTP on `127.0.0.1:4318`;
- keeps the Jaeger UI and query API on `127.0.0.1:16686`;
- enables the bounded guest trace relay on Friendzone's existing bootstrap port;
  and
- runs `fz broker` with its OTLP exporter pointed at loopback Jaeger.

The `.cmd` wrapper works when Windows PowerShell script execution is disabled by
using a process-scoped policy bypass. It does not change user or machine policy.

## 2. Run a traced command inside the guest

Complete normal Friendzone guest setup and **Approve + pin IP** first. In an
activated guest shell, download the command wrapper over the already-allowed
bootstrap connection:

```sh
curl --noproxy '*' -fsS "$FZ_BROKER/bootstrap/trace-command.sh" -o trace-command.sh
sh ./trace-command.sh cline --verbose --timeout 0 "minimal prompt that reproduces the timeout"
```

Everything after `trace-command.sh` is the exact command and argument list. The
wrapper does not insert `cline`, add flags, evaluate a shell expression, or
change the current directory. For example:

```sh
sh ./trace-command.sh cline --help
sh ./trace-command.sh cline --verbose --timeout 0 "another prompt"
sh ./trace-command.sh node ./reproduction.cjs "argument with spaces"
sh ./trace-command.sh sh -c 'command-one | command-two'
```

The wrapper requires Node.js. On first use only, npm installs pinned
OpenTelemetry Node packages under
`${XDG_DATA_HOME:-$HOME/.local/share}/friendzone`. It creates one
`friendzone.command` span around every command and preserves the command's
stdio, exit status, cwd, and argument boundaries. The supervisor forwards HUP,
INT, and TERM, then ends and flushes the outer command span when the child exits;
it does not replace the command's own signal handlers. Shell builtins, pipelines,
redirection, and compound commands need an explicit `sh -c`, as in the example
above. For a `cline` executable the wrapper also selects Cline's local backend,
avoiding an old uninstrumented hub process outside the wrapper.

Node commands and Node descendants load HTTP and Undici instrumentation. Cline
is Node-based, so its outbound provider call becomes a child of the command
span and injects the W3C context that Friendzone continues. A native executable
still gets the outer command-duration/exit span, but its internal work is not
automatically visible unless that executable has its own OpenTelemetry SDK.

The wrapper and its instrumented Node processes send OTLP batches to
`$FZ_BROKER/v1/traces`. Friendzone accepts them only from an approved, uniquely
IP-pinned, non-killed guest, applies concurrency, size, media-type, and timeout
bounds, strips guest headers, and relays the protobuf body only to Jaeger on host
loopback. **No additional guest-facing port or firewall rule is required.**

The wrapper is diagnostic instrumentation. Normal Friendzone guest setup does
not install it or make tracing persistent.

### If `invalid tracing preload` appears

This means an older running broker served Windows CRLF bytes. The corrected
broker always serves LF and the corrected wrapper also normalizes downloaded
JavaScript assets. On the host, stop the old `cargo run` with Ctrl+C and start
the traced broker instead:

```cmd
tools\trace-viewer.cmd Broker -BrokerAddress 172.24.80.1
```

Use your actual guest-facing host IP if it differs. Then redownload
`trace-command.sh` in the guest and run it again. The successful package
install is recorded under
`${XDG_DATA_HOME:-$HOME/.local/share}/friendzone/otel-node-v1`, so the retry does
not reinstall the 25 packages. The old `/bootstrap/trace-cline.sh` download URL
remains an alias, but the downloaded wrapper still expects the complete command.

## 3. Inspect or export the trace

Open <http://127.0.0.1:16686>. Select service **cline-guest**, click **Find
Traces**, and open the reproduction. The same trace contains:

```text
friendzone.command
└── cline-guest HTTP client
    └── friendzone.proxy.request
        └── friendzone.proxy.upstream
```

Jaeger keeps up to 10,000 traces in memory. To save one before stopping, copy
the 32-character trace ID from Jaeger and run:

```cmd
tools\trace-viewer.cmd Export -TraceId TRACE_ID -OutputPath timeout-trace.json
```

This writes the complete OTLP-based Jaeger JSON returned by Jaeger's stable v3
query API. Keep the JSON with the matching Friendzone request ID if another
person or tool will analyze the failure.

After the investigation, stop Friendzone with Ctrl+C, then stop Jaeger:

```cmd
tools\trace-viewer.cmd Stop
```

Stopping Jaeger discards its in-memory traces. `Status` reports whether the
viewer is running and where its logs are stored:

```cmd
tools\trace-viewer.cmd Status
```

## How Friendzone traces are exported

The `Broker` action starts `fz` with:

```text
OTEL_SERVICE_NAME=friendzone
OTEL_TRACES_EXPORTER=otlp
OTEL_EXPORTER_OTLP_TRACES_PROTOCOL=http/protobuf
OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://127.0.0.1:4318/v1/traces
FZ_TRACE_RELAY_ENABLED=true
```

At startup, Friendzone creates a Rust OpenTelemetry tracer provider with a batch
OTLP/HTTP exporter. When a proxy request finishes, the exporter POSTs its spans
as protobuf to Jaeger's loopback `/v1/traces` receiver. Jaeger stores and indexes
them for its browser UI. Friendzone flushes the provider during a clean shutdown.

Only events under the `fz::proxy` tracing target are exported. `RUST_LOG` affects
console diagnostics but does not enable or disable OTLP export.

For every application request admitted for forwarding, Friendzone creates:

1. `friendzone.proxy.request`, a server span parented to Cline's W3C
   `traceparent`; and
2. `friendzone.proxy.upstream`, a child client span whose context is injected
   into the provider request.

Both carry `friendzone.request.id`, which matches the Friendzone UI log. Their
attributes and events include normalized host/path, method, active request
counts, request-body timing, time to headers, time to first body byte, protocol,
HTTP status, response bytes, and typed transport outcomes. They exclude query
strings, bodies, credentials, arbitrary headers, and raw HTTP/2 HEADERS frames.

### `api.cline.bot` HTTP/1.1 workaround

Friendzone currently forces exact HTTPS `api.cline.bot:443` upstream connections
to HTTP/1.1. Traces showed multiple 2–5 minute requests overlapping on the same
H2 connection while fresh connections initially remained healthy. This targeted,
reversible workaround removes H2 multiplexing and connection-wide flow control
from Cline inference traffic without disabling H2 for any other origin.

The choice is made by TLS ALPN, not by relabeling a request version. Concurrent
Cline requests can therefore open separate H1 connections instead of sharing one
H2 connection. Restart the broker after updating; existing connections and a
running binary do not change in place. New Cline upstream spans should contain:

```text
server.address=api.cline.bot
network.protocol.name=http/1.1
```

This is an A/B mitigation, not proof of an H2 implementation defect. If the long
pre-header stalls disappear, the H2 connection path is strongly implicated. If
they remain, compare `request_body_complete_ms`, `time_to_headers_ms`, and the
response timing to distinguish upload backpressure from provider-side delay.

## Reading a timeout

| Observation | Likely boundary |
|---|---|
| `friendzone.command` only | The command ran but made no instrumented Node HTTP/Undici request; check that Cline used its local backend |
| No `cline-guest` HTTP span | The wrapped process stopped before making HTTP, or the actual network process was not a Node descendant |
| Cline client span but no Friendzone server child | Proxy/CA/routing failed before Friendzone admitted the request |
| Friendzone request without an upstream child | Identity, destination, policy/review, or credential substitution denied forwarding |
| Upstream ends `transport_error` before headers | DNS, connect, TLS, send, or HTTP/2 failure; inspect `friendzone.transport.detail` and `error.type` |
| Headers arrive but no first body byte | Provider or edge stalled before response content |
| First byte arrives, then `response_body_error` | Provider, edge, or upstream HTTP/2 stream failed mid-response |
| `downstream_body_dropped` | Cline disconnected or stopped consuming while Friendzone streamed the response |
| Friendzone records `response_complete` before Cline times out | Investigate Cline processing after the proxy rather than the provider connection |

## Cline limitation and privacy

Cline's documented built-in OpenTelemetry integration, checked on 2026-09-18,
exports metrics and log records but does not implement distributed tracing. The
wrapper uses generic Node auto-instrumentation specifically so Cline's outbound
HTTP request injects the W3C context Friendzone can continue.

Generic Node instrumentation does not inherit Cline's telemetry privacy policy
and may record URL or runtime metadata. Friendzone does not enable header or body
capture, and the command span records no arguments, cwd, environment values, or
output. Inspect exported JSON before sharing it and use tracing only for a focused
reproduction. Remove the guest packages afterward if desired:

```sh
rm -rf "${XDG_DATA_HOME:-$HOME/.local/share}/friendzone/otel-node-v1"
```

References:

- [Cline OpenTelemetry integration](https://docs.cline.bot/enterprise-solutions/monitoring/opentelemetry.md)
- [Cline CLI reference](https://docs.cline.bot/cline-cli/cli-reference.md)
- [OpenTelemetry Node zero-code instrumentation](https://opentelemetry.io/docs/zero-code/js/)
- [Jaeger APIs](https://www.jaegertracing.io/docs/2.21/apis/)