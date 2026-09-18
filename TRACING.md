# Trace Cline proxy timeouts

Use this runbook to determine whether a timeout starts in Cline, at the
Friendzone policy/connection boundary, at the provider, or while streaming the
response back to the guest.

## What Friendzone records

For each application request admitted for forwarding, Friendzone creates:

1. `friendzone.proxy.request`, a server span parented to an incoming W3C
   `traceparent` when one is present; and
2. `friendzone.proxy.upstream`, its client child, whose context is injected into
   the provider request.

The spans and their events include `friendzone.request.id`, method, normalized
host/path, active-request counts, request-body timing, time to response headers
and first body byte, protocol/status, observed response bytes, and typed
transport outcomes. They never include query strings, bodies, credentials,
arbitrary headers, or raw HTTP/2 HEADERS frames.

Friendzone also emits the same request ID and phase boundaries to its normal
stderr diagnostics and stores the final bounded transport detail in the UI log.

## Important Cline limitation

Cline's documented built-in OpenTelemetry integration (checked 2026-09-18) exports
**metrics and structured log events, not spans**. Its documentation explicitly
lists distributed tracing as not implemented. Stock Cline therefore does not
inject the W3C `traceparent` required to make the Cline operation the parent of
Friendzone's spans.

You have two useful modes:

- **Stock Cline diagnostics:** collect Cline verbose/core logs and optional Cline
  OTLP log events, then align them with Friendzone by UTC timestamp,
  provider/model, and failure phase. This does not produce one distributed
  trace.
- **Shared trace for a focused reproduction:** temporarily start the Node-based
  Cline CLI/hub with OpenTelemetry Node auto-instrumentation. Its HTTP/Undici
  client spans inject `traceparent`, producing the chain **Cline HTTP client →
  Friendzone request → Friendzone upstream → provider**.

The shared-trace recipe below is diagnostic instrumentation, not something the
Friendzone guest setup installs or manages.

## 1. Send Friendzone spans to a collector

Friendzone supports OTLP/HTTP protobuf. Configure the broker before startup;
the environment is read once, so restart the broker after changing it.

```powershell
$env:OTEL_SERVICE_NAME = 'friendzone'
$env:OTEL_EXPORTER_OTLP_TRACES_PROTOCOL = 'http/protobuf'
$env:OTEL_EXPORTER_OTLP_TRACES_ENDPOINT = 'http://HOST_IP:4318/v1/traces'

cargo run -- broker `
  --proxy-addr HOST_IP:8080 `
  --ui-addr 127.0.0.1:8081 `
  --bootstrap-addr HOST_IP:8082
```

Use `127.0.0.1` instead of `HOST_IP` for a host-only local demo. The
signal-specific endpoint is used exactly as supplied, including
`/v1/traces`. Alternatively, `OTEL_EXPORTER_OTLP_ENDPOINT` is a base URL and the
exporter appends `/v1/traces`. Standard OTLP headers/timeouts,
`OTEL_RESOURCE_ATTRIBUTES`, and batch processor variables are supported. This
build does not support OTLP/gRPC or compression, and its provider currently uses
the SDK default sampler rather than reading `OTEL_TRACES_SAMPLER`.

With no endpoint, Friendzone still continues valid incoming W3C context
upstream but does not export its own spans. `OTEL_TRACES_EXPORTER=none` has the
same propagation-only behavior. `OTEL_SDK_DISABLED=true` disables span creation
and propagation entirely.

## 2. Collect the stock Cline side first

Run Cline from the activated Friendzone guest shell so it inherits the proxy and
CA environment. For a CLI reproduction, make the task timeout explicit and ask
for verbose output:

`--timeout 0` means no overall Cline task deadline; it does not disable provider
or network timeouts. Check both documented default log locations because the
active path depends on whether the CLI uses its core service or background hub:

```sh
# Terminal 1
tail -F ~/.cline/cline-core-service.log ~/.cline/data/logs/hub-daemon.log

# Terminal 2
date -u
cline --verbose --timeout 0 "minimal prompt that reproduces the timeout"
```

If `--data-dir` or `CLINE_DATA_DIR` is set, inspect that configured data root
instead. Also run `cline doctor` and verify the exact installed flags with
`cline --help`; Cline's CLI changes independently of Friendzone.

### Optional Cline OTLP log events

Cline documents these controls under Enterprise Monitoring. If the installed
build supports them, console output is the safest first check because it does
not require another guest network exception:

```sh
export CLINE_OTEL_TELEMETRY_ENABLED=true
export CLINE_OTEL_LOGS_EXPORTER=console
export CLINE_OTEL_METRICS_EXPORTER=console
export TEL_DEBUG_DIAGNOSTICS=true
```

Restart every Cline CLI/core/hub process after setting them. Useful documented
events include `task.created`, `task.completed`, `task.retry_clicked`, and
`task.provider_api_error`, with fields such as `task_id`, `provider`, `model`,
`duration_ms`, `error_code`, and `error_message`. These are log records, not
trace spans; they do not supply a shared trace ID.

To export those Cline logs/metrics to an OTLP collector instead, use
`CLINE_OTEL_LOGS_EXPORTER=otlp`, `CLINE_OTEL_METRICS_EXPORTER=otlp`, and Cline's
`CLINE_OTEL_EXPORTER_OTLP_*` variables. Do not confuse those Cline-prefixed
settings with the standard `OTEL_*` variables used by Friendzone and Node
auto-instrumentation.

## 3. Produce a real shared trace from Cline CLI

This is an opt-in, temporary diagnostic for Node.js Cline CLI installations.
Install the instrumentation in an isolated directory inside the guest; do not
add it to the project under review.

```sh
otel_dir="$HOME/.local/share/friendzone-otel"
mkdir -p "$otel_dir"
npm install --prefix "$otel_dir" \
  @opentelemetry/api \
  @opentelemetry/auto-instrumentations-node

export NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--require=$otel_dir/node_modules/@opentelemetry/auto-instrumentations-node/register"
export OTEL_SERVICE_NAME=cline-guest
export OTEL_TRACES_EXPORTER=otlp
export OTEL_METRICS_EXPORTER=none
export OTEL_LOGS_EXPORTER=none
export OTEL_TRACES_SAMPLER=always_on
export OTEL_EXPORTER_OTLP_TRACES_PROTOCOL=http/protobuf
export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT="http://$FZ_HOST:4318/v1/traces"
export OTEL_NODE_ENABLED_INSTRUMENTATIONS=http,undici
export OTEL_NODE_RESOURCE_DETECTORS=env,process,container
```

The current Node auto-instrumentation package includes both Node HTTP and Undici
instrumentation, covering the usual HTTP clients and Node `fetch`. Confirm it
loaded with `OTEL_LOG_LEVEL=debug` only if needed; that output is extremely
verbose and can itself affect timing.

The process that actually sends the model request must inherit these variables.
An already-running Cline hub/core service will not. Stop it first or restart the
guest/container, then launch Cline from this instrumented environment:

```sh
date -u
cline --verbose --timeout 0 "minimal prompt that reproduces the timeout"
```

This recipe is for the Cline CLI/hub running inside the guest. A local editor
extension or remote extension host has a different process boundary; setting
variables only in a guest terminal does not instrument an already-running
editor process.

### Collector reachability is an explicit security exception

Friendzone setup puts `$FZ_HOST` in `NO_PROXY`, so the guest exporter connects
directly to `$FZ_HOST:4318`. The default confinement example permits only ports
8080 and 8082, so 4318 remains blocked unless you deliberately:

1. bind an OTLP collector receiver to the guest-facing host address used by
   both examples;
2. allow TCP 4318 only from the one diagnostic guest in both switch ACL and host
   firewall policy; and
3. remove that temporary allow after the reproduction.

Never expose the collector broadly, never open the management UI, and never
weaken the terminal egress deny. If adding a collector port is unacceptable,
set `OTEL_TRACES_EXPORTER=console` in the guest. The emitted Cline client span
still carries the trace ID injected into Friendzone, but you must match that
console trace ID to Friendzone's exported trace manually.

## 4. Read the result

Start with the Cline HTTP client span, then inspect its Friendzone descendants:

| Observation | Likely boundary |
|---|---|
| Cline reports a timeout but no Friendzone server span exists | Cline/hub never sent through this proxy, instrumentation was attached to the wrong process, or proxy/CA setup failed before HTTP admission |
| `friendzone.proxy.request` exists without `friendzone.proxy.upstream` | Friendzone denied identity, destination, policy/review, or credential substitution before forwarding |
| Upstream span ends `transport_error` before response headers | DNS/connect/TLS/send/HTTP2 failure; inspect `friendzone.transport.detail` and `error.type` |
| Response headers arrive but no first body byte | Provider/edge accepted the request but stalled before response content |
| First body byte arrives, then `response_body_error` | Provider/edge or upstream HTTP/2 stream failed mid-response |
| `downstream_body_dropped` | The guest/Cline side stopped consuming or disconnected while Friendzone was streaming |
| Friendzone records `response_complete` before Cline times out | Investigate Cline hub/client processing after the proxy, not the provider connection |

For non-shared stock diagnostics, synchronize host/guest clocks and compare UTC
timestamps with Friendzone's `request_id`, host, method/path, and phase timing.
Do not infer that adjacent requests share one physical HTTP/2 connection merely
because they overlap; use the socket tuple and connection diagnostics described
in the README.

## Privacy and cleanup

Cline's built-in telemetry applies its documented anonymization. Generic Node
auto-instrumentation does not apply Cline's privacy policy and may record URL or
runtime metadata. Do not enable request/response header capture, inspect your
collector before sharing traces, and use this only for a narrow reproduction.

Afterward, stop instrumented Cline processes, remove the temporary collector
network allow, and start a clean shell/container without `NODE_OPTIONS` and the
`OTEL_*`/`CLINE_OTEL_*` variables. Remove the isolated packages if no longer
needed:

```sh
rm -rf "$HOME/.local/share/friendzone-otel"
```

References checked for this runbook:

- [Cline OpenTelemetry integration](https://docs.cline.bot/enterprise-solutions/monitoring/opentelemetry.md)
- [Cline OpenTelemetry environment variables](https://docs.cline.bot/enterprise-solutions/monitoring/opentelemetry_override.md)
- [Cline OpenTelemetry events](https://docs.cline.bot/enterprise-solutions/monitoring/opentelemetry-events.md)
- [Cline CLI reference](https://docs.cline.bot/cline-cli/cli-reference.md)
- [OpenTelemetry Node zero-code instrumentation](https://opentelemetry.io/docs/zero-code/js/)