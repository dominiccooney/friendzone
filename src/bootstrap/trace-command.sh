#!/bin/sh
# Friendzone traced-command wrapper v2. Executes the exact command under an OTel session span.
set -eu

if [ "$#" -eq 0 ]; then
  echo 'Usage: sh ./trace-command.sh COMMAND [ARG ...]' >&2
  echo 'Example: sh ./trace-command.sh cline --verbose --timeout 0 "prompt"' >&2
  exit 2
fi
: "${FZ_BROKER:?Run this from a terminal activated by Friendzone guest setup}"
command -v node >/dev/null 2>&1 || { echo 'Node.js is required.' >&2; exit 1; }

otel_dir="${XDG_DATA_HOME:-$HOME/.local/share}/friendzone/otel-node-v1"
preload="$otel_dir/friendzone-trace-node.cjs"
supervisor="$otel_dir/friendzone-trace-command.cjs"
installed="$otel_dir/.friendzone-installed-v1"
if [ ! -f "$installed" ]; then
  command -v npm >/dev/null 2>&1 || { echo 'npm is required for the one-time tracing install.' >&2; exit 1; }
  echo 'Installing pinned OpenTelemetry Node instrumentation (one time)...' >&2
  mkdir -p "$otel_dir"
  npm install --prefix "$otel_dir" --no-audit --no-fund \
    @opentelemetry/api@1.9.0 \
    @opentelemetry/context-async-hooks@2.11.0 \
    @opentelemetry/sdk-trace-node@2.11.0 \
    @opentelemetry/exporter-trace-otlp-proto@0.222.0 \
    @opentelemetry/instrumentation@0.222.0 \
    @opentelemetry/instrumentation-http@0.222.0 \
    @opentelemetry/instrumentation-undici@0.32.0 \
    @opentelemetry/resources@2.11.0
  printf '%s\n' 'Friendzone tracing dependencies v1' > "$installed.tmp.$$"
  mv -f -- "$installed.tmp.$$" "$installed"
fi

preload_download="$preload.download.$$"
preload_temporary="$preload.tmp.$$"
supervisor_download="$supervisor.download.$$"
supervisor_temporary="$supervisor.tmp.$$"
trap 'rm -f -- "$preload_download" "$preload_temporary" "$supervisor_download" "$supervisor_temporary"' EXIT HUP INT TERM

curl --noproxy '*' -fsS "${FZ_BROKER%/}/bootstrap/trace-node.cjs" -o "$preload_download"
# Older Friendzone builds could serve source-checkout CRLF. This is a text-only
# JavaScript file, so remove CR bytes portably before validating or loading it.
tr -d '\015' < "$preload_download" > "$preload_temporary"
grep -q '^// Friendzone timeout tracing preload v1\.$' "$preload_temporary" || {
  echo 'Friendzone returned an invalid tracing preload.' >&2
  echo 'Restart the updated host broker, download trace-command.sh again, and retry.' >&2
  exit 1
}
curl --noproxy '*' -fsS "${FZ_BROKER%/}/bootstrap/trace-command.cjs" -o "$supervisor_download"
tr -d '\015' < "$supervisor_download" > "$supervisor_temporary"
grep -q '^// Friendzone traced-command supervisor v1\.$' "$supervisor_temporary" || {
  echo 'Friendzone returned an invalid tracing supervisor.' >&2
  echo 'Restart the updated host broker, download trace-command.sh again, and retry.' >&2
  exit 1
}
mv -f -- "$preload_temporary" "$preload"
mv -f -- "$supervisor_temporary" "$supervisor"
rm -f -- "$preload_download" "$supervisor_download"
trap - EXIT HUP INT TERM

export NODE_PATH="$otel_dir/node_modules${NODE_PATH:+:$NODE_PATH}"
export NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--require=\"$preload\""
export FZ_TRACE_PRELOAD="$preload"
export FZ_TRACE_SUPERVISOR=1
unset OTEL_EXPORTER_OTLP_HEADERS OTEL_EXPORTER_OTLP_TRACES_HEADERS
unset OTEL_EXPORTER_OTLP_COMPRESSION OTEL_EXPORTER_OTLP_TRACES_COMPRESSION
unset OTEL_SDK_DISABLED OTEL_PROPAGATORS
: "${OTEL_SERVICE_NAME:=cline-guest}"
export OTEL_SERVICE_NAME
export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT="${FZ_BROKER%/}/v1/traces"

command_name=${1##*/}
if [ "$command_name" = cline ]; then
  # A pre-existing Cline hub was not started with this preload. Local mode keeps
  # this invocation's HTTP work in the instrumented process tree.
  export CLINE_SESSION_BACKEND_MODE=local
fi

echo "Tracing $command_name through ${OTEL_EXPORTER_OTLP_TRACES_ENDPOINT}" >&2
# Consistency boundary: everything after this wrapper is argv for one command.
# The Node supervisor adds the session span; it never evaluates a shell string.
exec node "$supervisor" "$@"
