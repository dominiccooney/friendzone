// Friendzone traced-command supervisor v1.
'use strict';

const path = require('node:path');
const { spawn } = require('node:child_process');
const { context, propagation, trace, SpanStatusCode } = require('@opentelemetry/api');

const telemetry = require(process.env.FZ_TRACE_PRELOAD);
const argv = process.argv.slice(2);
const command = argv.shift();
if (!command) {
  console.error('Friendzone trace supervisor requires a command.');
  process.exit(2);
}

const commandName = path.basename(command);
const span = trace.getTracer('friendzone-traced-command').startSpan('friendzone.command', {
  attributes: {
    'process.executable.name': commandName,
  },
});
const commandContext = trace.setSpan(context.active(), span);
const carrier = {};
propagation.inject(commandContext, carrier);
const childEnv = {
  ...process.env,
  FZ_TRACEPARENT: carrier.traceparent,
};
delete childEnv.FZ_TRACE_PRELOAD;
delete childEnv.FZ_TRACE_SUPERVISOR;
if (carrier.tracestate) childEnv.FZ_TRACESTATE = carrier.tracestate;
else delete childEnv.FZ_TRACESTATE;

let finished = false;
let child;
const signals = ['SIGHUP', 'SIGINT', 'SIGTERM'];
for (const signal of signals) {
  process.on(signal, () => {
    if (child && child.exitCode === null && child.signalCode === null) child.kill(signal);
  });
}

async function finish(code, signal, spawnError) {
  if (finished) return;
  finished = true;
  if (Number.isInteger(code)) span.setAttribute('process.exit.code', code);
  if (signal) span.setAttribute('process.exit.signal', signal);
  if (spawnError) span.setAttribute('error.type', spawnError.code || 'spawn_error');
  if (spawnError || signal || code !== 0) {
    span.setStatus({ code: SpanStatusCode.ERROR });
  }
  span.end();
  await telemetry.shutdown();

  if (signal) {
    for (const name of signals) process.removeAllListeners(name);
    try {
      process.kill(process.pid, signal);
      return;
    } catch (_) {
      process.exit(1);
    }
  }
  process.exit(Number.isInteger(code) ? code : 1);
}

try {
  child = context.with(commandContext, () => spawn(command, argv, {
    cwd: process.cwd(),
    env: childEnv,
    shell: false,
    stdio: 'inherit',
  }));
  child.once('error', error => {
    console.error(`Friendzone could not start ${commandName}: ${error.code || 'spawn error'}`);
    void finish(127, null, error);
  });
  child.once('close', (code, signal) => void finish(code, signal, null));
} catch (error) {
  console.error(`Friendzone could not start ${commandName}: ${error.code || 'spawn error'}`);
  void finish(127, null, error);
}
