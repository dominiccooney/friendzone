// Friendzone timeout tracing preload v1.
'use strict';

const {
  AlwaysOnSampler,
  BatchSpanProcessor,
  NodeTracerProvider,
} = require('@opentelemetry/sdk-trace-node');
const { ROOT_CONTEXT, context, propagation, trace } = require('@opentelemetry/api');
const { AsyncLocalStorageContextManager } = require('@opentelemetry/context-async-hooks');
const { OTLPTraceExporter } = require('@opentelemetry/exporter-trace-otlp-proto');
const { registerInstrumentations } = require('@opentelemetry/instrumentation');
const { HttpInstrumentation } = require('@opentelemetry/instrumentation-http');
const { UndiciInstrumentation } = require('@opentelemetry/instrumentation-undici');
const { resourceFromAttributes } = require('@opentelemetry/resources');

const provider = new NodeTracerProvider({
  resource: resourceFromAttributes({
    'service.name': process.env.OTEL_SERVICE_NAME || 'cline-guest',
  }),
  sampler: new AlwaysOnSampler(),
  spanProcessors: [new BatchSpanProcessor(new OTLPTraceExporter())],
});
const contextManager = new AsyncLocalStorageContextManager().enable();
provider.register({ contextManager });

// A traced-command supervisor passes its command span through this private
// carrier. Attach it before the wrapped program is loaded so later HTTP and
// Undici calls continue the same trace. Keep the variables for Node descendants.
const inheritedCarrier = {
  traceparent: process.env.FZ_TRACEPARENT,
  tracestate: process.env.FZ_TRACESTATE,
};
const inherited = propagation.extract(ROOT_CONTEXT, inheritedCarrier);
if (trace.getSpanContext(inherited)) contextManager.attach(inherited);

registerInstrumentations({
  instrumentations: [new HttpInstrumentation(), new UndiciInstrumentation()],
});

let shutdownPromise;
async function shutdown() {
  if (!shutdownPromise) shutdownPromise = provider.shutdown();
  try {
    await shutdownPromise;
  } catch (error) {
    console.error('Friendzone trace flush failed:', error);
  }
}
process.once('beforeExit', () => void shutdown());

module.exports = { shutdown };
