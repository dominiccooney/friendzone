const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const root = path.join(__dirname, '..');
const supervisor = path.join(root, 'src/bootstrap/trace-command.cjs');
const wrapper = path.join(root, 'src/bootstrap/trace-command.sh');

function fixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'fz-trace-command-'));
  const modules = path.join(directory, 'node_modules/@opentelemetry/api');
  fs.mkdirSync(modules, { recursive: true });
  fs.writeFileSync(path.join(modules, 'index.js'), `
const fs = require('node:fs');
const span = {
  attributes: {}, status: null,
  setAttribute(name, value) { this.attributes[name] = value; },
  setStatus(status) { this.status = status; },
  end() { fs.writeFileSync(process.env.FZ_TEST_SPAN, JSON.stringify(this)); },
};
exports.context = { active: () => ({}), with: (_context, fn) => fn() };
exports.propagation = { inject: (_context, carrier) => {
  carrier.traceparent = '00-11111111111111111111111111111111-2222222222222222-01';
  carrier.tracestate = 'fixture=value';
} };
exports.trace = {
  getTracer: () => ({ startSpan: (_name, options) => {
    span.attributes = { ...options.attributes };
    return span;
  } }),
  setSpan: context => context,
};
exports.SpanStatusCode = { ERROR: 2 };
`);
  const preload = path.join(directory, 'preload.cjs');
  fs.writeFileSync(preload, `module.exports = { shutdown: async () => {
    require('node:fs').writeFileSync(process.env.FZ_TEST_SHUTDOWN, 'flushed');
  } };\n`);
  const child = path.join(directory, 'child.cjs');
  fs.writeFileSync(child, `
const fs = require('node:fs');
fs.writeFileSync(process.argv[2], JSON.stringify({
  argv: process.argv.slice(4),
  cwd: process.cwd(),
  traceparent: process.env.FZ_TRACEPARENT,
  tracestate: process.env.FZ_TRACESTATE,
  supervisor: process.env.FZ_TRACE_SUPERVISOR,
  preload: process.env.FZ_TRACE_PRELOAD,
  clineMode: process.env.CLINE_SESSION_BACKEND_MODE,
}));
process.stdout.write('child stdout marker\\n');
process.exit(Number(process.argv[3]));
`);
  return { directory, modules: path.join(directory, 'node_modules'), preload, child };
}

function run(exitCode, args) {
  const f = fixture();
  const output = path.join(f.directory, 'child.json');
  const span = path.join(f.directory, 'span.json');
  const shutdown = path.join(f.directory, 'shutdown.txt');
  const result = spawnSync(process.execPath, [supervisor, process.execPath, f.child, output,
    String(exitCode), ...args], {
    cwd: f.directory,
    encoding: 'utf8',
    env: {
      ...process.env,
      NODE_OPTIONS: '',
      NODE_PATH: f.modules,
      FZ_TRACE_PRELOAD: f.preload,
      FZ_TRACE_SUPERVISOR: '1',
      FZ_TEST_SPAN: span,
      FZ_TEST_SHUTDOWN: shutdown,
      CLINE_SESSION_BACKEND_MODE: '',
    },
  });
  return {
    result,
    directory: f.directory,
    child: JSON.parse(fs.readFileSync(output, 'utf8')),
    span: JSON.parse(fs.readFileSync(span, 'utf8')),
    shutdown: fs.readFileSync(shutdown, 'utf8'),
  };
}

test('supervisor preserves argv, cwd and stdout without shell evaluation and passes W3C context', t => {
  const args = ['two words', '"quoted"', '; touch must-not-exist', '$(not-a-command)', ''];
  const observed = run(0, args);
  t.after(() => fs.rmSync(observed.directory, { recursive: true, force: true }));
  assert.equal(observed.result.status, 0, observed.result.stderr);
  assert.deepEqual(observed.child.argv, args);
  assert.match(observed.child.cwd, /fz-trace-command-/);
  assert.match(observed.result.stdout, /child stdout marker/);
  assert.equal(observed.child.traceparent,
    '00-11111111111111111111111111111111-2222222222222222-01');
  assert.equal(observed.child.tracestate, 'fixture=value');
  assert.equal(observed.child.supervisor, undefined);
  assert.equal(observed.child.preload, undefined);
  assert.equal(observed.child.clineMode, '');
  assert.equal(observed.span.attributes['process.executable.name'], path.basename(process.execPath));
  assert.equal(observed.span.attributes['process.exit.code'], 0);
  assert.equal(observed.span.status, null);
  assert.equal(observed.shutdown, 'flushed');
  assert.equal(fs.existsSync(path.join(observed.child.cwd, 'must-not-exist')), false);
});

test('supervisor preserves a non-zero command exit and records it as an error', t => {
  const observed = run(23, ['argument']);
  t.after(() => fs.rmSync(observed.directory, { recursive: true, force: true }));
  assert.equal(observed.result.status, 23, observed.result.stderr);
  assert.equal(observed.span.attributes['process.exit.code'], 23);
  assert.deepEqual(observed.span.status, { code: 2 });
  assert.equal(observed.shutdown, 'flushed');
});

test('supervisor reports an executable lookup failure as 127 without exposing arguments', t => {
  const f = fixture();
  t.after(() => fs.rmSync(f.directory, { recursive: true, force: true }));
  const span = path.join(f.directory, 'span.json');
  const shutdown = path.join(f.directory, 'shutdown.txt');
  const result = spawnSync(process.execPath, [supervisor, path.join(f.directory, 'absent-command'),
    'private argument'], {
    encoding: 'utf8',
    env: {
      ...process.env,
      NODE_OPTIONS: '',
      NODE_PATH: f.modules,
      FZ_TRACE_PRELOAD: f.preload,
      FZ_TRACE_SUPERVISOR: '1',
      FZ_TEST_SPAN: span,
      FZ_TEST_SHUTDOWN: shutdown,
    },
  });
  assert.equal(result.status, 127);
  assert.doesNotMatch(result.stderr, /private argument/);
  const recorded = JSON.parse(fs.readFileSync(span, 'utf8'));
  assert.equal(recorded.attributes['process.exit.code'], 127);
  assert.equal(recorded.attributes['error.type'], 'ENOENT');
  assert.deepEqual(recorded.status, { code: 2 });
  assert.equal(fs.readFileSync(shutdown, 'utf8'), 'flushed');
});

test('shell wrapper is a generic exact-command launcher, not a hard-coded Cline prompt', () => {
  const source = fs.readFileSync(wrapper, 'utf8');
  assert.equal(source.includes('\r'), false);
  assert.match(source, /exec node "\$supervisor" "\$@"/);
  assert.doesNotMatch(source, /^exec cline\b/m);
  assert.ok(source.includes('if [ "$command_name" = cline ]; then'));
});