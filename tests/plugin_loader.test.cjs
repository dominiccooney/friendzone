// Import-only tests. Never call setup or a contributed tool. Run on Node and
// Bun; optionally set FZ_CLINE_PLUGIN_IMPORT to the pinned Cline loader source
// (with its dependencies available) for the actual Jiti-backed import path.
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const source = path.join(__dirname, '../src/plugin/friendzone.js');

function validate(plugin) {
  assert.equal(plugin?.name, 'friendzone', 'Cline must receive the plugin, not an exports wrapper');
  assert.deepEqual(plugin.manifest.capabilities, ['tools']);
  assert.equal(typeof plugin.setup, 'function');
}

function artifact(t, sourceFile = source) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fz plugin import '));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  // Use a standalone installed .js file, outside repository package context.
  const file = path.join(dir, 'Guest space ü', '.cline', 'plugins', 'friendzone.js');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.copyFileSync(sourceFile, file);
  return file;
}

test('CommonJS exposes the plugin itself without running setup', t => {
  const file = artifact(t);
  const plugin = require(file);
  validate(plugin);
  assert.equal(plugin.default, undefined, 'no synthetic default wrapper in module.exports');
  delete require.cache[require.resolve(file)];
});

test('native dynamic import gives Cline a named plugin at the default export', async t => {
  const exports = await import(pathToFileURL(artifact(t)).href);
  // This is the selection used by Cline's plugin loader, not exports.default
  // selected directly out of a VM mock of CommonJS module.exports.
  validate(exports.default ?? exports.plugin);
});

test('actual Cline importPluginModule selects the standalone plugin', {
  skip: !process.env.FZ_CLINE_PLUGIN_IMPORT && 'Set FZ_CLINE_PLUGIN_IMPORT for the upstream loader contract check',
}, async t => {
  const { importPluginModule } = await import(pathToFileURL(process.env.FZ_CLINE_PLUGIN_IMPORT).href);
  const exports = await importPluginModule(artifact(t), { useCache: false });
  validate(exports.default ?? exports.plugin);
});

test('generated Linux and installed Windows artifacts cross the same import boundary', {
  skip: !process.env.FZ_PLUGIN_TEST_ARTIFACT_DIR && 'Set FZ_PLUGIN_TEST_ARTIFACT_DIR when running bootstrap tests, then run this suite',
}, async t => {
  const dir = process.env.FZ_PLUGIN_TEST_ARTIFACT_DIR;
  const names = fs.readdirSync(dir).filter(name => name.endsWith('.js'));
  assert.ok(names.includes('linux-script.js'), 'missing extracted Linux script artifact');
  assert.ok(names.includes('windows-powershell51.js'), 'missing installed PowerShell 5.1 artifact');
  const cline = process.env.FZ_CLINE_PLUGIN_IMPORT
    ? await import(pathToFileURL(process.env.FZ_CLINE_PLUGIN_IMPORT).href) : null;
  for (const name of names) {
    const sourceFile = path.join(dir, name);
    assert.deepEqual(fs.readFileSync(sourceFile), fs.readFileSync(source), name);
    const file = artifact(t, sourceFile);
    validate(require(file));
    const exports = await import(pathToFileURL(file).href);
    validate(exports.default ?? exports.plugin);
    if (cline) {
      const loaded = await cline.importPluginModule(file, { useCache: false });
      validate(loaded.default ?? loaded.plugin);
    }
    delete require.cache[require.resolve(file)];
  }
});