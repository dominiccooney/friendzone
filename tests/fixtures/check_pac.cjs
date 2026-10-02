const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

// Rust supplies the exact PAC fetched from the real bootstrap listener.
const [pac, expected] = process.argv.slice(2);
const sandbox = {};
vm.runInNewContext(fs.readFileSync(pac, 'utf8'), sandbox);
for (const [host, route] of JSON.parse(fs.readFileSync(expected, 'utf8'))) {
  assert.equal(sandbox.FindProxyForURL(`https://${host}/private/path?query=1`, host), route, host);
  assert.equal(sandbox.FindProxyForURL(`ftp://${host}/file`, host), 'DIRECT', host);
}