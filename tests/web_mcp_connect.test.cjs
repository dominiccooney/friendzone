// Run with Node's built-in runner: node --test tests/web_mcp_connect.test.cjs
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const web = path.join(__dirname, "../src/web");
const html = fs.readFileSync(path.join(web, "index.html"), "utf8");
const script = fs.readFileSync(path.join(web, "app.js"), "utf8");

function fixture() {
  // Only model the DOM APIs used by the connection panel. IDs come from
  // the shipped HTML so missing/mismatched element wiring fails the test.
  const elements = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(([, id]) => ["#" + id, {
    value: "", innerHTML: "", textContent: "", disabled: false, listeners: {},
    addEventListener(type, listener) { this.listeners[type] = listener; },
    focus() { this.focused = true; },
    select() { this.selected = true; },
  }]));
  const calls = [];
  const sandbox = {
    document: {
      querySelector(selector) {
        assert.ok(elements.has(selector), `HTML is missing ${selector}`);
        return elements.get(selector);
      },
      querySelectorAll() { return []; },
    },
    localStorage: { getItem() { return null; } },
    EventSource: class {},
    window: {}, navigator: {}, URLSearchParams, console,
    setTimeout, clearTimeout,
    fetch(url) {
      return new Promise(resolve => calls.push({url, resolve}));
    },
  };
  const context = vm.createContext(sandbox);
  vm.runInContext(script, context);
  const run = source => vm.runInContext(source, context);
  const element = id => elements.get("#mcp-" + id);
  const seed = () => {
    run('mcpConnectData = {forwards:[{name:"linear",tools:["read"]}]}');
    element("connect-forward").value = "linear";
    element("connect-guest").value = "scratch-kali";
    element("connect-host").value = "172.31.208.1";
  };
  const reply = (call, guest) => call.resolve({
    ok: true,
    json: async () => ({
      endpoint: "http://172.31.208.1:8082/mcp/linear",
      authorization: "Basic " + Buffer.from(guest + ":x").toString("base64"),
      warnings: [],
      cline_config: {mcpServers:{"linear-via-friendzone":{transport:{
        type:"streamableHttp", url:"http://172.31.208.1:8082/mcp/linear",
        headers:{Authorization:"Basic " + Buffer.from(guest + ":x").toString("base64")},
      }}}},
    }),
  });
  return {run, element, sandbox, calls, seed, reply};
}

test("guest change discards stale instructions and copies the current config", async () => {
  const f = fixture(); f.seed();
  const old = f.run("loadMcpConnection()");
  const oldCall = f.calls.at(-1);
  assert.ok(oldCall.url.includes("/api/mcp/linear/guest-config?guest=scratch-kali"));
  f.element("connect-guest").value = "guest-ü";
  const current = f.element("connect-guest").listeners.change();
  assert.equal(f.element("connect-json").value, "");
  assert.equal(f.element("copy-json").disabled, true);
  f.reply(f.calls.at(-1), "guest-ü"); await current;
  f.reply(oldCall, "scratch-kali"); await old;
  const json = JSON.parse(f.element("connect-json").value);
  const header = json.mcpServers["linear-via-friendzone"].transport.headers.Authorization;
  assert.equal(Buffer.from(header.slice(6), "base64").toString(), "guest-ü:x");
  assert.equal(f.element("copy-json").disabled, false);
  let copied;
  f.sandbox.navigator.clipboard = {async writeText(text) { copied = text; }};
  await f.element("copy-json").onclick();
  assert.equal(copied, f.element("connect-json").value);
  delete f.sandbox.navigator.clipboard;
  await f.element("copy-auth").onclick();
  assert.equal(f.element("connect-auth").selected, true);
  assert.match(f.element("connect-status").textContent, /Ctrl\+C/);
});

test("selection defaults, empty state, and guest refresh preserve user choices", () => {
  const f = fixture();
  f.run('fillMcpConnectSelect("#mcp-connect-forward", [{value:"linear",label:"linear"}], "Select")');
  assert.equal(f.element("connect-forward").value, "linear");
  f.run('fillMcpConnectSelect("#mcp-connect-forward", [{value:"linear",label:"linear"},{value:"github",label:"github"}], "Select")');
  assert.equal(f.element("connect-forward").value, "linear");
  f.element("connect-host").value = "my-broker.local";
  f.element("connect-guest").value = "scratch-kali";
  f.run('snapshot.containers = [{id:"scratch-kali",name:"scratch-kali",approved:true,state:"working"}]; updateMcpConnectionGuests()');
  assert.equal(f.element("connect-guest").value, "scratch-kali");
  assert.equal(f.element("connect-host").value, "my-broker.local");
  f.run('fillMcpConnectSelect("#mcp-connect-forward", [], "Select"); loadMcpConnection()');
  assert.equal(f.element("copy-json").disabled, true);
  assert.match(f.element("connect-status").textContent, /Select or add a forward/);
});

test("Settings refresh does not overwrite an edited broker host", async () => {
  const f = fixture(); f.seed();
  f.run("mcpHostInitialized = true");
  f.element("connect-host").value = "my-broker.local";
  const pending = f.run("renderSettings()");
  f.calls.find(c=>c.url==="/api/escrow").resolve({json:async()=>({entries:[]})});
  f.calls.find(c=>c.url==="/api/mcp").resolve({json:async()=>({
    forwards:[], guest_host:"172.31.208.1", guest_port:8082, guest_address_warning:null,
  })});
  f.calls.find(c=>c.url==="/api/guest-env").resolve({text:async()=>"# environment"});
  await pending;
  assert.equal(f.element("connect-host").value, "my-broker.local");
});