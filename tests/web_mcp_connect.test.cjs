// Run with Node's built-in runner: node --test tests/web_mcp_connect.test.cjs
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const web = path.join(__dirname, "../src/web");
const html = fs.readFileSync(path.join(web, "index.html"), "utf8");
const script = fs.readFileSync(path.join(web, "app.js"), "utf8");

function fixture({storage = new Map(), storageUnavailable = false, notificationPermission = null, secureContext = true} = {}) {
  // Only model the DOM APIs used by the connection panel. IDs come from
  // the shipped HTML so missing/mismatched element wiring fails the test.
  const elements = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(([, id]) => ["#" + id, {
    value: "", innerHTML: "", textContent: "", disabled: false, listeners: {},
    addEventListener(type, listener) { this.listeners[type] = listener; },
    focus() { this.focused = true; },
    select() { this.selected = true; },
    scrollIntoView() { this.scrolled = true; },
  }]));
  const calls = [];
  const timers = [];
  const notifications = [];
  let permissionRequests = 0;
  class Notification {
    static permission = notificationPermission;
    static async requestPermission() { permissionRequests++; return this.permission = "granted"; }
    constructor(title, options) { this.title=title;this.options=options;notifications.push(this); }
    close() { this.closed=true; }
  }
  const classList = () => {
    const classes = new Set();
    return {toggle(name, enabled){if(enabled)classes.add(name);else classes.delete(name);}, contains(name){return classes.has(name);}};
  };
  const nav = ["inbox", "log", "settings"].map(view => ({
    dataset:{view}, classList:classList(), attributes:{},
    setAttribute(name,value){this.attributes[name]=value;}, removeAttribute(name){delete this.attributes[name];},
  }));
  const views = ["inbox", "log", "settings"].map(view => ({id:`${view}-view`, classList:classList()}));
  let copyButtons = [];
  let revokeButtons = [];
  const sandbox = {
    document: {
      querySelector(selector) {
        assert.ok(elements.has(selector), `HTML is missing ${selector}`);
        return elements.get(selector);
      },
      querySelectorAll(selector) {
        if (selector === ".nav") return nav;
        if (selector === ".view") return views;
        if (selector === "[data-comment-revoke]") {
          revokeButtons=[...elements.get("#comment-permissions").innerHTML.matchAll(/data-comment-revoke="([^"]*)" data-container="([^"]*)"/g)].map(match=>({dataset:{commentRevoke:match[1],container:match[2]}}));
          return revokeButtons;
        }
        if (selector !== "[data-mcp-copy-url]") return [];
        // Model row-level controls from the real rendered markup so tests
        // exercise both button wiring and choosing the guest (not upstream) URL.
        for (const button of copyButtons) button.input.isConnected = false;
        const markup = elements.get("#mcp-list").innerHTML;
        const values = [...markup.matchAll(/<textarea data-mcp-endpoint[^>]*>([^<]*)<\/textarea>/g)].map(match=>match[1]);
        copyButtons = [...markup.matchAll(/data-mcp-copy-url="([^"]*)"/g)].map((match, index) => {
          const input = {value:values[index], isConnected:true, focus(){this.focused=true;}, select(){this.selected=true;}};
          return {input, dataset:{mcpCopyUrl:match[1]}, closest(selector){assert.equal(selector,".mcp-card");return {querySelector(selector){assert.equal(selector,"[data-mcp-endpoint]");return input;}};}};
        });
        return copyButtons;
      },
    },
    localStorage: {
      getItem(key) { if(storageUnavailable)throw new Error("storage blocked");return storage.get(key) ?? null; },
      setItem(key,value) { if(storageUnavailable)throw new Error("storage blocked");storage.set(key,value); },
    },
    EventSource: class {},
    window: {addEventListener(){}, isSecureContext:secureContext, focus(){this.focused=true;}}, navigator: {}, URL, URLSearchParams, console,
    confirm:()=>true,
    setTimeout(callback) { const timer = {callback, cancelled:false}; timers.push(timer); return timer; },
    clearTimeout(timer) { if (timer) timer.cancelled = true; },
    fetch(url, options) {
      return new Promise(resolve => calls.push({url, options, resolve}));
    },
  };
  if (notificationPermission !== null) sandbox.Notification = Notification;
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
  return {run, element, sandbox, calls, seed, reply, timers, nav, views, storage, notifications, get permissionRequests(){return permissionRequests;}, copyButtons:()=>copyButtons, revokeButtons:()=>revokeButtons};
}

const pendingRequest = {id:"request-id",container:"guest<script>",method:"POST",url:"https://api.github.com/graphql?x=<script>",body_bytes:42,expires_at:"2099-01-01T00:00:00Z",fingerprint:"exact-hash",reason:"Review complete GraphQL payload",headers:[["authorization","[redacted]"]],body:'{"query":"<script>alert(1)</script>","variables":{"id":42}}'};

const parsedGraphql = {status:"parsed",analysis:{version:1,operation_type:"mutation",operation_name:"InnocentName",operation_count:1,
  formatted_document:'mutation InnocentName($input: AddCommentInput!) {\n  harmless: addComment(input: $input) {\n    clientMutationId\n  }\n}',
  supplied_variables:'{\n  "input": {"subjectId":"opaque-node","body":"<img src=x onerror=steal()>"}\n}',effective_variables:[],warnings:["Not schema validated; targets are unverified."],
  fields:[{field:"addComment",response_name:"harmless",path:["harmless"],parent:null,arguments:{},arguments_text:'input: {subjectId: "opaque-node", body: "<img src=x onerror=steal()>"}',conditions:[{kind:"directive",name:"skip",arguments:{if:{kind:"boolean",value:false}}}],conditions_text:["@skip(if: false) (not evaluated)"],action:"Post comment",comment_body:"<img src=x onerror=steal()>",target:{kind:"node_id",input_path:"input.subjectId",id:"opaque-node",expected_type:"Issue or PullRequest"}}]}};

test("GraphQL review shows actual action, opaque target and comment separately without executing markup", async () => {
  const f=fixture();
  const opening=f.run('openRequestReview("request-id")');
  f.calls.at(-1).resolve({ok:true,json:async()=>({...pendingRequest,graphql:parsedGraphql})}); await opening;
  const element=id=>f.sandbox.document.querySelector("#request-graphql-"+id);
  assert.match(element("operation").textContent,/MUTATION.*InnocentName/);
  assert.equal(element("document").textContent,parsedGraphql.analysis.formatted_document);
  assert.equal(element("variables").textContent,parsedGraphql.analysis.supplied_variables);
  const markup=element("fields").innerHTML;
  assert.match(markup,/Post comment/); assert.match(markup,/Actual field: <code>addComment/);
  assert.match(markup,/harmless/); assert.match(markup,/opaque-node/); assert.match(markup,/NOT an issue\/PR number/);
  assert.match(markup,/Comment text \(literal, not Markdown\)/); assert.match(markup,/&lt;img/); assert.doesNotMatch(markup,/<img/);
  assert.match(markup,/Conditions \(all branches retained\)/);
  assert.equal(f.sandbox.document.querySelector("#request-review-body").textContent,pendingRequest.body);
  assert.equal(f.run("activeReview.fingerprint"),"exact-hash");
});

test("structured GraphQL warnings and non-GraphQL reviews clear previously displayed targets", () => {
  const f=fixture(); f.run(`renderGraphqlReview(${JSON.stringify(parsedGraphql)})`);
  f.run('renderGraphqlReview({status:"unavailable",message:"fragment cycle <script>"})');
  assert.equal(f.sandbox.document.querySelector("#request-graphql-fields").innerHTML,"");
  assert.equal(f.sandbox.document.querySelector("#request-graphql-document").textContent,"");
  assert.match(f.sandbox.document.querySelector("#request-graphql-warning").textContent,/fragment cycle.*No operation or target was inferred/);
  assert.equal(f.sandbox.document.querySelector("#request-graphql-warning").innerHTML,"");
  f.run('renderGraphqlReview(null)'); assert.equal(f.sandbox.document.querySelector("#request-graphql").hidden,true);
});

test("repository issue/PR targets preserve repository context rather than extracting a bare number", () => {
  const f=fixture(); const graph=JSON.parse(JSON.stringify(parsedGraphql));
  Object.assign(graph.analysis,{operation_type:"query",operation_name:null});
  Object.assign(graph.analysis.fields[0],{field:"pullRequest",parent:0,action:null,comment_body:null,target:{kind:"repository_number",owner:"cline",repository:"cline",number:"482",expected_type:"PullRequest"}});
  f.run(`renderGraphqlReview(${JSON.stringify(graph)})`);
  assert.match(f.sandbox.document.querySelector("#request-graphql-fields").innerHTML,/cline\/cline #482.*not a verified pin/);
  assert.match(f.sandbox.document.querySelector("#request-graphql-operation").textContent,/QUERY.*anonymous/);
});

test("PR and review inputs are readable, escaped and explicitly manually approvable", async () => {
  const fixtures=JSON.parse(fs.readFileSync(path.join(__dirname,"fixtures/github_mutations.json"),"utf8"));
  for (const example of fixtures.filter(item=>item.body.variables?.input)) {
    const f=fixture();
    const input=example.body.variables.input;
    const analysis={...parsedGraphql.analysis,fields:[{...parsedGraphql.analysis.fields[0],field:example.field,action:example.action,comment_body:null,
      target:{kind:"node_id",input_path:example.target_path,id:"opaque-id",expected_type:example.target_type},
      mutation_inputs:Object.entries(input).map(([key,value])=>({path:`input.${key}`,label:key==="event"?"Review event (APPROVE / REQUEST_CHANGES / COMMENT)":key==="baseRefName"?"Base branch (destination)":key==="headRefName"?"Head branch (source)":key,value:JSON.stringify(value)}))}]};
    const opening=f.run('openRequestReview("request-id")');
    f.calls.at(-1).resolve({ok:true,json:async()=>({...pendingRequest,graphql:{status:"parsed",analysis},comment_permission_supported:false})});await opening;
    const element=id=>f.sandbox.document.querySelector(id);
    assert.match(element("#request-graphql-operation").textContent,/Manual approval required/);
    const markup=element("#request-graphql-fields").innerHTML;
    assert.ok(markup.includes(example.action)); assert.ok(markup.includes(example.highlight));
    assert.match(markup,/approve once only/);assert.doesNotMatch(markup,/<img|<script/);
    assert.match(element("#comment-permission-status").textContent,/allowed with Approve once below/);
    assert.equal(element("#request-approve").disabled,false);
    assert.equal(element("#save-comment-permission").disabled,true);
    const decision=f.run('decideRequest("approve")');const call=f.calls.at(-1);
    assert.equal(call.url,"/api/requests/request-id/decision");assert.deepEqual(JSON.parse(call.options.body),{fingerprint:"exact-hash",decision:"approve"});
    call.resolve({ok:false,text:async()=>"expired"});await decision;
  }
});

test("review renders guest payload literally and only submits the loaded fingerprint", async () => {
  const f=fixture();
  f.run(`snapshot.pending_requests=[${JSON.stringify(pendingRequest)}]; renderPendingRequests()`);
  const markup=f.sandbox.document.querySelector("#pending-requests").innerHTML;
  assert.ok(markup.includes("guest&lt;script&gt;")); assert.ok(!markup.includes("<script>"));
  assert.equal(f.sandbox.document.querySelector("#inbox-count").textContent,1);
  const opening=f.run('openRequestReview("request-id")');
  f.calls.at(-1).resolve({ok:true,json:async()=>pendingRequest}); await opening;
  assert.equal(f.sandbox.document.querySelector("#request-review-body").textContent,pendingRequest.body);
  assert.equal(f.sandbox.document.querySelector("#request-review-body").innerHTML,"");
  const decision=f.run('decideRequest("approve")');
  const call=f.calls.at(-1);
  assert.equal(call.url,"/api/requests/request-id/decision");
  assert.equal(call.options.headers["x-friendzone-review"],"1");
  assert.deepEqual(JSON.parse(call.options.body),{fingerprint:"exact-hash",decision:"approve"});
  call.resolve({ok:false,text:async()=>"already expired"}); await decision;
  assert.match(f.sandbox.document.querySelector("#request-review-status").textContent,/Could not confirm.*expired/);
  f.run('snapshot.pending_requests=[]; renderPendingRequests()');
  assert.equal(f.sandbox.document.querySelector("#request-approve").disabled,true);
  const count=f.calls.length; await f.run('decideRequest("approve")'); assert.equal(f.calls.length,count);
});

const verifiedTarget={node_id:"canonical",repository_id:"repo-id",repository:"cline/cline",kind:"Issue",number:482,title:"<img src=x> A real issue",url:"https://github.com/cline/cline/issues/482"};
test("resolve then grant requires confirmation, binds the displayed resolution, and never approves the pending write", async () => {
  const f=fixture(), element=id=>f.sandbox.document.querySelector("#"+id);
  f.run(`activeReview=${JSON.stringify({...pendingRequest,comment_permission_supported:true})}; renderCommentPermissionPanel(activeReview)`);
  assert.equal(element("save-comment-permission").disabled,true);
  const resolve=element("resolve-comment-target").onclick();const call=f.calls.at(-1);
  assert.equal(call.url,"/api/requests/request-id/github-target");assert.deepEqual(JSON.parse(call.options.body),{fingerprint:"exact-hash"});
  call.resolve({ok:true,json:async()=>({...pendingRequest,comment_permission_supported:true,resolution_id:"resolution",resolved_target:{target:verifiedTarget,credential:"github"}})});await resolve;
  assert.match(element("resolved-comment-target").textContent,/cline\/cline #482/);assert.equal(element("resolved-comment-target").innerHTML,"");
  let message; f.sandbox.confirm=text=>{message=text;return true;};
  const save=element("save-comment-permission").onclick();const grant=f.calls.at(-1);
  assert.match(message,/arbitrary text.*cline\/cline #482/);assert.match(message,/does NOT approve/);
  assert.equal(grant.url,"/api/requests/request-id/comment-permission");assert.deepEqual(JSON.parse(grant.options.body),{fingerprint:"exact-hash",resolution_id:"resolution"});
  grant.resolve({ok:true});await new Promise(setImmediate);
  f.calls.at(-1).resolve({json:async()=>({containers:[],requests:[],pending_requests:[pendingRequest],comment_permissions:[{id:"grant",container:"guest",target:verifiedTarget,credential:"github"}]})});
  // Avoid irrelevant container rendering in this unit fixture; the real
  // browser test covers the full snapshot render.
  f.run('renderContainers=()=>renderPendingRequests()');await save;
  assert.ok(!f.calls.some(c=>c.url.endsWith("/decision")));
  assert.match(element("comment-permission-status").textContent,/still needs Approve once or Deny/);
  assert.match(element("comment-permissions").innerHTML,/&lt;img/);
  const revoke=f.revokeButtons()[0].onclick();const revokeCall=f.calls.at(-1);
  assert.equal(revokeCall.options.method,"DELETE");assert.equal(revokeCall.options.headers["x-friendzone-review"],"1");
  revokeCall.resolve({ok:false,text:async()=>"disk full"});await revoke;
  assert.match(element("comment-permissions-status").textContent,/Could not confirm revocation.*disk full/);
});

test("stale target lookups cannot restore a closed review or a permission button", async () => {
  const f=fixture(), element=id=>f.sandbox.document.querySelector("#"+id);
  f.run(`activeReview=${JSON.stringify({...pendingRequest,comment_permission_supported:true})}; renderCommentPermissionPanel(activeReview)`);
  const resolve=element("resolve-comment-target").onclick();const call=f.calls.at(-1);
  element("request-close").onclick();
  call.resolve({ok:true,json:async()=>({...pendingRequest,comment_permission_supported:true,resolution_id:"stale",resolved_target:{target:verifiedTarget,credential:"github"}})});await resolve;
  assert.equal(f.run("activeReview"),null);assert.equal(element("save-comment-permission").disabled,true);
  assert.equal(element("comment-permission-panel").hidden,true);
});

test("stale asynchronous detail response cannot change the request being reviewed", async () => {
  const f=fixture();
  const first=f.run('openRequestReview("old")'); const firstCall=f.calls.at(-1);
  const second=f.run('openRequestReview("new")'); const secondCall=f.calls.at(-1);
  secondCall.resolve({ok:true,json:async()=>({...pendingRequest,id:"new",body:"new payload"})}); await second;
  firstCall.resolve({ok:true,json:async()=>({...pendingRequest,id:"old",body:"old payload"})}); await first;
  assert.equal(f.run("activeReview.id"),"new");
  assert.equal(f.sandbox.document.querySelector("#request-review-body").textContent,"new payload");
});

test("notification permission requires a click; bursts, SSE repeats and reloads are deduplicated", async () => {
  const storage=new Map(); const f=fixture({storage,notificationPermission:"default"});
  f.run(`snapshot.pending_requests=[${JSON.stringify(pendingRequest)}]; renderPendingRequests()`);
  assert.equal(f.permissionRequests,0); assert.equal(f.notifications.length,0);
  await f.sandbox.document.querySelector("#enable-notifications").onclick();
  assert.equal(f.permissionRequests,1);
  f.run('snapshot.pending_requests.push({...snapshot.pending_requests[0],id:"second"}); renderPendingRequests(); renderPendingRequests()');
  assert.equal(f.timers.length,1); f.timers[0].callback();
  assert.equal(f.notifications.length,1); assert.match(f.notifications[0].options.body,/2 new requests/);
  assert.ok(!JSON.stringify(f.notifications).includes("script"));
  f.run('renderPendingRequests()'); assert.equal(f.timers.length,1);
  f.notifications[0].onclick(); assert.equal(f.sandbox.window.focused,true);
  assert.equal(f.nav.find(n=>n.classList.contains("active")).dataset.view,"inbox");
  assert.equal(f.notifications[0].closed,true);
  assert.ok(!f.calls.some(call=>call.url.includes("/decision")));
  const reload=fixture({storage,notificationPermission:"granted"});
  reload.run(`snapshot.pending_requests=[${JSON.stringify(pendingRequest)},{...${JSON.stringify(pendingRequest)},id:"second"}]; renderPendingRequests()`);
  assert.equal(reload.notifications.length,0); assert.equal(reload.timers.length,0);
  await reload.sandbox.document.querySelector("#enable-notifications").onclick();
  assert.equal(storage.get("fz-notifications"),"disabled");
});

test("unsupported, insecure, denied notifications and disappeared requests leave Inbox usable", () => {
  for (const options of [{},{notificationPermission:"granted",secureContext:false},{notificationPermission:"denied"}]) {
    const f=fixture({...options,storage:new Map([["fz-notifications","enabled"]])});
    f.run(`snapshot.pending_requests=[${JSON.stringify(pendingRequest)}]; renderPendingRequests()`);
    assert.equal(f.notifications.length,0); assert.equal(f.permissionRequests,0);
    assert.ok(f.sandbox.document.querySelector("#notification-status").textContent);
    assert.match(f.sandbox.document.querySelector("#pending-requests").innerHTML,/Review request/);
  }
  const f=fixture({notificationPermission:"granted",storage:new Map([["fz-notifications","enabled"]])});
  f.run(`snapshot.pending_requests=[${JSON.stringify(pendingRequest)}]; renderPendingRequests(); snapshot.pending_requests=[]; renderPendingRequests()`);
  f.timers[0].callback(); assert.equal(f.notifications.length,0);
});

test("selected inbox/log/settings tab survives reload and loads its view", () => {
  for (const selected of ["inbox", "log", "settings"]) {
    const storage = new Map();
    const original = fixture({storage});
    original.nav.find(n=>n.dataset.view===selected).onclick();
    assert.equal(storage.get("fz-active-view"), selected);
    const reloaded = fixture({storage});
    assert.equal(reloaded.nav.find(n=>n.classList.contains("active")).dataset.view, selected);
    assert.equal(reloaded.views.find(n=>n.classList.contains("active")).id, `${selected}-view`);
    assert.equal(reloaded.nav.find(n=>n.dataset.view===selected).attributes["aria-current"], "page");
    if(selected==="settings") assert.ok(reloaded.calls.some(c=>c.url==="/api/mcp"));
    if(selected==="log") assert.ok(reloaded.calls.some(c=>c.url.startsWith("/api/log?")));
  }
});

test("invalid or unavailable browser storage cannot break navigation", () => {
  const invalid = fixture({storage:new Map([["fz-active-view", "not-a-tab"],["fz-order", "{"]])});
  assert.equal(invalid.nav.find(n=>n.classList.contains("active")).dataset.view, "inbox");
  assert.equal(invalid.run("order.length"), 0);
  const blocked = fixture({storageUnavailable:true});
  assert.equal(blocked.nav.find(n=>n.classList.contains("active")).dataset.view, "inbox");
  blocked.nav.find(n=>n.dataset.view==="settings").onclick();
  assert.equal(blocked.views.find(n=>n.classList.contains("active")).id, "settings-view");
});

test("container status reports permission, never guesses working or idle", () => {
  const f=fixture();
  assert.equal(f.run('containerStatus({approved:true,state:"approved"})'), "Approved");
  assert.equal(f.run('containerStatus({approved:true,state:"working"})'), "Approved", "old broker's state must not restore misleading wording");
  assert.equal(f.run('containerStatus({approved:false,state:"pending"})'), "Awaiting approval");
  assert.equal(f.run('containerStatus({approved:true,state:"killed"})'), "Killed");
  assert.match(f.run('containerTraffic({last_activity:null})'), /No guest traffic observed/);
  assert.match(f.run('containerTraffic({last_activity:"2026-09-09T01:00:00Z"})'), /Last guest traffic:/);
});

test("failed policy API change is visible and not reported as saved", async () => {
  const f=fixture();
  const change=f.run('changeContainerPolicy("/api/containers/guest/approve", {method:"POST"})');
  f.calls.at(-1).resolve({ok:false,text:async()=>"container policy change was not applied: disk full"});
  await change;
  assert.match(f.sandbox.document.querySelector("#container-error").textContent,/Change not applied:.*disk full/);
  assert.match(f.sandbox.document.querySelector("#container-error").textContent,/Existing policy remains in effect/);
});

test("a lost policy response is reported as unconfirmed rather than unchanged", async () => {
  const f=fixture();
  f.sandbox.fetch=async()=>{throw new Error("network disconnected");};
  await f.run('changeContainerPolicy("/api/containers/guest/kill", {method:"POST"})');
  const text=f.sandbox.document.querySelector("#container-error").textContent;
  assert.match(text,/Could not confirm.*network disconnected/);
  assert.match(text,/Refresh to check the actual policy/);
  assert.doesNotMatch(text,/Existing policy remains/);
});

async function resolveSettings(f, forwards = []) {
  await new Promise(setImmediate);
  f.calls.filter(c=>c.url==="/api/escrow").at(-1).resolve({json:async()=>({entries:[]})});
  f.calls.filter(c=>c.url==="/api/mcp").at(-1).resolve({json:async()=>({forwards,guest_host:"172.31.208.1",guest_port:8082})});
  f.calls.filter(c=>c.url==="/api/guest-env").at(-1).resolve({text:async()=>"# environment"});
}

const linearForward = {
  name:"Linear", url:"https://mcp.linear.app/mcp", tools:["read"], guests:["scratch-kali"],
  auth:"cline-link", guest_endpoint:"http://172.31.208.1:8082/mcp/Linear",
};

test("forward row explains Cline credential ownership and copies the Friendzone URL without a guest", async () => {
  const f=fixture();
  const render=f.run("renderSettings()"); await resolveSettings(f, [linearForward]); await render;
  assert.match(f.element("list").innerHTML, /Uses host Cline's credentials/);
  assert.match(f.element("list").innerHTML, /host Cline must refresh it/);
  assert.match(f.element("list").innerHTML, /Authorize in Friendzone/);
  assert.match(f.element("list").innerHTML, /class="mcp-card"/);
  assert.doesNotMatch(f.element("list").innerHTML, /class="log-row"|class="request"/);
  assert.equal(f.element("connect-guest").value, "");
  let copied;
  f.sandbox.navigator.clipboard={async writeText(value){copied=value;}};
  const [button]=f.copyButtons();
  await button.onclick();
  assert.equal(copied, linearForward.guest_endpoint);
  assert.notEqual(copied, linearForward.url);
  assert.match(f.element("copy-status").textContent, /required guest Authorization header/);
  assert.ok(!f.calls.some(call=>call.url.includes("guest-config")), "URL copy does not need credentials or guest selection");
  delete f.sandbox.navigator.clipboard;
  await button.onclick();
  assert.equal(button.input.selected,true);
  assert.match(f.element("copy-status").textContent,/Ctrl\+C/);
});

test("wildcard endpoint does not offer to copy a partial URL and broker OAuth is clearly labeled", async () => {
  const f=fixture();
  const render=f.run("renderSettings()");
  await resolveSettings(f, [{...linearForward, auth:"oauth", guest_endpoint:null}]); await render;
  assert.match(f.element("list").innerHTML, /Friendzone manages OAuth/);
  assert.match(f.element("list").innerHTML, /set the broker host/);
  assert.equal(f.copyButtons().length,0);
});

test("broker OAuth posts selected scope and reports completion without guest login", async () => {
  const f=fixture();
  const start=f.run('startMcpOAuth("Linear", "read")');
  const call=f.calls.at(-1);
  assert.equal(call.url,"/api/mcp/Linear/oauth/start");
  assert.equal(call.options.method,"POST");
  assert.deepEqual(JSON.parse(call.options.body),{scope:"read"});
  const authorizeUrl="https://auth.example/authorize?response_type=code&client_id=test&redirect_uri=http%3A%2F%2F127.0.0.1%3A8081%2Foauth%2Fcallback&state=abc&scope=read%20write";
  call.resolve({ok:true,json:async()=>({authorize_url:authorizeUrl,browser_opened:false})});
  await resolveSettings(f); await start;
  assert.equal(f.element("oauth-link").href,authorizeUrl);
  assert.equal(f.element("oauth-url").value,authorizeUrl);
  assert.equal(f.element("oauth-redirect").value,"http://127.0.0.1:8081/oauth/callback");
  assert.match(f.element("oauth-status").textContent,/could not be opened/);
  let copied;
  f.sandbox.navigator.clipboard={async writeText(value){copied=value;}};
  await f.element("copy-oauth").onclick();
  assert.equal(copied,authorizeUrl);
  const poll=f.timers.at(-1).callback();
  f.calls.at(-1).resolve({ok:true,json:async()=>({state:"connected"})});
  await resolveSettings(f); await poll;
  assert.equal(f.element("oauth-link").hidden,true);
  assert.match(f.element("form-status").textContent,/Friendzone now refreshes/);
  assert.equal(f.element("oauth-next").hidden,false);
});

test("Add & authorize saves a private server and immediately starts sign-in", async () => {
  const f=fixture();
  f.element("name").value="Linear"; f.element("url").value="https://mcp.linear.app/mcp";
  f.element("scope").value="read";
  const pending=f.element("save-oauth").onclick();
  f.calls.at(-1).resolve({json:async()=>[]});
  await new Promise(setImmediate);
  const save=f.calls.at(-1);
  assert.equal(save.url,"/api/mcp/config"); assert.equal(save.options.method,"PUT");
  const [config]=JSON.parse(save.options.body);
  assert.equal(config.oauth,true); assert.deepEqual(config.tools,[]); assert.deepEqual(config.guests,[]);
  save.resolve({ok:true});
  await resolveSettings(f,[{...linearForward,auth:"oauth-required",tools:[],guests:[]}]);
  await new Promise(setImmediate);
  const login=f.calls.at(-1);
  assert.equal(login.url,"/api/mcp/Linear/oauth/start");
  assert.deepEqual(JSON.parse(login.options.body),{scope:"read"});
  login.resolve({ok:true,json:async()=>({authorize_url:"https://auth.example/authorize?redirect_uri=http%3A%2F%2F127.0.0.1%3A8081%2Foauth%2Fcallback",browser_opened:true})});
  await resolveSettings(f,[{...linearForward,auth:"oauth-required",tools:[],guests:[]}]);
  await pending;
  assert.equal(f.element("save-oauth").disabled,false);
  assert.equal(f.element("oauth-panel").hidden,false);
  assert.match(html,/Add &amp; authorize/);
  assert.doesNotMatch(html,/Save for OAuth \(no tools\/guests yet\)/);
});

test("cancelled OAuth polling cannot restore a waiting or success state", async () => {
  const f=fixture();
  const start=f.run('startMcpOAuth("Linear", "read")');
  f.calls.at(-1).resolve({ok:true,json:async()=>({authorize_url:"https://auth.example/authorize"})});
  await resolveSettings(f); await start;
  const poll=f.timers.at(-1).callback();
  const request=f.calls.at(-1);
  f.run('cancelMcpOAuth("Linear")');
  const count=f.timers.length;
  request.resolve({ok:true,json:async()=>({state:"waiting_for_user"})}); await poll;
  assert.equal(f.timers.length,count,"stale poll must not schedule itself again");
  assert.equal(f.run('mcpOAuthPolls.has("Linear")'),false);
});

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
  f.run('snapshot.containers = [{id:"scratch-kali",name:"scratch-kali",approved:true,state:"approved"}]; updateMcpConnectionGuests()');
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