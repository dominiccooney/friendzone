// Run with Node's built-in runner: node --test tests/web_mcp_connect.test.cjs
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const web = path.join(__dirname, "../src/web");
const html = fs.readFileSync(path.join(web, "index.html"), "utf8");
const script = fs.readFileSync(path.join(web, "app.js"), "utf8");

function fixture({storage = new Map(), storageUnavailable = false, notificationPermission = null, secureContext = true, popupBlocked = false} = {}) {
  // Only model the DOM APIs used by the connection panel. IDs come from
  // the shipped HTML so missing/mismatched element wiring fails the test.
  const elements = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(([, id]) => ["#" + id, {
    value: "", innerHTML: "", textContent: "", disabled: false, listeners: {},
    addEventListener(type, listener) { this.listeners[type] = listener; },
    focus() { this.focused = true; },
    select() { this.selected = true; },
    scrollIntoView() { this.scrolled = true; },
    append(child) { this.child=child; },
    content: {cloneNode(){return {}; }},
    attributes: {}, setAttribute(name,value){this.attributes[name]=value;},
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
  let fakeKeyButtons = [];
  let revokeButtons = [];
  let clineOAuthButtons = [];
  const openedWindows = [];
  const intervals = [];
  const windowListeners = {};
  const history = {
    entries:[], index:-1, state:null,
    pushState(state) { this.entries.splice(this.index+1);this.entries.push(state);this.index++;this.state=state; },
    replaceState(state) { if(this.index<0){this.entries.push(state);this.index=0;}else this.entries[this.index]=state;this.state=state; },
    back() { if(this.index<=0)return;this.state=this.entries[--this.index];windowListeners.popstate?.({state:this.state}); },
  };
  const sandbox = {
    document: {
      title: "Friendzone",
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
        if (selector === "[data-escrow-copy]") {
          fakeKeyButtons=[...elements.get("#escrow-list").innerHTML.matchAll(/data-escrow-copy="([^"]*)"/g)].map(match=>({dataset:{escrowCopy:match[1]}}));
          return fakeKeyButtons;
        }
        if (selector === "[data-cline-oauth]") {
          clineOAuthButtons=[...elements.get("#escrow-list").innerHTML.matchAll(/data-cline-oauth="([^"]*)"/g)].map(match=>({dataset:{clineOauth:match[1]}}));
          return clineOAuthButtons;
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
    window: {
      history,addEventListener(type,listener){windowListeners[type]=listener;}, isSecureContext:secureContext, focus(){this.focused=true;},
      open(url,target){
        if(popupBlocked)return null;
        const opened={initialUrl:url,target,opener:{},closed:false,location:{replace(value){opened.url=value;}},close(){this.closed=true;}};
        openedWindows.push(opened);return opened;
      },
    }, navigator: {}, URL, URLSearchParams, console,
    confirm:()=>true,
    setTimeout(callback) { const timer = {callback, cancelled:false}; timers.push(timer); return timer; },
    clearTimeout(timer) { if (timer) timer.cancelled = true; },
    setInterval(callback) { const timer={callback,cancelled:false};intervals.push(timer);return timer; },
    clearInterval(timer) { if(timer)timer.cancelled=true; },
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
      authorization: null,
      identity: "source_ip",
      warnings: [],
      cline_config: {mcpServers:{"linear-via-friendzone":{transport:{
        type:"streamableHttp", url:"http://172.31.208.1:8082/mcp/linear",
      }}}},
    }),
  });
  return {run, element, sandbox, calls, seed, reply, timers, intervals, openedWindows, nav, views, storage, notifications, history, get permissionRequests(){return permissionRequests;}, copyButtons:()=>copyButtons, fakeKeyButtons:()=>fakeKeyButtons, clineOAuthButtons:()=>clineOAuthButtons, revokeButtons:()=>revokeButtons};
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
  assert.match(markup,/Post comment/); assert.match(markup,/addComment/);
  assert.match(markup,/harmless/); assert.match(markup,/opaque-node/); assert.match(markup,/Not an issue\/PR number/);
  assert.match(markup,/Comment text/); assert.match(markup,/&lt;img/); assert.doesNotMatch(markup,/<img|<details/);
  assert.match(markup,/When this field is included:/);
  assert.match(html,/Operation names are requester-controlled, untrusted text/);
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

test("unknown mutations expose every typed input without field expanders and separate response-only selections", () => {
  const f=fixture();
  const field={field:"convertPullRequestToDraft",response_name:"safeName",path:["safeName"],parent:null,action:null,target:null,conditions_text:[],
    arguments:{input:{kind:"object",value:{pullRequestId:{kind:"string",value:"PR_fixture"},futureFlag:{kind:"boolean",value:false},items:{kind:"list",value:[{kind:"object",value:{label:{kind:"string",value:"<img src=x>\nsecond line"},count:{kind:"int",value:"9007199254740993"}}}]},empty:{kind:"list",value:[]},absent:{kind:"null"},missing:{kind:"missing_variable",value:"optional"}}}},mutation_inputs:[]};
  const nested={field:"comments",response_name:"comments",path:["safeName","comments"],parent:0,arguments:{first:{kind:"int",value:"5"}},conditions_text:["@include(if: false) (not evaluated)"]};
  const graph={...parsedGraphql,analysis:{...parsedGraphql.analysis,fields:[field,nested,{field:"id",response_name:"id",path:["safeName","id"],parent:0,arguments:{}}],effective_variables:[{name:"n",declared_type:"Int",source:"default",value:{kind:"int",value:"5"}}]}};
  f.run(`renderGraphqlReview(${JSON.stringify(graph)})`);
  const markup=f.sandbox.document.querySelector("#request-graphql-fields").innerHTML;
  for(const text of ["PR_fixture","input.futureFlag","false","input.items[0].label","9007199254740993","input.empty","[]","null","Not supplied ($optional)","first","@include(if: false)"]) assert.ok(markup.includes(text),text);
  assert.doesNotMatch(markup,/<details|<img/);assert.match(markup,/&lt;img/);
  assert.match(f.sandbox.document.querySelector("#request-graphql-response").textContent,/safeName → id/);
  assert.equal(f.sandbox.document.querySelector("#request-graphql-no-arguments").open,false);
  assert.equal(f.sandbox.document.querySelector("#request-graphql-no-arguments-count").textContent,"(1)");
  assert.match(f.sandbox.document.querySelector("#request-graphql-effective").innerHTML,/default.*5/s);
  assert.equal(f.sandbox.document.querySelector("#request-graphql-variables-panel").hidden,false);
});

test("review timing distinguishes broker expiry from early cancellation without claiming a timeout", () => {
  const f=fixture(), created="2026-09-11T05:00:00Z";
  assert.match(f.run(`reviewTiming({status:"pending",created_at:"${created}",expires_at:"2026-09-11T05:02:00Z"}, Date.parse("2026-09-11T05:00:30Z"))`),/Waiting 30s · 90s.*Client timeout may be shorter/);
  assert.match(f.run(`reviewTiming({status:"cancelled",created_at:"${created}",updated_at:"2026-09-11T05:00:25Z"})`),/25s.*timeout or cancellation is possible/);
  assert.equal(f.run(`reviewTiming({status:"cancelled",created_at:"${created}",updated_at:"2026-09-10T00:00:00Z"})`),"");
});

test("async upstream diagnostics separate approval latency and retain only broker-supplied safe metadata", async () => {
  const f=fixture();
  const upstream={approved_at:"2026-09-15T01:20:18Z",started_at:"2026-09-15T01:20:20Z",headers_at:"2026-09-15T01:20:27Z",finished_at:"2026-09-15T01:20:27Z",accepted_to_approval_ms:12917,approval_to_admission_ms:2000,accepted_to_admission_ms:14917,time_to_headers_ms:7000,total_ms:7001,remote_addr:"140.82.112.5:443",http_version:"HTTP/2.0",response_headers:[["x-github-request-id","ABC1:DEF2:3"],["server","GitHub.com"]],response_bytes:0,response_complete:true,transport_error:null};
  const job={...pendingRequest,asynchronous:true,status:"upstream_error",http_status:499,outcome:"GitHub returned HTTP 499",created_at:"2026-09-15T01:20:05Z",updated_at:"2026-09-15T01:20:27Z",upstream};
  const opening=f.run('openRequestReview("request-id")');
  f.calls.at(-1).resolve({ok:true,json:async()=>job});await opening;
  assert.match(f.sandbox.document.querySelector("#request-review-timing").textContent,/12917 ms to approval.*2000 ms approval to admission.*7001 ms in upstream transport/);
  const detail=f.sandbox.document.querySelector("#request-review-upstream").textContent;
  assert.match(detail,/Accepted → approval: 12917 ms/);
  assert.match(detail,/Approval → admission: 2000 ms/);
  assert.match(detail,/Admission → response headers: 7000 ms/);
  assert.match(detail,/x-github-request-id: ABC1:DEF2:3/);
  assert.match(detail,/Observed response body: 0 bytes/);
});

test("HTTP 200 GraphQL errors explain the separate transport and application results", async () => {
  const f=fixture(), element=id=>f.sandbox.document.querySelector("#"+id);
  const graphql_response={error_count:2,data_present:true,response_bytes:321,content_type:"application/json; charset=utf-8",response_headers:[["x-github-request-id","ABC:123"],["via","edge"]],errors:[
    {message:"Field 'badField' doesn't exist <script>",path:"repository → issue",locations:["line 3, column 5"],kind:"undefinedField"},
    {message:"Resource not accessible",path:null,locations:[],kind:"FORBIDDEN"},
  ]};
  const detail={...pendingRequest,status:"graphql_error",http_status:200,outcome:"old generic text",graphql_response};
  const opening=f.run('openRequestReview("request-id")');
  f.calls.at(-1).resolve({ok:true,json:async()=>detail});await opening;
  assert.equal(element("request-review-badge").textContent,"GraphQL errors · HTTP 200 response");
  assert.match(element("request-review-outcome").textContent,/response arrived.*application-level errors/i);
  assert.equal(element("request-graphql-error").hidden,false);
  assert.match(element("request-graphql-error-explanation").textContent,/syntax.*GitHub's schema/i);
  const diagnostics=element("request-graphql-error-detail").textContent;
  for(const expected of ["2 GraphQL errors","part of the operation may have succeeded","badField","path repository → issue","x-github-request-id: ABC:123"])assert.match(diagnostics,new RegExp(expected));
  assert.equal(element("request-graphql-error-detail").innerHTML,"");
});

test("compact overview puts operation repository and HTTP errors in one row without repeated prose",()=>{
  const f=fixture();
  const job={...pendingRequest,status:'response_received',http_status:499,outcome:'Response received',updated_at:'2026-09-14T09:14:17Z',facts:{operation_name:'PublishBackgroundCommandStreaming',operation_type:'mutation',fields:['createCommitOnBranch'],repositories:['cline/cline'],targets:['branch feature'],more:false}};
  const markup=f.run(`reviewTable([${JSON.stringify(job)}],"empty")`);
  assert.match(markup,/<table/);assert.match(markup,/<td[^>]*>PublishBackgroundCommandStreaming<\/td>/);
  assert.match(markup,/href="https:\/\/github\.com\/cline\/cline"[^>]*>cline\/cline<\/a> · branch feature<\/td>/);assert.match(markup,/>HTTP 499<\/span>/);
  assert.doesNotMatch(markup,/Response received|<article|<p>/);
  assert.match(markup,/createCommitOnBranch/);assert.match(markup,/&lt;script&gt;/);
  f.run(`snapshot.pending_requests=[];snapshot.containers=[];renderPendingRequests()`);
  assert.equal(f.sandbox.document.querySelector('#pending-section').hidden,true);
  assert.equal(f.sandbox.document.querySelector('#attention-empty').hidden,false);
  f.run(`snapshot.pending_requests=[${JSON.stringify(pendingRequest)}];renderPendingRequests()`);
  assert.equal(f.sandbox.document.querySelector('#pending-section').hidden,false);
  assert.equal(f.sandbox.document.querySelector('#attention-empty').hidden,true);
});

test("compact targets independently link repositories and every GitHub artifact",()=>{
  const f=fixture();
  const facts={operation_name:"Inspect",operation_type:"query",fields:["repository"],repositories:["cline/cline"],targets:["#1234"],more:false};
  const markup=f.run(`reviewTable([{...${JSON.stringify(pendingRequest)},facts:${JSON.stringify(facts)}}],"empty")`);
  assert.match(markup,/<a href="https:\/\/github\.com\/cline\/cline" target="_blank" rel="noopener noreferrer">cline\/cline<\/a> · <a href="https:\/\/github\.com\/cline\/cline\/issues\/1234" target="_blank" rel="noopener noreferrer">#1234<\/a>/);
  const pull=f.run(`reviewTarget({...${JSON.stringify(facts)},artifacts:[{repository:"cline/cline",number:"1234",kind:"pull_request"}]}).markup`);
  assert.match(pull,/href="https:\/\/github\.com\/cline\/cline\/pull\/1234"/);
  const issue=f.run(`reviewTarget({...${JSON.stringify(facts)},artifacts:[{repository:"cline/cline",number:"1234",kind:"issue"}]}).markup`);
  assert.match(issue,/href="https:\/\/github\.com\/cline\/cline\/issues\/1234"/);

  const repository=f.run(`reviewTarget({repositories:["cline/cline"],targets:[]}).markup`);
  assert.equal(repository,'<a href="https://github.com/cline/cline" target="_blank" rel="noopener noreferrer">cline/cline</a>');
  const branch=f.run(`reviewTarget({repositories:["cline/cline"],targets:["branch feature"]}).markup`);
  assert.match(branch,/href="https:\/\/github\.com\/cline\/cline"/);assert.match(branch,/ · branch feature$/);
  const multiple=f.run(`reviewTarget({repositories:["cline/cline"],targets:["#12","#34"],artifacts:[{repository:"cline/cline",number:"12",kind:"pull_request"},{repository:"cline/cline",number:"34",kind:"pull_request"}]}).markup`);
  assert.match(multiple,/href="https:\/\/github\.com\/cline\/cline"[^>]*>cline\/cline<\/a> · <a href="https:\/\/github\.com\/cline\/cline\/pull\/12"[^>]*>#12<\/a> · <a href="https:\/\/github\.com\/cline\/cline\/pull\/34"[^>]*>#34<\/a>/);
  const ambiguous=f.run(`reviewTarget({repositories:["one/repo","two/repo"],targets:["#12"]}).markup`);
  assert.match(ambiguous,/href="https:\/\/github\.com\/one\/repo"/);assert.match(ambiguous,/href="https:\/\/github\.com\/two\/repo"/);assert.doesNotMatch(ambiguous,/href="[^"]+\/(?:issues|pull)\/12"/);assert.match(ambiguous,/#12$/);
  const hostile=f.run(`reviewTarget({repositories:["cline/<script>"],targets:["#12"]}).markup`);
  assert.doesNotMatch(hostile,/<a|<script>/);assert.match(hostile,/&lt;script&gt;/);
});

test("large value references render exact content in arguments and variables without expanders",()=>{
  const f=fixture(),text='<script> & '+"long content ".repeat(10000);
  const value={kind:'reference',value:'content-hash'};
  const graph={status:'parsed',analysis:{...parsedGraphql.analysis,large_values:{'content-hash':text},effective_variables:[{name:'body',declared_type:'String!',source:'supplied',value}],fields:[{field:'createCommitOnBranch',response_name:'createCommitOnBranch',path:['createCommitOnBranch'],parent:null,arguments:{contents:value},conditions_text:[]}]}};
  f.run(`renderGraphqlReview(${JSON.stringify(graph)})`);
  const fields=f.sandbox.document.querySelector('#request-graphql-fields').innerHTML;
  assert.ok(fields.includes(text.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;')));
  assert.doesNotMatch(fields,/<details|<script>/);
  assert.doesNotMatch(f.sandbox.document.querySelector('#request-graphql-effective').innerHTML,/Missing value/);
  assert.doesNotMatch(f.sandbox.document.querySelector('#request-graphql-warning').textContent,/Structured review unavailable|budget/);
});

test("async jobs keep normal approval controls without claiming a live waiting client", async () => {
  const f=fixture();
  const job={...pendingRequest,asynchronous:true,status:"pending",outcome:"Awaiting host approval",created_at:"2026-09-11T05:00:00Z"};
  const opening=f.run('openRequestReview("request-id")');
  f.calls.at(-1).resolve({ok:true,json:async()=>job});await opening;
  assert.equal(f.sandbox.document.querySelector("#request-approve").disabled,false);
  assert.match(f.sandbox.document.querySelector("#request-review-timing").textContent,/Async job.*Client does not need to wait/);
  f.run('applyReviewOutcome({status:"cancelled",outcome:"Broker restarted before execution. Not sent."})');
  assert.equal(f.sandbox.document.querySelector("#request-approve").disabled,true);
  assert.doesNotMatch(f.sandbox.document.querySelector("#request-review-timing").textContent,/timeout|client.*cancell/i);
});

test("Git publication preparation cannot approve and refetches the derived review before enabling approval", async () => {
  const f=fixture(), element=id=>f.sandbox.document.querySelector("#"+id);
  const preparing={...pendingRequest,method:"GIT PUSH",asynchronous:true,status:"preparing",outcome:"Validating bundle and deriving review",git_push:null};
  const opening=f.run('openRequestReview("request-id")');
  f.calls.at(-1).resolve({ok:true,json:async()=>preparing});await opening;
  assert.equal(element("request-approve").disabled,true);
  assert.equal(element("request-review-actions").hidden,true);
  assert.match(element("request-review-timing").textContent,/No publication is approvable yet/);
  const before=f.calls.length;
  f.run('applyReviewOutcome({status:"pending",updated_at:"2099-01-02T00:00:00Z",outcome:"Awaiting host approval"})');
  assert.equal(f.calls.length,before+1);
  const refetch=f.calls.at(-1);
  assert.equal(refetch.url,"/api/requests/request-id");
  assert.equal(element("request-approve").disabled,true,"summary-only transition must not enable approval");
  const review={repository:"cline/cline",branch:"feature",expected_oid:"0".repeat(40),base_oid:"1".repeat(40),head_oid:"2".repeat(40),bundle_sha256:"3".repeat(64),bundle_bytes:123,
    commits:[{oid:"2".repeat(40),parents:["1".repeat(40)],author:"A <script>",email:"a@example.test",authored_at:"2026-09-15T00:00:00Z",subject:"subject",message:"subject\n\n<body & detail>"}],
    files:[{commit_oid:"2".repeat(40),status:"R100",old_path:"old<script>",path:"new&name"}],patch:"diff --git a/x b/x\n+<script>literal patch</script>\n"};
  refetch.resolve({ok:true,json:async()=>({...preparing,status:"pending",updated_at:"2099-01-02T00:00:00Z",outcome:"Awaiting host approval",git_push:review})});
  await new Promise(setImmediate);
  assert.equal(element("request-approve").disabled,false);
  assert.equal(element("request-git-push").hidden,false);
  assert.match(element("request-git-push-refs").textContent,/refs\/heads\/feature.*Reviewed head OID/s);
  assert.doesNotMatch(element("request-git-push-refs").textContent,/Base branch/);
  const commits=element("request-git-push-commits").innerHTML;
  assert.match(commits,/A &lt;script&gt;/);assert.match(commits,/&lt;body &amp; detail&gt;/);assert.doesNotMatch(commits,/<script>|<body/);
  const files=element("request-git-push-files").innerHTML;
  assert.match(files,/old&lt;script&gt; → new&amp;name/);assert.doesNotMatch(files,/<script>/);
  assert.equal(element("request-git-push-patch").textContent,review.patch);
  assert.equal(element("request-git-push-patch").innerHTML,"");
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
    assert.equal(element("#request-review-badge").textContent,"Pending");
    const markup=element("#request-graphql-fields").innerHTML;
    assert.ok(markup.includes(example.action)); assert.ok(markup.includes(example.highlight));
    assert.match(markup,/graphql-values/);assert.doesNotMatch(markup,/<img|<script|<details/);
    assert.equal(element("#comment-permission-panel").hidden,true);
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
  assert.equal(f.sandbox.document.title,"(1) Friendzone");
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
test("review outcomes stay visible, survive reopening and never enable resolved actions", async () => {
  const f=fixture(), element=id=>f.sandbox.document.querySelector("#"+id);
  f.run(`snapshot.pending_requests=[${JSON.stringify(pendingRequest)}]`);
  const opening=f.run('openRequestReview("request-id")');
  f.calls.at(-1).resolve({ok:true,json:async()=>pendingRequest}); await opening;
  for (const [status,code,label] of [["approved",null,"Approved"],["sending",null,"Sending"],["response_received",201,"Response received · HTTP 201"],["graphql_error",200,"GraphQL errors · HTTP 200 response"],["denied",null,"Denied"],["expired",null,"Expired"],["cancelled",null,"Cancelled"],["blocked",null,"Blocked"],["upstream_error",502,"HTTP 502"]]) {
    const summary={...pendingRequest,status,http_status:code,outcome:"Exact outcome <script>",updated_at:"2099-01-01T00:00:00Z"};
    f.run(`snapshot.pending_requests=[];snapshot.recent_reviews=[${JSON.stringify(summary)}];renderPendingRequests()`);
    assert.equal(element("request-review-badge").textContent,label);
    if(status==="graphql_error")assert.match(element("request-review-outcome").textContent,/response arrived.*application-level errors/i);
    else assert.equal(element("request-review-outcome").textContent,summary.outcome);
    assert.equal(element("request-review-outcome").innerHTML,"");
    assert.equal(element("request-review-body").textContent,pendingRequest.body);
    assert.equal(element("request-review").hidden,false);
    assert.equal(element("request-review-actions").hidden,true);
    assert.equal(element("inbox-count").textContent,0);
    assert.equal(element("recent-count").textContent,1);
    if(status==="graphql_error")assert.match(element("recent-reviews").innerHTML,/application-level errors/);
    else assert.match(element("recent-reviews").innerHTML,/Exact outcome &lt;script&gt;/);
    const calls=f.calls.length; await f.run('decideRequest("approve")'); assert.equal(f.calls.length,calls);
  }
  const reopening=f.run('openRequestReview("request-id")');
  f.calls.at(-1).resolve({ok:true,json:async()=>({...pendingRequest,status:"denied",outcome:"Not sent.",updated_at:"2099-02-01T00:00:00Z"})});await reopening;
  assert.equal(element("request-review-badge").textContent,"Denied");
  assert.equal(element("request-approve").disabled,true);
  f.run('snapshot.pending_requests=[];snapshot.recent_reviews=[];renderPendingRequests()');
  assert.equal(element("request-review-badge").textContent,"Not retained");
  assert.doesNotMatch(element("request-review-outcome").textContent,/Check the log/);
});

test("one-shot decisions need one click, never a confirmation dialog or automatic retry", async () => {
  for (const action of ["approve", "deny"]) {
    const f=fixture(), element=id=>f.sandbox.document.querySelector("#"+id);
    f.sandbox.confirm=()=>{assert.fail("one-shot approval must not open a dialog");};
    const opening=f.run('openRequestReview("request-id")');
    f.calls.at(-1).resolve({ok:true,json:async()=>pendingRequest});await opening;
    const submitting=element(`request-${action}`).onclick();
    const call=f.calls.at(-1);
    assert.equal(call.url,"/api/requests/request-id/decision");
    assert.deepEqual(JSON.parse(call.options.body),{fingerprint:"exact-hash",decision:action});
    assert.equal(call.options.headers["x-friendzone-review"],"1");
    assert.equal(element("request-approve").disabled,true);
    assert.equal(element("request-deny").disabled,true);
    const count=f.calls.length;
    await element(`request-${action}`).onclick();assert.equal(f.calls.length,count);
    call.resolve({ok:false,text:async()=>"request already cancelled"});await submitting;
    assert.equal(f.calls.length,count,"failed decision must not be replayed automatically");
    assert.match(element("request-review-status").textContent,/cancelled/);
    f.run(`applyReviewOutcome({status:"cancelled",outcome:"Not sent."})`);
    await element(`request-${action}`).onclick();assert.equal(f.calls.length,count);
  }
});

test("uncertain responses describe observed facts consistently in list and detail", async () => {
  const f=fixture(), element=id=>f.sandbox.document.querySelector("#"+id);
  const opening=f.run('openRequestReview("request-id")');
  f.calls.at(-1).resolve({ok:true,json:async()=>pendingRequest});await opening;
  for (const [code,label,message] of [[null,"No response received",/did not receive a reply.*may have completed/], [200,"Response incomplete · HTTP 200",/server replied.*complete response.*does not mean.*failed/]]) {
    const unknown={...pendingRequest,status:"unknown",http_status:code,outcome:"HTTP response was not fully observed. Check upstream before retrying.",updated_at:"2099-01-01T00:00:00Z"};
    f.run(`snapshot.pending_requests=[];snapshot.recent_reviews=[${JSON.stringify(unknown)}];renderPendingRequests()`);
    assert.equal(element("request-review-badge").textContent,label);
    const explanation=element("request-review-outcome").textContent;
    assert.match(explanation,message);
    assert.ok(element("recent-reviews").innerHTML.includes(label));
    assert.ok(element("recent-reviews").innerHTML.includes(explanation));
    assert.doesNotMatch(element("recent-reviews").innerHTML,/Outcome unknown|stale retry/);
    assert.equal(element("request-review-actions").hidden,true);
    assert.equal(f.run("activeReview.status"),"unknown","display must not fabricate a successful outcome");
    const reopening=f.run('openRequestReview("request-id")');
    f.calls.at(-1).resolve({ok:true,json:async()=>unknown});await reopening;
    assert.equal(element("request-review-badge").textContent,label);
  }
});

test("newer SSE outcome wins over slow detail and decision responses", async () => {
  const f=fixture(), element=id=>f.sandbox.document.querySelector("#"+id);
  const original={...pendingRequest,status:"pending",updated_at:"2099-01-01T00:00:00Z"};
  const resolved={...original,status:"response_received",updated_at:"2099-01-01T00:00:01Z",http_status:201,outcome:"Response received."};
  const opening=f.run('openRequestReview("request-id")');
  f.run(`snapshot.recent_reviews=[${JSON.stringify(resolved)}];renderPendingRequests()`);
  f.calls.at(-1).resolve({ok:true,json:async()=>original});await opening;
  assert.equal(element("request-review-badge").textContent,"Response received · HTTP 201");
  f.run(`activeReview=${JSON.stringify(original)};snapshot.pending_requests=[${JSON.stringify(original)}];snapshot.recent_reviews=[]`);
  const decision=f.run('decideRequest("approve")'), call=f.calls.at(-1);
  const count=f.calls.length;await f.run('decideRequest("approve")');assert.equal(f.calls.length,count,"double click submits once");
  f.run(`snapshot.pending_requests=[];snapshot.recent_reviews=[${JSON.stringify(resolved)}];renderPendingRequests()`);
  call.resolve({ok:true});await new Promise(setImmediate);
  assert.equal(element("request-review-badge").textContent,"Response received · HTTP 201");
  f.calls.at(-1).resolve({json:async()=>({containers:[],requests:[],pending_requests:[],recent_reviews:[resolved]})});await decision;
  assert.equal(element("request-review-badge").textContent,"Response received · HTTP 201");
  assert.equal(element("request-review-actions").hidden,true);
});

test("retained outcomes do not send notifications or increase pending count", () => {
  const f=fixture({notificationPermission:"granted",storage:new Map([["fz-notifications","enabled"]])});
  f.run(`snapshot.recent_reviews=[${JSON.stringify({...pendingRequest,status:"denied"})}];renderPendingRequests();renderPendingRequests()`);
  assert.equal(f.notifications.length,0);assert.equal(f.timers.length,0);
  assert.equal(f.sandbox.document.querySelector("#inbox-count").textContent,0);
});

test("slow state fetch cannot replace newer SSE outcomes with pending requests", async () => {
  const f=fixture();
  const refreshing=f.run('refresh()'), call=f.calls.at(-1);
  const resolved={...pendingRequest,status:"denied",outcome:"Denied. Not sent."};
  f.run(`events.onmessage({data:JSON.stringify({containers:[],requests:[],pending_requests:[],recent_reviews:[${JSON.stringify(resolved)}]})})`);
  call.resolve({ok:true,json:async()=>({containers:[],requests:[],pending_requests:[pendingRequest],recent_reviews:[]})});await refreshing;
  assert.equal(f.sandbox.document.querySelector("#pending-count").textContent,0);
  assert.match(f.sandbox.document.querySelector("#recent-reviews").innerHTML,/Denied/);
});

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
    assert.match(f.sandbox.document.querySelector("#pending-requests").innerHTML,/>Review</);
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

test("page title mirrors every request needing attention", () => {
  const f=fixture();
  assert.equal(f.sandbox.document.title,"Friendzone");
  f.run(`snapshot.pending_requests=[${JSON.stringify(pendingRequest)}];snapshot.containers=[{id:"join",approved:false,state:"pending"}];renderPendingRequests()`);
  assert.equal(f.sandbox.document.querySelector("#inbox-count").textContent,2);
  assert.equal(f.sandbox.document.title,"(2) Friendzone");
  f.run("snapshot.pending_requests=[];snapshot.containers=[];renderPendingRequests()");
  assert.equal(f.sandbox.document.title,"Friendzone");
});

test("browser back closes a review; Close deterministically replaces it with Inbox", async () => {
  const f=fixture();
  assert.equal(JSON.stringify(f.history.state),JSON.stringify({friendzone:true,view:"inbox",reviewId:null}));
  const opening=f.run('openRequestReview("request-id")');
  f.calls.at(-1).resolve({ok:true,json:async()=>pendingRequest});await opening;
  assert.equal(f.history.state.reviewId,"request-id");
  f.history.back();
  assert.equal(f.run("activeReview"),null);
  assert.equal(f.sandbox.document.querySelector("#request-review").hidden,true);

  f.nav.find(node=>node.dataset.view==="settings").onclick();
  const beforeOpen=f.history.index;
  f.nav.find(node=>node.dataset.view==="inbox").onclick();
  const reopened=f.run('openRequestReview("request-id")');
  f.calls.at(-1).resolve({ok:true,json:async()=>pendingRequest});await reopened;
  assert.equal(f.history.index,beforeOpen+2);
  const beforeClose=f.history.index;
  f.sandbox.document.querySelector("#request-close").onclick();
  assert.equal(f.history.index,beforeClose,"Close must not traverse unrelated browser history");
  assert.equal(f.history.state.view,"inbox");
  assert.equal(f.history.state.reviewId,null);
  assert.equal(f.run("activeReview"),null);
  assert.equal(f.sandbox.document.querySelector("#pending-requests").scrolled,true);
  f.history.back();
  assert.equal(f.history.state.view,"inbox");
  assert.equal(f.views.find(node=>node.classList.contains("active")).id,"inbox-view");
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

test("join errors stay in Inbox while preapproval errors stay in Settings", async () => {
  const f=fixture(), element=id=>f.sandbox.document.querySelector("#"+id);
  element("guest-joins").hidden=true;
  const join=f.run('changeContainerPolicy("/api/containers/guest/approve", {method:"POST"}, "#join-error")');
  f.calls.at(-1).resolve({ok:false,text:async()=>"join save failed"});await join;
  assert.match(element("join-error").textContent,/join save failed/);
  assert.equal(element("guest-joins").hidden,false);
  assert.equal(element("container-error").textContent,"");
  const create=f.run('changeContainerPolicy("/api/containers", {method:"POST"}, "#preapprove-status")');
  f.calls.at(-1).resolve({ok:false,text:async()=>"preapproval save failed"});await create;
  assert.match(element("preapprove-status").textContent,/preapproval save failed/);
  assert.doesNotMatch(element("join-error").textContent,/preapproval/);
});

test("guest setup opens one panel without granting access or clearing entered values", () => {
  const f=fixture(), element=id=>f.sandbox.document.querySelector("#"+id);
  element("guest-setup").hidden=true;
  element("setup-container").value="guest-name";
  const calls=f.calls.length;
  element("show-guest-setup").onclick();
  assert.equal(element("guest-setup").hidden,false);
  assert.equal(element("show-guest-setup").attributes["aria-expanded"],"true");
  element("show-guest-setup").onclick();
  assert.equal(element("guest-setup").hidden,true);
  assert.equal(element("setup-container").value,"guest-name");
  assert.equal(f.calls.length,calls,"no policy write from showing setup");
});

test("manual preapproval confirms wildcard scope, rejects existing guests and preserves input on failure", async () => {
  const f=fixture(), element=id=>f.sandbox.document.querySelector("#"+id);
  let resets=0, confirmation="";
  const event={preventDefault(){},target:{reset(){resets++;}}};
  element("new-container-name").value=" new-guest ";
  const submit=element("add-container").onsubmit(event);
  const call=f.calls.at(-1);
  assert.equal(call.url,"/api/containers");assert.deepEqual(JSON.parse(call.options.body),{name:"new-guest"});
  assert.equal(element("preapprove-guest").disabled,true);
  call.resolve({ok:false,text:async()=>"disk full"});await submit;
  assert.match(element("preapprove-status").textContent,/disk full/);assert.equal(resets,0);
  assert.equal(element("preapprove-guest").disabled,false);
  f.sandbox.confirm=message=>{confirmation=message;return false;};
  let count=f.calls.length;await element("add-container").onsubmit(event);assert.equal(f.calls.length,count);
  assert.match(confirmation,/any IP/);assert.match(confirmation,/does not set up/);
  f.run('snapshot.containers=[{id:"new-guest",approved:false,state:"pending"}]');
  await element("add-container").onsubmit(event);assert.equal(f.calls.length,count);
  assert.match(element("preapprove-status").textContent,/already exists/);
});

test("killed unapproved guests are not actionable joins or badge counts", () => {
  const f=fixture();
  f.run('snapshot.containers=[{id:"joined",approved:false,state:"pending"},{id:"killed",approved:false,state:"killed"},{id:"ready",approved:true,state:"approved"}];renderPendingRequests()');
  assert.equal(f.run('guestJoinRequests().length'),1);
  assert.equal(f.sandbox.document.querySelector("#inbox-count").textContent,1);
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

async function resolveSettings(f, forwards = [], entries = []) {
  await new Promise(setImmediate);
  f.calls.filter(c=>c.url==="/api/escrow").at(-1).resolve({json:async()=>({entries})});
  f.calls.filter(c=>c.url==="/api/mcp").at(-1).resolve({json:async()=>({forwards,guest_host:"172.31.208.1",guest_port:8082})});
}

test("credential rows copy the selected fake key without exposing the real key", async () => {
  const f=fixture(), entry={name:"github",hosts:["api.github.com"],header:"authorization",prefix:"Bearer ",fake:"ghp_friendzone_fake",connected:true};
  const render=f.run("renderSettings()");await resolveSettings(f,[],[entry]);await render;
  assert.match(f.sandbox.document.querySelector("#escrow-list").innerHTML,/Copy fake key/);
  let copied;f.sandbox.navigator.clipboard={async writeText(value){copied=value;}};
  const [button]=f.fakeKeyButtons();await button.onclick();
  assert.equal(copied,entry.fake);
  assert.equal(f.sandbox.document.querySelector("#escrow-copy-status").textContent,"Fake key for 'github' copied.");
  delete f.sandbox.navigator.clipboard;await button.onclick();
  assert.equal(f.sandbox.document.querySelector("#escrow-copy-value").selected,true);
});

test("Cline device sign-in opens in the admin browser and survives popup blocking", async () => {
  const entry={name:"cline",hosts:["api.cline.bot"],header:"authorization",prefix:"Bearer ",fake:"fz-cline-fake",connected:false};
  for(const popupBlocked of [false,true]){
    const f=fixture({popupBlocked});
    const render=f.run("renderSettings()");await resolveSettings(f,[],[entry]);await render;
    const [button]=f.clineOAuthButtons();
    const pending=button.onclick();
    assert.equal(f.openedWindows.length,popupBlocked?0:1,"popup must be reserved before the request completes");
    const call=f.calls.at(-1);assert.equal(call.url,"/api/escrow/cline/cline-oauth/start");
    call.resolve({ok:true,json:async()=>({state:"waiting_for_user",user_code:"ABCD-EFGH",verification_uri:"https://auth.example/device?user_code=ABCD-EFGH"})});
    await pending;
    if(popupBlocked){
      assert.match(f.sandbox.document.querySelector("#e-hint").innerHTML,/browser blocked.*open the sign-in page/i);
    }else{
      assert.equal(f.openedWindows[0].initialUrl,"about:blank");
      assert.equal(f.openedWindows[0].target,"_blank");
      assert.equal(f.openedWindows[0].opener,null);
      assert.equal(f.openedWindows[0].url,"https://auth.example/device?user_code=ABCD-EFGH");
    }
    assert.equal(f.intervals.length,1,"device flow continues polling in either case");
  }
});

test("OAuth browser navigation rejects non-HTTP schemes and closes its placeholder", () => {
  const f=fixture();
  const browser=f.run("prepareOAuthBrowser()");
  f.sandbox.window.openedForTest=browser;
  assert.equal(f.run('navigateOAuthBrowser(window.openedForTest,"javascript:alert(1)")'),false);
  assert.equal(browser.closed,true);
  assert.equal(browser.url,undefined);
});

test("guest bootstrap commands discard stale responses, use explicit platform choices and copy safely", async () => {
  const f=fixture(); const element=id=>f.sandbox.document.querySelector("#setup-"+id);
  element("host").value="172.31.208.1"; element("container").value="scratch-kali";
  const first=f.run("loadGuestSetup()"); const old=f.calls.at(-1);
  element("host").value="192.0.2.1";
  const second=f.run("loadGuestSetup()"); const current=f.calls.at(-1);
  assert.match(current.url,/host=192.0.2.1/);
  const reply={broker:"http://192.0.2.1:9082",sh:"safe-linux-command",powershell:"safe-powershell-command",sh_url:"http://192.0.2.1:9082/bootstrap/setup?shell=sh",powershell_url:"http://192.0.2.1:9082/bootstrap/setup?shell=powershell"};
  current.resolve({ok:true,json:async()=>reply}); await second;
  old.resolve({ok:true,json:async()=>({...reply,sh:"stale"})}); await first;
  assert.equal(element("sh").value,"safe-linux-command");
  assert.equal(element("powershell").value,"safe-powershell-command");
  assert.equal(element("view-sh").href,reply.sh_url);
  let copied;f.sandbox.navigator.clipboard={async writeText(text){copied=text;}};
  await element("copy-powershell").onclick(); assert.equal(copied,reply.powershell);
  assert.match(element("status").textContent,/guest terminal/);
  element("host").value="";await f.run("loadGuestSetup()");
  assert.equal(element("sh").value,"");assert.equal(element("copy-sh").disabled,true);
  assert.equal(element("view-sh").hidden,true);
});

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
  assert.equal(f.element("copy-status").textContent, "Endpoint copied.");
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
  assert.match(f.element("list").innerHTML, /enter a reachable host/);
  assert.equal(f.copyButtons().length,0);
});

test("broker OAuth posts selected scope and reports completion without guest login", async () => {
  const f=fixture();
  const start=f.run('startMcpOAuth("Linear", "read")');
  const call=f.calls.at(-1);
  assert.equal(call.url,"/api/mcp/Linear/oauth/start");
  assert.equal(call.options.method,"POST");
  assert.deepEqual(JSON.parse(call.options.body),{scope:"read"});
  assert.equal(f.openedWindows.length,1,"popup is reserved synchronously from the user action");
  const authorizeUrl="https://auth.example/authorize?response_type=code&client_id=test&redirect_uri=http%3A%2F%2F127.0.0.1%3A8081%2Foauth%2Fcallback&state=abc&scope=read%20write";
  call.resolve({ok:true,json:async()=>({authorize_url:authorizeUrl})});
  await resolveSettings(f); await start;
  assert.equal(f.element("oauth-link").href,authorizeUrl);
  assert.equal(f.element("oauth-url").value,authorizeUrl);
  assert.equal(f.element("oauth-redirect").value,"http://127.0.0.1:8081/oauth/callback");
  assert.equal(f.openedWindows[0].opener,null);
  assert.equal(f.openedWindows[0].url,authorizeUrl);
  assert.match(f.element("oauth-status").textContent,/browser tab that opened/);
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

test("popup-blocked MCP OAuth keeps Open and Copy recovery available", async () => {
  const f=fixture({popupBlocked:true});
  const start=f.run('startMcpOAuth("Linear", "read")');
  const authorizeUrl="https://auth.example/authorize?redirect_uri=http%3A%2F%2F127.0.0.1%3A8081%2Foauth%2Fcallback";
  f.calls.at(-1).resolve({ok:true,json:async()=>({authorize_url:authorizeUrl})});
  await resolveSettings(f);await start;
  assert.equal(f.element("oauth-link").href,authorizeUrl);
  assert.equal(f.element("oauth-link").hidden,false);
  assert.equal(f.element("copy-oauth").disabled,false);
  assert.match(f.element("oauth-status").textContent,/browser blocked/);
});

test("Add & authorize saves a private server and immediately starts sign-in", async () => {
  const f=fixture();
  f.element("name").value="Linear"; f.element("url").value="https://mcp.linear.app/mcp";
  f.element("scope").value="read";
  const pending=f.element("save-oauth").onclick();
  assert.equal(f.openedWindows.length,1,"the original click reserves the browser before saving");
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
  const authorizeUrl="https://auth.example/authorize?redirect_uri=http%3A%2F%2F127.0.0.1%3A8081%2Foauth%2Fcallback";
  login.resolve({ok:true,json:async()=>({authorize_url:authorizeUrl})});
  await resolveSettings(f,[{...linearForward,auth:"oauth-required",tools:[],guests:[]}]);
  await pending;
  assert.equal(f.element("save-oauth").disabled,false);
  assert.equal(f.element("oauth-panel").hidden,false);
  assert.equal(f.openedWindows.length,1,"nested OAuth must reuse the reserved browser");
  assert.equal(f.openedWindows[0].url,authorizeUrl);
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
  assert.equal(f.openedWindows[0].closed,true,"cancelling must close the reserved sign-in tab");
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
  assert.equal(json.mcpServers["linear-via-friendzone"].transport.headers,undefined);
  assert.equal(f.element("copy-json").disabled, false);
  let copied;
  f.sandbox.navigator.clipboard = {async writeText(text) { copied = text; }};
  await f.element("copy-json").onclick();
  assert.equal(copied, f.element("connect-json").value);
  delete f.sandbox.navigator.clipboard;
  assert.equal(f.element("copy-auth").disabled,true);
  assert.match(f.element("connect-auth").value,/pinned source IP/);
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
  await pending;
  assert.equal(f.element("connect-host").value, "my-broker.local");
});

test("settings sections and guest platform persist without exposing the long form", () => {
  const storage=new Map([["fz-settings-section","mcp"],["fz-setup-platform","powershell"]]);
  const f=fixture({storage});const element=id=>f.sandbox.document.querySelector('#'+id);
  assert.equal(element('settings-mcp').hidden,false);assert.equal(element('settings-guests').hidden,true);
  assert.equal(element('setup-platform-sh').hidden,true);assert.equal(element('setup-platform-powershell').hidden,false);
  f.run('selectSettings("credentials");selectSetupPlatform("sh")');
  assert.equal(storage.get('fz-settings-section'),'credentials');assert.equal(storage.get('fz-setup-platform'),'sh');
  const reloaded=fixture({storage});assert.equal(reloaded.sandbox.document.querySelector('#settings-credentials').hidden,false);
  assert.doesNotMatch(html,/fz setup|matching fz binary|Guest environment \(manual\)|URL alone is not enough/);
  assert.doesNotMatch(script,/URL alone is not enough/);
});