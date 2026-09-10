// Optional real-browser layout test, with no browser automation dependency:
// FZ_TEST_BROWSER=/absolute/path/to/chrome node --test tests/web_mcp_layout.test.cjs
const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { setTimeout: delay } = require("node:timers/promises");

const web = path.join(__dirname, "../src/web");

test("MCP cards show full URLs and usable actions at desktop and narrow widths", {
  skip: !process.env.FZ_TEST_BROWSER, timeout: 30000,
}, async () => {
  const name = "Linear-" + "long-server-name-".repeat(12);
  const endpoint = "http://172.31.208.1:8082/mcp/" + name;
  const forward = { name, url: "https://mcp.linear.app/mcp", tools: ["list_issues"],
    guests: ["scratch-kali"], auth: "oauth", guest_endpoint: endpoint };
  const state = { containers: [{ id: "scratch-kali", name: "scratch-kali", approved: true,
    state: "approved", request_count: 0, last_activity: null, pinned_ip: null }], requests: [] };
  const pending = {id:"request-id",container:"scratch-kali",method:"POST",url:"https://api.github.com/graphql?long="+"x".repeat(180),
    body_bytes:64,fingerprint:"immutable-hash",created_at:"2026-09-09T00:00:00Z",expires_at:"2099-01-01T00:00:00Z",reason:"GraphQL request needs review"};
  state.pending_requests=[pending];
  state.comment_permissions=[];
  const detail={...pending,headers:[["content-type","application/json"],["authorization","[redacted]"]],body:'{"query":"<img src=x onerror=window.pwned=true>","variables":{"value":"' + "payload".repeat(200) + '"}}'};
  detail.graphql={status:"parsed",analysis:{version:1,operation_type:"mutation",operation_name:"Comment",operation_count:1,
    formatted_document:'mutation Comment($input: AddCommentInput!) {\n  harmless: addComment(input: $input) {\n    clientMutationId\n  }\n}',supplied_variables:'{\n  "input": {"subjectId":"opaque","body":"<img src=x onerror=window.pwned=true>"}\n}',
    effective_variables:[],warnings:["Parsed syntax only; target is not verified."],fields:[{field:"addComment",response_name:"harmless",path:["harmless"],parent:null,arguments:{},arguments_text:"input: "+"long-argument-".repeat(250),conditions:[],action:"Post comment",comment_body:"<img src=x onerror=window.pwned=true>",target:{kind:"node_id",input_path:"input.subjectId",id:"opaque-"+"node".repeat(80),expected_type:"Issue or PullRequest"}}]}};
  const decisions=[];
  const permissionActions=[];
  const resolvedTarget={target:{node_id:"canonical",repository_id:"repo-id",repository:"cline/cline",kind:"Issue",number:482,title:"<img src=x onerror=window.pwned=true> A real issue",url:"https://github.com/cline/cline/issues/482"},credential:"github"};
  detail.comment_permission_supported=true;
  const server = http.createServer((request, response) => {
    const route = request.url.split("?")[0];
    if (route === "/api/events") {
      response.writeHead(200, { "content-type": "text/event-stream" });
      response.write("data: " + JSON.stringify(state) + "\n\n"); return;
    }
    if (route === "/api/requests/request-id/github-target" || route === "/api/requests/request-id/comment-permission") {
      let body="";request.on("data",chunk=>body+=chunk);request.on("end",()=>{
        permissionActions.push({route,headers:request.headers,body:JSON.parse(body)});
        response.writeHead(200,{"content-type":"application/json"});
        if(route.endsWith("github-target")) {detail.resolved_target=resolvedTarget;detail.resolution_id="resolution";response.end(JSON.stringify(detail));}
        else {state.comment_permissions=[{id:"grant",container:"scratch-kali",credential:"github",target:resolvedTarget.target}];response.end(JSON.stringify({id:"grant"}));}
      });return;
    }
    if (route === "/api/containers/scratch-kali/comment-permissions/grant" && request.method === "DELETE") {
      permissionActions.push({route});state.comment_permissions=[];response.writeHead(204);response.end();return;
    }
    if (route === "/api/requests/request-id/decision") {
      let body=""; request.on("data",chunk=>body+=chunk); request.on("end",()=>{
        decisions.push({headers:request.headers,body:JSON.parse(body)}); state.pending_requests=[];
        response.writeHead(204); response.end();
      }); return;
    }
    const assets = { "/": ["index.html", "text/html"], "/app.js": ["app.js", "text/javascript"], "/app.css": ["app.css", "text/css"] };
    if (assets[route]) {
      response.writeHead(200, { "content-type": assets[route][1] });
      response.end(fs.readFileSync(path.join(web, assets[route][0]), "utf8").replace("{{CLINE_MCP_SETTINGS_PATH}}", "C:/Users/host/.cline/data/settings/cline_mcp_settings.json")); return;
    }
    const replies = {
      "/api/state": state, "/api/escrow": { entries: [] },
      "/api/mcp": { forwards: [forward], guest_host: "172.31.208.1", guest_port: 8082 },
      "/api/mcp/config": [], "/api/log": { requests: [], next_before: null, retained: 0, capacity: 10000, evicted: 0 },
      "/api/requests/request-id":detail,
    };
    if (route === "/api/guest-env") { response.end("# environment"); return; }
    if (route.endsWith("/guest-config")) replies[route] = { endpoint, authorization: "Basic c2NyYXRjaC1rYWxpOng=", warnings: [], cline_config: { mcpServers: {} } };
    response.writeHead(route in replies ? 200 : 404, { "content-type": "application/json" });
    response.end(JSON.stringify(replies[route] || {}));
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "fz-browser-layout-"));
  const browser = spawn(process.env.FZ_TEST_BROWSER, ["--headless=new", "--no-first-run", "--no-default-browser-check",
    "--disable-background-networking", "--disable-extensions", "--remote-debugging-port=0",
    "--remote-debugging-address=127.0.0.1", "--user-data-dir=" + profile, "about:blank"],
    { windowsHide: true, stdio: "ignore" });
  let socket;
  try {
    const portFile = path.join(profile, "DevToolsActivePort");
    for (let i = 0; !fs.existsSync(portFile) && i < 100; i++) await delay(50);
    assert.ok(fs.existsSync(portFile), "headless browser failed to start");
    const port = fs.readFileSync(portFile, "utf8").split("\n")[0];
    const pages = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    socket = new WebSocket(pages.find(page => page.type === "page").webSocketDebuggerUrl);
    await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
    let sequence = 0; const pending = new Map(); const errors = [];
    socket.onmessage = event => {
      const message = JSON.parse(event.data);
      if (message.method === "Runtime.exceptionThrown") errors.push(message.params.exceptionDetails.text);
      const call = pending.get(message.id);
      if (call) { pending.delete(message.id); message.error ? call.reject(message.error) : call.resolve(message.result); }
    };
    const send = (method, params = {}) => new Promise((resolve, reject) => {
      const id = ++sequence; pending.set(id, { resolve, reject }); socket.send(JSON.stringify({ id, method, params }));
    });
    const evaluate = async expression => {
      const result = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
      assert.equal(result.exceptionDetails, undefined, JSON.stringify(result.exceptionDetails));
      return result.result.value;
    };
    await send("Runtime.enable"); await send("Page.enable");
    await send("Page.navigate", { url: `http://127.0.0.1:${server.address().port}/` });
    for (let i = 0; i < 100 && !await evaluate("!!document.querySelector('[data-view=settings]')?.onclick"); i++) await delay(25);
    await evaluate("document.querySelector('[data-view=settings]').click()");
    for (let i = 0; i < 100 && !await evaluate("!!document.querySelector('.mcp-card')"); i++) await delay(25);
    for (const width of [1058, 480]) {
      await send("Emulation.setDeviceMetricsOverride", { width, height: 1000, deviceScaleFactor: 1, mobile: false });
      await delay(50);
      const layout = await evaluate(`(() => {
        const card = document.querySelector('.mcp-card'), url = card.querySelector('[data-mcp-endpoint]');
        const copy = card.querySelector('[data-mcp-copy-url]'), rect = copy.getBoundingClientRect();
        return {value:url.value, cardWidth:card.clientWidth, cardScroll:card.scrollWidth,
          urlWidth:url.clientWidth, urlScroll:url.scrollWidth, urlHeight:url.clientHeight, urlScrollHeight:url.scrollHeight,
          textOverflow:getComputedStyle(url).textOverflow, whiteSpace:getComputedStyle(url).whiteSpace,
          copyText:copy.textContent, copyLeft:rect.left, copyRight:rect.right, viewport:innerWidth,
          pageWidth:document.documentElement.scrollWidth};
      })()`);
      assert.equal(layout.value, endpoint);
      assert.ok(layout.cardScroll <= layout.cardWidth + 1, JSON.stringify(layout));
      assert.ok(layout.urlScroll <= layout.urlWidth + 1, JSON.stringify(layout));
      assert.ok(layout.urlScrollHeight <= layout.urlHeight + 1, "full endpoint must be visible without vertical scrolling: " + JSON.stringify(layout));
      assert.notEqual(layout.textOverflow, "ellipsis");
      assert.equal(layout.whiteSpace, "pre-wrap");
      assert.equal(layout.copyText, "Copy URL");
      assert.ok(layout.copyLeft >= 0 && layout.copyRight <= width, JSON.stringify(layout));
      assert.ok(layout.pageWidth <= width + 1, JSON.stringify(layout));
      if (process.env.FZ_SCREENSHOT_DIR) {
        fs.mkdirSync(process.env.FZ_SCREENSHOT_DIR, { recursive: true });
        const shot = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: false });
        fs.writeFileSync(path.join(process.env.FZ_SCREENSHOT_DIR, `mcp-${width}.png`), Buffer.from(shot.data, "base64"));
      }
    }
    await evaluate("Object.defineProperty(navigator, 'clipboard', {value:{writeText:async text=>{window.copiedEndpoint=text}}, configurable:true}); document.querySelector('[data-mcp-copy-url]').click()");
    assert.equal(await evaluate("window.copiedEndpoint"), endpoint);
    for (const tab of ["log", "inbox", "settings"]) {
      await evaluate(`document.querySelector('[data-view=${tab}]').click()`);
      assert.equal(await evaluate("localStorage.getItem('fz-active-view')"), tab);
      await evaluate("document.documentElement.dataset.beforeReload='yes'");
      await send("Page.reload");
      for (let i=0;i<100;i++) {
        if (await evaluate(`!document.documentElement.dataset.beforeReload && document.querySelector('.view.active')?.id === '${tab}-view' && !!document.querySelector('[data-view=${tab}]')?.onclick`)) break;
        await delay(25);
      }
      assert.equal(await evaluate("document.querySelector('.view.active').id"), `${tab}-view`);
      if (tab === "inbox") {
        for (let i=0;i<100 && !await evaluate("!!document.querySelector('.container')");i++) await delay(25);
        assert.equal(await evaluate("document.querySelector('.container .state').textContent"), "Approved");
        assert.match(await evaluate("document.querySelector('.container .meta').textContent"), /No guest traffic observed/);
      }
    }
    await evaluate("document.querySelector('[data-view=inbox]').click()");
    for(let i=0;i<100 && !await evaluate("!!document.querySelector('[data-review]')");i++) await delay(25);
    await evaluate("document.querySelector('[data-review]').click()");
    for(let i=0;i<100 && !await evaluate("!document.querySelector('#request-review').hidden");i++) await delay(25);
    assert.equal(await evaluate("document.querySelector('#request-review-body').textContent"),detail.body);
    assert.equal(await evaluate("document.querySelector('#request-review-body').children.length"),0);
    assert.equal(await evaluate("document.querySelector('#request-graphql-document').textContent"),detail.graphql.analysis.formatted_document);
    assert.equal(await evaluate("document.querySelector('#request-graphql-fields').querySelectorAll('img').length"),0);
    assert.match(await evaluate("document.querySelector('#request-graphql-fields').textContent"),/Post comment.*Actual field:/s);
    assert.match(await evaluate("document.querySelector('#request-graphql-fields').textContent"),/NOT an issue\/PR number/);
    assert.equal(await evaluate("!!window.pwned"),false);
    assert.equal(await evaluate("document.querySelector('#inbox-count').textContent"),"1");
    await evaluate("document.querySelector('#resolve-comment-target').click()");
    for(let i=0;i<100 && !await evaluate("!!activeReview?.resolution_id");i++) await delay(25);
    assert.match(await evaluate("document.querySelector('#resolved-comment-target').textContent"),/cline\/cline #482/);
    assert.equal(await evaluate("document.querySelector('#resolved-comment-target').children.length"),0);
    await evaluate("window.confirm=()=>true; document.querySelector('#save-comment-permission').click()");
    for(let i=0;i<100 && !await evaluate("!!document.querySelector('[data-comment-revoke]')");i++) await delay(25);
    assert.equal(decisions.length,0,"saving permission must not approve the pending request");
    assert.equal(permissionActions[1].headers["x-friendzone-review"],"1");
    assert.deepEqual(permissionActions[1].body,{fingerprint:"immutable-hash",resolution_id:"resolution"});
    assert.equal(await evaluate("document.querySelector('#inbox-count').textContent"),"1");
    await evaluate("document.querySelector('[data-comment-revoke]').click()");
    for(let i=0;i<100 && await evaluate("!!document.querySelector('[data-comment-revoke]')");i++) await delay(25);
    assert.equal(permissionActions.length,3);
    for(const width of [1058,480]) {
      await send("Emulation.setDeviceMetricsOverride",{width,height:1000,deviceScaleFactor:1,mobile:false});
      const layout=await evaluate(`(() => {const body=document.querySelector('#request-review-body'), button=document.querySelector('#request-approve');return {page:document.documentElement.scrollWidth,body:body.clientWidth,scroll:body.scrollWidth,button:button.getBoundingClientRect().right,disabled:button.disabled};})()`);
      assert.ok(layout.page<=width+1,JSON.stringify(layout)); assert.ok(layout.scroll<=layout.body+1,JSON.stringify(layout)); assert.ok(layout.button<=width,JSON.stringify(layout)); assert.equal(layout.disabled,false);
    }
    await evaluate("window.confirm=()=>true; document.querySelector('#request-approve').click()");
    for(let i=0;i<100 && !decisions.length;i++) await delay(25);
    assert.deepEqual(decisions.map(d=>d.body),[{fingerprint:"immutable-hash",decision:"approve"}]);
    assert.equal(decisions[0].headers["x-friendzone-review"],"1");
    for(let i=0;i<100 && await evaluate("document.querySelector('#inbox-count').textContent !== '0'");i++) await delay(25);
    assert.equal(await evaluate("document.querySelector('#request-approve').disabled"),true);
    assert.equal(await evaluate("document.querySelector('#inbox-count').textContent"),"0");
    assert.deepEqual(errors, []);
  } finally {
    socket?.close(); browser.kill();
    server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
    await delay(250);
    fs.rmSync(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
});