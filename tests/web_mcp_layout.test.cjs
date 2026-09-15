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
  state.recent_reviews=[];
  state.comment_permissions=[];
  const detail={...pending,headers:[["content-type","application/json"],["authorization","[redacted]"]],body:'{"query":"<img src=x onerror=window.pwned=true>","variables":{"value":"' + "payload".repeat(200) + '"}}'};
  detail.graphql={status:"parsed",analysis:{version:1,operation_type:"mutation",operation_name:"Comment",operation_count:1,
    formatted_document:'mutation Comment($input: AddCommentInput!) {\n  harmless: addComment(input: $input) {\n    clientMutationId\n  }\n}',supplied_variables:'{\n  "input": {"subjectId":"opaque","body":"<img src=x onerror=window.pwned=true>"}\n}',
    effective_variables:[],warnings:["Parsed syntax only; target is not verified."],fields:[{field:"addComment",response_name:"harmless",path:["harmless"],parent:null,arguments:{},arguments_text:"input: "+"long-argument-".repeat(250),conditions:[],action:"Post comment",comment_body:"<img src=x onerror=window.pwned=true>",target:{kind:"node_id",input_path:"input.subjectId",id:"opaque-"+"node".repeat(80),expected_type:"Issue or PullRequest"}}]}};
  const decisions=[];
  const permissionActions=[];
  const guestActions=[];
  let failGuestChange = false;
  const resolvedTarget={target:{node_id:"canonical",repository_id:"repo-id",repository:"cline/cline",kind:"Issue",number:482,title:"<img src=x onerror=window.pwned=true> A real issue",url:"https://github.com/cline/cline/issues/482"},credential:"github"};
  detail.comment_permission_supported=true;
  const server = http.createServer((request, response) => {
    const route = request.url.split("?")[0];
    if (route === "/api/events") {
      response.writeHead(200, { "content-type": "text/event-stream" });
      response.write("data: " + JSON.stringify(state) + "\n\n"); return;
    }
    if (route === "/api/bootstrap/commands") {
      response.writeHead(200,{"content-type":"application/json"});
      response.end(JSON.stringify({broker:"http://172.31.208.1:8082",sh:"(curl --noproxy '*' 'http://172.31.208.1:8082/bootstrap/setup?shell=sh&broker="+"x".repeat(350)+"')",powershell:"& { "+"PowerShell command ".repeat(60)+"}",sh_url:"http://172.31.208.1:8082/bootstrap/setup?shell=sh",powershell_url:"http://172.31.208.1:8082/bootstrap/setup?shell=powershell"}));return;
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
        Object.assign(detail,{status:"response_received",http_status:201,outcome:"Upstream response received.",updated_at:"2099-01-01T00:00:00Z"});
        state.recent_reviews=[{...pending,status:detail.status,http_status:201,outcome:detail.outcome,updated_at:detail.updated_at}];
        response.writeHead(204); response.end();
      }); return;
    }
    if (route === "/api/containers" || /^\/api\/containers\/[^/]+(?:\/(approve|kill|pin))?$/.test(route)) {
      let body="";request.on("data",chunk=>body+=chunk);request.on("end",()=>{
        const data=body?JSON.parse(body):{};
        guestActions.push({route,method:request.method,body:data});
        if(failGuestChange){failGuestChange=false;response.writeHead(500);response.end("fixture policy save failed");return;}
        const parts=route.split("/"),name=decodeURIComponent(parts[3]||data.name), action=parts[4];
        const guest=state.containers.find(c=>c.id===name);
        if(route==="/api/containers")state.containers.push({id:name,name,approved:true,state:"approved",request_count:0,last_activity:null,pinned_ip:null});
        else if(request.method==="DELETE")state.containers=state.containers.filter(c=>c.id!==name);
        else if(action==="approve"){guest.approved=true;guest.state="approved";if(data.pin_to_last_ip)guest.pinned_ip="10.0.0.2";}
        else if(action==="kill")guest.state=data.killed?"killed":"approved";
        else if(action==="pin")guest.pinned_ip=data.ip;
        response.writeHead(204);response.end();
      });return;
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
    if (route.endsWith("/guest-config")) replies[route] = { endpoint, authorization: null, identity:"source_ip", warnings: [], cline_config: { mcpServers: {} } };
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
    const joinGuest={id:"joining-guest",name:"joining-guest",approved:false,state:"pending",request_count:1,last_activity:null,pinned_ip:"~10.0.0.2"};
    state.containers.push(joinGuest);
    await evaluate("refresh()");
    // The initial SSE snapshot can race the explicit fetch. Wait for the
    // rendered join, rather than asserting before the winning snapshot paints.
    for (let i=0;i<100 && !await evaluate("document.querySelector('#joining-guests .container') !== null");i++) {await evaluate("refresh()");await delay(25);}
    for(const width of [1058,480]) {
      await send("Emulation.setDeviceMetricsOverride",{width,height:1000,deviceScaleFactor:1,mobile:false});
      await evaluate("window.scrollTo(0,0)");
      const hierarchy=await evaluate(`(() => {const inbox=document.querySelector('#inbox-view'),rect=s=>document.querySelector(s).getBoundingClientRect();return {
        forms:inbox.querySelectorAll('form').length,setup:inbox.contains(document.querySelector('#guest-setup')),
        management:inbox.querySelectorAll('.stop,.pin-edit').length,joins:inbox.querySelectorAll('.container').length,
        pendingY:rect('#pending-requests').top,joinY:rect('#guest-joins').top,recentY:rect('#recent-reviews-panel').top,
        hasDupes:[...document.querySelectorAll('[id]')].length!==new Set([...document.querySelectorAll('[id]')].map(n=>n.id)).size,
        page:document.documentElement.scrollWidth,firstAction:inbox.querySelector('[data-review]').getBoundingClientRect().bottom,
        setupParent:document.querySelector('#add-container').closest('.settings-panel').id,
        manual:document.querySelector('#guest-preapprove').open,settingsCards:document.querySelectorAll('#settings-guests .container').length};})()`);
      assert.deepEqual([hierarchy.forms,hierarchy.setup,hierarchy.management,hierarchy.hasDupes,hierarchy.manual],[0,false,0,false,false]);
      assert.equal(hierarchy.joins,1);assert.equal(hierarchy.settingsCards,1);assert.equal(hierarchy.setupParent,'settings-guests');
      assert.ok(hierarchy.pendingY<hierarchy.joinY && hierarchy.joinY<hierarchy.recentY,JSON.stringify(hierarchy));
      assert.ok(hierarchy.firstAction<400,JSON.stringify(hierarchy));assert.ok(hierarchy.page<=width+1,JSON.stringify(hierarchy));
      if(process.env.FZ_SCREENSHOT_DIR){fs.mkdirSync(process.env.FZ_SCREENSHOT_DIR,{recursive:true});const shot=await send('Page.captureScreenshot',{format:'png'});fs.writeFileSync(path.join(process.env.FZ_SCREENSHOT_DIR,`inbox-hierarchy-${width}.png`),Buffer.from(shot.data,'base64'));}
    }
    // Failure stays with the join; a successful approval moves, not copies, its card.
    await evaluate("selectView('settings');selectSettings('guests')");
    assert.equal(await evaluate("document.querySelector('#review-guest-joins').hidden"),false);
    await evaluate("document.querySelector('#review-guest-joins').click()");
    assert.equal(await evaluate("document.querySelector('.view.active').id"),'inbox-view');
    assert.equal(guestActions.length,0,"navigation never grants access");
    failGuestChange=true;
    await evaluate("document.querySelector('#joining-guests .approve-pin').click()");
    for(let i=0;i<100 && !await evaluate("document.querySelector('#join-error').textContent");i++)await delay(25);
    assert.match(await evaluate("document.querySelector('#join-error').textContent"),/fixture policy save failed/);
    assert.equal(await evaluate("document.querySelector('#container-error').textContent"),"");
    assert.equal(await evaluate("document.querySelector('#inbox-count').textContent"),"2");
    await evaluate("document.querySelector('#joining-guests .approve-pin').click()");
    for(let i=0;i<100 && await evaluate("!!document.querySelector('#joining-guests .container')");i++)await delay(25);
    assert.equal(await evaluate("document.querySelector('#guest-joins').hidden"),true);
    assert.equal(await evaluate("document.querySelector('#inbox-count').textContent"),"1");
    assert.equal(await evaluate("document.querySelectorAll('[data-id=joining-guest]').length"),1);
    assert.deepEqual(guestActions.at(-1).body,{pin_to_last_ip:true});
    await evaluate("document.querySelector('[data-view=settings]').click()");
    for (let i = 0; i < 100 && !await evaluate("!!document.querySelector('.mcp-card')"); i++) await delay(25);
    assert.equal(await evaluate("document.querySelector('#settings-guests').hidden"),false);
    assert.equal(await evaluate("document.querySelector('#settings-mcp').hidden"),true);
    assert.equal(await evaluate("document.querySelector('#setup-platform-powershell').hidden"),true);
    assert.equal(await evaluate("document.querySelector('#guest-setup').hidden"),true);
    for(const width of [1058,480]) {
      await send('Emulation.setDeviceMetricsOverride',{width,height:1000,deviceScaleFactor:1,mobile:false});
      await evaluate("window.scrollTo(0,0)");await delay(50);
      assert.ok(await evaluate(`document.documentElement.scrollWidth<=${width+1}`));
      if(process.env.FZ_SCREENSHOT_DIR){const shot=await send('Page.captureScreenshot',{format:'png'});fs.writeFileSync(path.join(process.env.FZ_SCREENSHOT_DIR,`guest-management-${width}.png`),Buffer.from(shot.data,'base64'));}
    }
    assert.equal(await evaluate("document.querySelector('#guest-preapprove').open"),false);
    // Managed operations still use the same API and expose failures beside the card.
    failGuestChange=true;
    await evaluate("document.querySelector('[data-id=joining-guest] .stop').click()");
    for(let i=0;i<100 && !await evaluate("document.querySelector('#container-error').textContent");i++)await delay(25);
    assert.match(await evaluate("document.querySelector('#container-error').textContent"),/fixture policy save failed/);
    await evaluate("document.querySelector('[data-id=joining-guest] .stop').click()");
    for(let i=0;i<100 && !await evaluate("!!document.querySelector('[data-id=joining-guest] .resume')");i++)await delay(25);
    assert.equal(await evaluate("document.querySelector('[data-id=joining-guest] .state').textContent"),"Killed");
    await evaluate("document.querySelector('[data-id=joining-guest] .resume').click()");
    for(let i=0;i<100 && await evaluate("!!document.querySelector('[data-id=joining-guest] .resume')");i++)await delay(25);
    assert.equal(await evaluate("document.querySelector('[data-id=joining-guest] .state').textContent"),"Approved");
    assert.deepEqual(guestActions.at(-1).body,{killed:false});
    await evaluate("window.prompt=()=> '10.0.0.3';document.querySelector('[data-id=joining-guest] .pin-edit').click()");
    for(let i=0;i<100 && !await evaluate("document.querySelector('[data-id=joining-guest] .meta').textContent.includes('pinned to 10.0.0.3')");i++)await delay(25);
    assert.deepEqual(guestActions.at(-1).body,{ip:'10.0.0.3'});
    await evaluate("window.confirm=()=>true;document.querySelector('[data-id=joining-guest] .remove').click()");
    for(let i=0;i<100 && await evaluate("!!document.querySelector('[data-id=joining-guest]')");i++)await delay(25);
    await evaluate("document.querySelector('#show-guest-setup').click();document.querySelector('#guest-preapprove').open=true;document.querySelector('#new-container-name').value='preapproved';document.querySelector('#preapprove-guest').click()");
    for(let i=0;i<100 && !await evaluate("!!document.querySelector('[data-id=preapproved]')");i++)await delay(25);
    assert.deepEqual(guestActions.at(-1).body,{name:'preapproved'});
    assert.match(await evaluate("document.querySelector('#preapprove-status').textContent"),/Preapproved/);
    assert.equal(await evaluate("document.querySelector('#inbox-count').textContent"),"1");
    await evaluate("document.querySelector('[data-id=preapproved] .remove').click();document.querySelector('#guest-preapprove').open=false;document.querySelector('#show-guest-setup').click()");
    for(let i=0;i<100 && await evaluate("!!document.querySelector('[data-id=preapproved]')");i++)await delay(25);
    assert.equal(await evaluate("document.querySelector('#guest-setup').hidden"),true);
    state.containers.push({...joinGuest,approved:false,state:'pending'});
    await evaluate("refresh();selectView('inbox')");
    for(let i=0;i<100 && !await evaluate("!!document.querySelector('#joining-guests .remove')");i++)await delay(25);
    await evaluate("document.querySelector('#joining-guests .remove').click()");
    for(let i=0;i<100 && await evaluate("!!document.querySelector('#joining-guests .remove')");i++)await delay(25);
    assert.equal(await evaluate("document.querySelector('#guest-joins').hidden"),true);
    assert.equal(guestActions.at(-1).method,'DELETE');
    assert.equal(await evaluate("document.querySelector('#inbox-count').textContent"),'1');
    await evaluate("selectView('settings');selectSettings('guests')");
    for (const width of [1058, 480]) {
      await send("Emulation.setDeviceMetricsOverride", { width, height: 1000, deviceScaleFactor: 1, mobile: false });
      await evaluate("document.querySelector('[data-settings=mcp]').click()");
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
      assert.ok(layout.cardWidth>100, "MCP panel must actually be visible");
      assert.ok(layout.cardScroll <= layout.cardWidth + 1, JSON.stringify(layout));
      assert.ok(layout.urlScroll <= layout.urlWidth + 1, JSON.stringify(layout));
      assert.ok(layout.urlScrollHeight <= layout.urlHeight + 1, "full endpoint must be visible without vertical scrolling: " + JSON.stringify(layout));
      assert.notEqual(layout.textOverflow, "ellipsis");
      assert.equal(layout.whiteSpace, "pre-wrap");
      assert.equal(layout.copyText, "Copy URL");
      assert.ok(layout.copyLeft >= 0 && layout.copyRight <= width, JSON.stringify(layout));
      assert.ok(layout.pageWidth <= width + 1, JSON.stringify(layout));
      await evaluate("document.querySelector('[data-settings=guests]').click()");
      await evaluate("if(document.querySelector('#guest-setup').hidden)document.querySelector('#show-guest-setup').click()");
      const setup=await evaluate(`(() => {const panel=document.querySelector('#guest-setup'), command=document.querySelector('#setup-sh');return {width:panel.clientWidth,scroll:panel.scrollWidth,value:command.value,copyDisabled:document.querySelector('#setup-copy-sh').disabled,inspect:document.querySelector('#setup-view-sh').href};})()`);
      assert.ok(setup.width>100);
      assert.ok(setup.scroll<=setup.width+1,JSON.stringify(setup));
      assert.match(setup.value,/--noproxy/);assert.equal(setup.copyDisabled,false);assert.match(setup.inspect,/bootstrap\/setup\?shell=sh/);
      if (process.env.FZ_SCREENSHOT_DIR) {
        fs.mkdirSync(process.env.FZ_SCREENSHOT_DIR, { recursive: true });
        const shot = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: false });
        fs.writeFileSync(path.join(process.env.FZ_SCREENSHOT_DIR, `guests-${width}.png`), Buffer.from(shot.data, "base64"));
      }
    }
    // Normal-sized sample in addition to the deliberately hostile/long fixture.
    const normal={name:'Linear',url:'https://mcp.linear.app/mcp',tools:['list_issues','get_issue'],guests:['scratch-kali'],auth:'oauth',guest_endpoint:'http://172.31.208.1:8082/mcp/Linear'};
    await evaluate(`window.fixtureFetch=fetch;window.fetch=(url,options)=>url==='/api/mcp'?Promise.resolve({json:async()=>({forwards:[${JSON.stringify(normal)}],guest_host:'172.31.208.1',guest_port:8082})}):fixtureFetch(url,options);renderSettings()`);
    for(const width of [1058,480]) {
      await send('Emulation.setDeviceMetricsOverride',{width,height:1000,deviceScaleFactor:1,mobile:false});
      await evaluate(`selectSettings('guests');document.querySelector('#setup-sh').value="curl --noproxy '*' -fsS 'http://172.31.208.1:8082/bootstrap/setup?shell=sh&container=scratch-kali' -o friendzone-setup.sh";window.scrollTo(0,0)`);
      await delay(60);
      if(process.env.FZ_SCREENSHOT_DIR){const shot=await send('Page.captureScreenshot',{format:'png'});fs.writeFileSync(path.join(process.env.FZ_SCREENSHOT_DIR,'guest-normal-'+width+'.png'),Buffer.from(shot.data,'base64'));}
    }
    await evaluate("selectSettings('mcp');document.querySelector('[data-mcp-connect]').click();window.scrollTo(0,0)");
    await delay(60);
    if(process.env.FZ_SCREENSHOT_DIR){const shot=await send('Page.captureScreenshot',{format:'png',captureBeyondViewport:true});fs.writeFileSync(path.join(process.env.FZ_SCREENSHOT_DIR,'mcp-normal.png'),Buffer.from(shot.data,'base64'));}
    await evaluate('window.fetch=window.fixtureFetch;renderSettings()');
    await evaluate("document.querySelector('[data-settings=mcp]').click();document.querySelector('[data-mcp-connect]').click()");
    for(let i=0;i<100 && await evaluate("document.querySelector('#mcp-copy-json').disabled");i++) await delay(25);
    assert.equal(await evaluate("!!document.querySelector('#mcp-connect').closest('.mcp-card')"),true);
    assert.equal(await evaluate("document.querySelector('#mcp-connect').hidden"),false);
    assert.equal(await evaluate("document.querySelector('#mcp-connect details').open"),false);
    await evaluate("Object.defineProperty(navigator,'clipboard',{value:{writeText:async text=>{window.copiedConfig=text}},configurable:true});document.querySelector('#mcp-copy-json').click()");
    assert.equal(await evaluate("window.copiedConfig"),await evaluate("document.querySelector('#mcp-connect-json').value"));
    if(process.env.FZ_SCREENSHOT_DIR){const shot=await send('Page.captureScreenshot',{format:'png',captureBeyondViewport:true});fs.writeFileSync(path.join(process.env.FZ_SCREENSHOT_DIR,'mcp-inline.png'),Buffer.from(shot.data,'base64'));}
    await evaluate("document.querySelector('#mcp-connect-close').click()");
    assert.equal(await evaluate("document.querySelector('#mcp-connect').hidden"),true);
    await evaluate("document.querySelector('[data-settings=credentials]').click();document.querySelector('#setup-platform').value='powershell';document.querySelector('#setup-platform').dispatchEvent(new Event('change'))");
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
        assert.equal(await evaluate("document.querySelector('#settings-guests .container .state').textContent"), "Approved");
        assert.match(await evaluate("document.querySelector('#settings-guests .container .meta').textContent"), /No guest traffic observed/);
        assert.equal(await evaluate("document.querySelectorAll('#inbox-view .container, #inbox-view form').length"),0);
      }
    }
    assert.equal(await evaluate("document.querySelector('#settings-credentials').hidden"),false);
    assert.equal(await evaluate("document.querySelector('#setup-platform').value"),'powershell');
    await evaluate("document.querySelector('[data-view=inbox]').click()");
    for(let i=0;i<100 && !await evaluate("!!document.querySelector('[data-review]')");i++) await delay(25);
    await evaluate("document.querySelector('[data-review]').click()");
    for(let i=0;i<100 && !await evaluate("!document.querySelector('#request-review').hidden");i++) await delay(25);
    assert.equal(await evaluate("document.querySelector('#request-review-body').textContent"),detail.body);
    assert.equal(await evaluate("document.querySelector('#request-review-body').children.length"),0);
    assert.equal(await evaluate("document.querySelector('#request-graphql-document').textContent"),detail.graphql.analysis.formatted_document);
    assert.equal(await evaluate("document.querySelector('#request-graphql-fields').querySelectorAll('img').length"),0);
    assert.match(await evaluate("document.querySelector('#request-graphql-fields').textContent"),/Post comment.*addComment/s);
    assert.match(await evaluate("document.querySelector('#request-graphql-fields').textContent"),/Not an issue\/PR number/);
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
    await evaluate("selectView('settings');selectSettings('guests');document.querySelector('#saved-comment-permissions').open=true;document.querySelector('[data-comment-revoke]').click()");
    for(let i=0;i<100 && await evaluate("!!document.querySelector('[data-comment-revoke]')");i++) await delay(25);
    assert.equal(permissionActions.length,3);
    await evaluate("selectView('inbox')");
    for(const width of [1058,480]) {
      await send("Emulation.setDeviceMetricsOverride",{width,height:1000,deviceScaleFactor:1,mobile:false});
      const layout=await evaluate(`(() => {document.querySelector('#request-raw').open=true;const body=document.querySelector('#request-review-body'), button=document.querySelector('#request-approve');return {page:document.documentElement.scrollWidth,body:body.clientWidth,scroll:body.scrollWidth,button:button.getBoundingClientRect().right,disabled:button.disabled};})()`);
      assert.ok(layout.page<=width+1,JSON.stringify(layout)); assert.ok(layout.scroll<=layout.body+1,JSON.stringify(layout)); assert.ok(layout.button<=width,JSON.stringify(layout)); assert.equal(layout.disabled,false);
    }
    await evaluate("window.confirm=()=>{throw new Error('Unexpected approval dialog')}; document.querySelector('#request-approve').click(); document.querySelector('#request-approve').click()");
    for(let i=0;i<100 && !decisions.length;i++) await delay(25);
    assert.deepEqual(decisions.map(d=>d.body),[{fingerprint:"immutable-hash",decision:"approve"}]);
    assert.equal(decisions[0].headers["x-friendzone-review"],"1");
    for(let i=0;i<100 && await evaluate("document.querySelector('#inbox-count').textContent !== '0'");i++) await delay(25);
    assert.equal(await evaluate("document.querySelector('#request-approve').disabled"),true);
    assert.equal(await evaluate("document.querySelector('#inbox-count').textContent"),"0");
    assert.equal(await evaluate("document.querySelector('#request-review-badge').textContent"),"Response received · HTTP 201");
    assert.equal(await evaluate("document.querySelector('#request-review').hidden"),false);
    assert.equal(await evaluate("document.querySelector('#request-review-actions').hidden"),true);
    assert.equal(await evaluate("getComputedStyle(document.querySelector('#request-review-actions')).display"),'none');
    assert.equal(await evaluate("document.querySelector('#recent-reviews [data-review]').textContent"),"Details");
    if(process.env.FZ_SCREENSHOT_DIR){const shot=await send('Page.captureScreenshot',{format:'png',captureBeyondViewport:true});fs.writeFileSync(path.join(process.env.FZ_SCREENSHOT_DIR,'review-outcome.png'),Buffer.from(shot.data,'base64'));}
    await evaluate("document.documentElement.dataset.beforeReload='yes'");
    await send("Page.reload");
    for(let i=0;i<100;i++){if(await evaluate("!document.documentElement.dataset.beforeReload && !!document.querySelector('#recent-reviews [data-review]')"))break;await delay(25);}
    await evaluate("document.querySelector('#recent-reviews [data-review]').click()");
    for(let i=0;i<100 && !await evaluate("!document.querySelector('#request-review').hidden");i++)await delay(25);
    assert.equal(await evaluate("document.querySelector('#request-review-badge').textContent"),"Response received · HTTP 201");
    assert.equal(await evaluate("document.querySelector('#request-approve').disabled"),true);
    // Real browser rendering of mutation cards: both actions remain explicitly
    // approvable, not disabled by the lack of an automatic comment permission.
    for (const [field,action,label,value] of [["createPullRequest","Create pull request","Head branch (source)","fork:"+"feature-".repeat(150)],["submitPullRequestReview","Submit pull request review","Review event","APPROVE"]]) {
      const mutation={...detail,comment_permission_supported:false,resolution_id:null,resolved_target:null,graphql:{status:"parsed",analysis:{...detail.graphql.analysis,
        fields:[{...detail.graphql.analysis.fields[0],field,action,comment_body:null,mutation_inputs:[{label,path:"input.value",value},{label:"Body",path:"input.body",value:"<img src=x onerror=window.pwned=true>"}]}]}}};
      await evaluate(`activeReview=${JSON.stringify(mutation)};renderGraphqlReview(activeReview.graphql);renderCommentPermissionPanel(activeReview);document.querySelector('#request-approve').disabled=false`);
      assert.match(await evaluate("document.querySelector('#request-graphql-operation').textContent"),/MUTATION/);
      assert.equal(await evaluate("document.querySelector('#comment-permission-panel').hidden"),true);
      assert.equal(await evaluate("document.querySelector('#save-comment-permission').disabled"),true);
      assert.equal(await evaluate("document.querySelector('#request-graphql-fields img')===null"),true);
      assert.equal(await evaluate("!!window.pwned"),false);
      for(const width of [1058,480]) {
        await send("Emulation.setDeviceMetricsOverride",{width,height:1000,deviceScaleFactor:1,mobile:false});
        assert.ok(await evaluate(`document.documentElement.scrollWidth <= ${width+1}`));
      }
    }
    for(const code of [null,200]) {
      const uncertain={...detail,status:"unknown",http_status:code,outcome:"HTTP response was not fully observed.",updated_at:"2099-02-01T00:00:00Z"};
      await evaluate(`activeReview=${JSON.stringify(uncertain)};snapshot.pending_requests=[];snapshot.recent_reviews=[activeReview];renderPendingRequests()`);
      const expected=code?"Response incomplete · HTTP 200":"No response received";
      assert.equal(await evaluate("document.querySelector('#request-review-badge').textContent"),expected);
      assert.equal(await evaluate("document.querySelector('#recent-reviews .request-badge').textContent"),expected);
      assert.equal(await evaluate("document.querySelector('#request-review-actions').hidden"),true);
      assert.equal(await evaluate("document.querySelector('#request-review-outcome').textContent===document.querySelector('#recent-reviews .request-badge').title"),true);
    }
    const now=Date.now();
    const overview={...detail,status:'response_received',http_status:499,outcome:'Response received',facts:{operation_name:'InspectPullRequest',operation_type:'query',fields:['repository'],repositories:['cline/cline'],targets:['#1234'],artifacts:[{repository:'cline/cline',number:'1234',kind:'pull_request'}],more:false}};
    await evaluate(`activeReview=null;snapshot.pending_requests=[];snapshot.recent_reviews=[${JSON.stringify(overview)}];renderPendingRequests();document.querySelector('#request-review').hidden=true;window.scrollTo(0,0)`);
    for(const width of [1058,480]){
      await send('Emulation.setDeviceMetricsOverride',{width,height:1000,deviceScaleFactor:1,mobile:false});
      const layout=await evaluate(`(()=>{const row=document.querySelector('#recent-reviews tbody tr'),visible=n=>{const r=n.getBoundingClientRect();return r.left>=0&&r.right<=innerWidth&&r.width>0},links=[...row.querySelectorAll('.review-target a')].map(link=>({href:link.href,text:link.textContent,target:link.target,rel:link.rel,visible:visible(link)}));return {height:row.getBoundingClientRect().height,text:row.textContent,operation:row.cells[0].textContent,repository:row.cells[1].textContent,paragraphs:row.querySelectorAll('p').length,page:document.documentElement.scrollWidth,scroll:document.querySelector('#recent-reviews .review-table-scroll').scrollWidth,statusVisible:visible(row.querySelector('.request-badge')),actionVisible:visible(row.querySelector('button')),links};})()`);
      assert.equal(layout.operation,'InspectPullRequest');assert.equal(layout.repository,'cline/cline · #1234');assert.deepEqual(layout.links.map(link=>[link.href,link.text]),[['https://github.com/cline/cline','cline/cline'],['https://github.com/cline/cline/pull/1234','#1234']]);assert.ok(layout.links.every(link=>link.target==='_blank'&&link.rel.includes('noopener')&&link.visible));assert.equal(layout.paragraphs,0);assert.ok(width>700?layout.height<50:layout.height<110);assert.match(layout.text,/HTTP 499/);assert.doesNotMatch(layout.text,/Response received|HTTP error/);assert.ok(layout.page<=width+1);assert.equal(layout.statusVisible,true);assert.equal(layout.actionVisible,true);
      assert.equal(await evaluate("(() => {const cell=document.querySelector('#recent-reviews tbody tr').lastElementChild;return cell.querySelector('button').getBoundingClientRect().right<=cell.getBoundingClientRect().right;})()"),true,'action must fit inside its cell');
      if(process.env.FZ_SCREENSHOT_DIR){const shot=await send('Page.captureScreenshot',{format:'png'});fs.writeFileSync(path.join(process.env.FZ_SCREENSHOT_DIR,`request-table-${width}.png`),Buffer.from(shot.data,'base64'));}
    }
    await evaluate("document.querySelector('#request-review').hidden=false");
    const draft={...detail,url:"https://api.github.com/graphql",status:"pending",outcome:null,http_status:null,created_at:new Date(now-25000).toISOString(),updated_at:new Date(now-25000).toISOString(),expires_at:new Date(now+95000).toISOString(),graphql:{status:"parsed",analysis:{...detail.graphql.analysis,operation_name:null,effective_variables:[{name:"id",declared_type:"ID!",source:"supplied",value:{kind:"string",value:"PR_fixture_opaque"}}],
      fields:[{field:"convertPullRequestToDraft",response_name:"convertPullRequestToDraft",path:["convertPullRequestToDraft"],parent:null,arguments:{input:{kind:"object",value:{pullRequestId:{kind:"string",value:"PR_fixture_opaque"},note:{kind:"string",value:"first line\n<img src=x onerror=window.pwned=true>\nlast line"},count:{kind:"int",value:"9007199254740993"}}}},conditions_text:[],mutation_inputs:[]},
        {field:"number",response_name:"number",path:["convertPullRequestToDraft","pullRequest","number"],parent:0,arguments:{},conditions_text:[]}]}}};
    await evaluate(`activeReview=${JSON.stringify(draft)};snapshot.pending_requests=[activeReview];snapshot.recent_reviews=[];renderPendingRequests();renderGraphqlReview(activeReview.graphql);applyReviewOutcome(activeReview);document.querySelector('#request-review-url').textContent=activeReview.url;document.querySelector('#request-raw').open=false;document.querySelector('#comment-permission-panel').hidden=true;`);
    for(const width of [1058,480]) {
      await send("Emulation.setDeviceMetricsOverride",{width,height:1000,deviceScaleFactor:1,mobile:false});
      await evaluate("document.querySelector('#request-review').scrollIntoView({block:'start'})");
      const visible=await evaluate(`(() => { const root=document.querySelector('#request-graphql-fields');return {rows:[...root.querySelectorAll('dd pre')].map(node=>({text:node.textContent,visible:node.checkVisibility(),clipped:node.scrollHeight>node.clientHeight+1})),hidden:root.querySelectorAll('details').length,overflow:document.documentElement.scrollWidth>innerWidth+1,executed:!!window.pwned}; })()`);
      assert.equal(visible.hidden,0);assert.equal(visible.overflow,false);assert.equal(visible.executed,false);
      assert.equal(visible.rows.length,3);assert.ok(visible.rows.every(row=>row.visible&&!row.clipped));
      assert.ok(visible.rows.some(row=>row.text==="PR_fixture_opaque"));assert.ok(visible.rows.some(row=>row.text==="9007199254740993"));
      assert.equal(await evaluate("document.querySelector('#request-graphql-effective').checkVisibility()"),true);
      assert.equal(await evaluate("document.querySelector('#request-review-actions').hidden"),false);
      if(process.env.FZ_SCREENSHOT_DIR){const shot=await send('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});fs.writeFileSync(path.join(process.env.FZ_SCREENSHOT_DIR,`approval-values-${width}.png`),Buffer.from(shot.data,'base64'));}
    }
    assert.deepEqual(errors, []);
  } finally {
    socket?.close(); browser.kill();
    server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
    await delay(250);
    fs.rmSync(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
});