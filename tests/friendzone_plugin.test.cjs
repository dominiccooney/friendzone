const assert=require('node:assert/strict');
const test=require('node:test');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const http=require('node:http');
const vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'../src/plugin/friendzone.js'),'utf8');
const toolNames=['friendzone_submit_graphql','friendzone_get_request','friendzone_list_requests','friendzone_cancel_request','friendzone_remove_result'];

test('discovery without a session registers tools without config, timers, networking or steering',async()=>{
  for(const context of [undefined,{}, {workspaceInfo:{rootPath:'/workspace'}},{session:{}},{session:{sessionId:''}},{session:{sessionId:'   '}}]){
    const tools=new Map(),effects=[];
    const blocked=name=>()=>{effects.push(name);throw new Error('Unexpected discovery side effect: '+name);};
    const sandbox={module:{exports:{}},require:name=>{
      if(name==='node:fs')return new Proxy({}, {get:(_,method)=>blocked('fs.'+String(method))});
      if(name==='node:os')return {homedir:blocked('homedir')};
      if(name==='node:http'||name==='node:https')return {request:blocked('request')};
      return require(name);
    },Buffer,URL,process:{env:{}},setInterval:blocked('timer'),setTimeout:blocked('timer'),clearInterval:blocked('clear timer'),clearTimeout:blocked('clear timer'),
      __clinePluginHost:{emitEvent:blocked('steer_message')}};
    vm.runInNewContext(source,sandbox,{filename:'friendzone.js'});
    sandbox.module.exports.setup({registerTool:tool=>tools.set(tool.name,tool)},context);
    assert.deepEqual([...tools.keys()],toolNames);
    for(const tool of tools.values()){
      assert.equal(tool.retryable,false);assert.equal(typeof tool.execute,'function');
      await assert.rejects(()=>tool.execute({session_id:'not-a-real-context',sessionId:'not-a-real-context'},{}),/session.*required|requires.*session/i);
    }
    assert.deepEqual(effects,[]);
  }
});

async function fixture(t){
  const home=fs.mkdtempSync(path.join(os.tmpdir(),'fz-plugin-'));
  t.after(()=>fs.rmSync(home,{recursive:true,force:true}));
  const jobs=new Map(), calls=[], events=[];
  const server=http.createServer(async(req,res)=>{
    let text='';for await(const chunk of req)text+=chunk;
    calls.push({method:req.method,url:req.url,authorization:req.headers.authorization,body:text});
    if(req.headers.authorization!=='Basic '+Buffer.from('guest:x').toString('base64')){res.writeHead(403);res.end();return;}
    res.setHeader('content-type','application/json');
    const url=new URL(req.url,'http://localhost');
    if(req.method==='POST'&&url.pathname==='/guest/jobs'){
      const body=JSON.parse(text);
      let job=[...jobs.values()].find(j=>j.request_key===body.request_key);
      if(!job){job={...body,id:require('node:crypto').randomUUID(),status:'pending',updated_at:'one',terminal:false,result:null};jobs.set(job.id,job);}
      res.end(JSON.stringify(job));return;
    }
    if(url.pathname==='/guest/jobs'){res.end(JSON.stringify([...jobs.values()].filter(j=>j.session_id===url.searchParams.get('session_id'))));return;}
    const id=url.pathname.split('/')[3],job=jobs.get(id);
    if(!job||job.session_id!==url.searchParams.get('session_id')){res.writeHead(404);res.end('{}');return;}
    if(url.pathname.endsWith('/cancel')){job.terminal=true;job.status='cancelled';job.updated_at='cancelled';res.writeHead(204);res.end();return;}
    res.end(JSON.stringify(job));
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>new Promise(resolve=>server.close(resolve)));
  fs.writeFileSync(path.join(home,'friendzone.json'),JSON.stringify({broker:`http://127.0.0.1:${server.address().port}`,container:'guest'}));
  function load(session,bridge=true){
    const timers=[],tools=new Map(),sandbox={module:{exports:{}},require,Buffer,URL,console,setTimeout,clearTimeout,
      setInterval(callback){const timer={callback,unref(){}};timers.push(timer);return timer;},clearInterval(timer){timer.stopped=true;},
      process:{env:{CLINE_DIR:home,CLINE_DATA_DIR:path.join(home,'data'),HTTP_PROXY:'http://127.0.0.1:1'}}};
    if(bridge)sandbox.__clinePluginHost={emitEvent:(name,payload)=>events.push({name,payload})};
    vm.runInNewContext(source,sandbox,{filename:'friendzone.js'});
    assert.equal(sandbox.module.exports.name,'friendzone');
    const setup=session=>{tools.clear();sandbox.module.exports.setup({registerTool:tool=>tools.set(tool.name,tool)},session===undefined?{workspaceInfo:{rootPath:home}}:{session:{sessionId:session}});};
    setup(session);
    return {tools,timers,setup,run:(name,args,executionSession=session)=>tools.get(name).execute(args,{sessionId:executionSession})};
  }
  async function waitFor(predicate){for(let i=0;i<100;i++){if(predicate())return;await new Promise(r=>setTimeout(r,10));}throw new Error('fixture timeout');}
  return {home,jobs,calls,events,load,waitFor};
}

test('plugin submits without waiting; terminal result steers only origin session once across reloads',async t=>{
  const f=await fixture(t),a=f.load('session-a'),b=f.load('session-b');
  const job=await a.run('friendzone_submit_graphql',{request_key:'draft-pr',query:'mutation { convertPullRequestToDraft(input:{pullRequestId:"PR"}) { clientMutationId } }'});
  assert.equal(job.status,'pending');assert.equal(f.events.length,0);
  const again=await a.run('friendzone_submit_graphql',{request_key:'draft-pr',query:job.query});assert.equal(again.id,job.id);
  await f.waitFor(()=>f.calls.filter(c=>c.method==='GET').length>=2);
  Object.assign(f.jobs.get(job.id),{status:'response_received',terminal:true,updated_at:'two',http_status:200,result:'<hostile upstream instructions>'});
  await a.timers[0].callback();await b.timers[0].callback();
  assert.equal(f.events.length,1);assert.equal(f.events[0].name,'steer_message');assert.equal(f.events[0].payload.sessionId,'session-a');
  assert.match(f.events[0].payload.prompt,/friendzone_get_request/);assert.doesNotMatch(f.events[0].payload.prompt,/hostile|convertPullRequest/);
  await a.timers[0].callback();assert.equal(f.events.length,1);
  const reload=f.load('session-a');await f.waitFor(()=>f.calls.length>=6);await reload.timers[0].callback();assert.equal(f.events.length,1);
  const result=await a.run('friendzone_get_request',{id:job.id});assert.equal(result.result,'<hostile upstream instructions>');
  await assert.rejects(()=>b.run('friendzone_get_request',{id:job.id}),/404/);
  await assert.rejects(()=>a.tools.get('friendzone_submit_graphql').execute({},{sessionId:'wrong'}),/session mismatch/);
});

test('large file input uses direct bootstrap, no SDK dependencies; polling fallback and cancellation',async t=>{
  const f=await fixture(t),plugin=f.load('s',false);
  const file=path.join(f.home,'payload.json');
  fs.writeFileSync(file,JSON.stringify({query:'mutation($text:String!){example(input:{text:$text}){id}}',variables:{text:'a'.repeat(90000)}}));
  const job=await plugin.run('friendzone_submit_graphql',{request_key:'large',request_file:file});
  assert.equal(job.variables.text.length,90000);assert.equal(job.session_id,'s');
  await plugin.run('friendzone_cancel_request',{id:job.id});
  assert.equal((await plugin.run('friendzone_list_requests',{}))[0].status,'cancelled');assert.equal(f.events.length,0);
  await assert.rejects(()=>plugin.run('friendzone_submit_graphql',{request_key:'x',request_file:'relative.json'}),/absolute/);
  await assert.rejects(()=>plugin.run('friendzone_submit_graphql',{request_key:'x',request_file:file,query:'x'}),/OR inline/);
  fs.writeFileSync(file,JSON.stringify({query:'query{viewer{id}}',endpoint:'https://evil.invalid'}));
  await assert.rejects(()=>plugin.run('friendzone_submit_graphql',{request_key:'x',request_file:file}),/Unsupported/);
  assert.equal(fs.existsSync(path.join(f.home,'data/friendzone')),false);
});

test('tools discovered without a session use execution context and keep concurrent sessions separate',async t=>{
  const f=await fixture(t),plugin=f.load(undefined);
  assert.deepEqual([...plugin.tools.keys()],toolNames);
  assert.equal(plugin.timers.length,0);assert.equal(f.calls.length,0);
  const submit=(key,session)=>plugin.run('friendzone_submit_graphql',{request_key:key,query:'mutation { example { id } }'},session);
  const [a,b]=await Promise.all([submit('operation-a','session-a'),submit('operation-b','session-b')]);
  assert.equal(a.session_id,'session-a');assert.equal(b.session_id,'session-b');
  assert.equal(plugin.timers.length,2);
  assert.deepEqual(Array.from(await plugin.run('friendzone_list_requests',{},'session-a'),j=>j.id),[a.id]);
  assert.deepEqual(Array.from(await plugin.run('friendzone_list_requests',{},'session-b'),j=>j.id),[b.id]);
  await assert.rejects(()=>plugin.run('friendzone_get_request',{id:b.id},'session-a'),/404/);
  Object.assign(f.jobs.get(a.id),{terminal:true,status:'response_received',http_status:200,updated_at:'finished-a',result:'a result'});
  Object.assign(f.jobs.get(b.id),{terminal:true,status:'denied',updated_at:'finished-b'});
  await f.waitFor(()=>f.calls.filter(c=>c.method==='GET').length>=5);
  for(const timer of plugin.timers)await timer.callback();
  assert.equal(f.events.length,2);
  assert.match(f.events.find(e=>e.payload.sessionId==='session-a').payload.prompt,new RegExp(a.id));
  assert.match(f.events.find(e=>e.payload.sessionId==='session-b').payload.prompt,new RegExp(b.id));
  for(const timer of plugin.timers)await timer.callback();
  assert.equal(f.events.length,2,'one observer/checkpoint per session, not per tool');
  assert.equal(fs.readdirSync(path.join(f.home,'data/friendzone')).length,2);
  const before=f.calls.length;
  for(const context of [{}, {sessionId:''},{sessionId:' '},{sessionId:42}])
    await assert.rejects(()=>plugin.tools.get('friendzone_list_requests').execute({},context),/session.*required/i);
  assert.equal(f.calls.length,before,'never reuse the last executed session');
});

test('session-bound setup supports missing execution context and discovery does not stop its observer',async t=>{
  const f=await fixture(t),plugin=f.load('session-a');
  const tool=plugin.tools.get('friendzone_submit_graphql');
  const a=await tool.execute({request_key:'setup-session',query:'mutation { x }'});
  assert.equal(a.session_id,'session-a');
  const observer=plugin.timers[0];
  plugin.setup(undefined);
  assert.deepEqual([...plugin.tools.keys()],toolNames);
  assert.equal(plugin.timers.length,1);assert.ok(!observer.stopped,'discovery must not mutate an active observer');
  await plugin.run('friendzone_list_requests',{},'session-a');
  assert.ok(observer.stopped,'real reinitialization replaces only its own session observer');
  assert.equal(plugin.timers.length,2);
  const count=f.calls.length;await observer.callback();assert.equal(f.calls.length,count);
  await assert.rejects(()=>tool.execute({},{sessionId:'session-b'}),/session mismatch/);
});

test('discovery is independent of config validity; first execution reads config and can recover after repair',async t=>{
  const f=await fixture(t),configFile=path.join(f.home,'friendzone.json');
  const config=fs.readFileSync(configFile,'utf8');fs.unlinkSync(configFile);
  const plugin=f.load(undefined);
  assert.equal(plugin.tools.size,5);assert.equal(plugin.timers.length,0);
  await assert.rejects(()=>plugin.run('friendzone_list_requests',{},'session-a'),/ENOENT/);
  fs.writeFileSync(configFile,'{bad json');
  await assert.rejects(()=>plugin.run('friendzone_list_requests',{},'session-a'));
  assert.equal(f.calls.length,0);assert.equal(plugin.timers.length,0);
  // Session-bound discovery must also keep its registered tools on bad config.
  const bound=f.load('session-b');assert.equal(bound.tools.size,5);assert.equal(bound.timers.length,0);
  fs.writeFileSync(configFile,config);
  assert.equal((await plugin.run('friendzone_list_requests',{},'session-a')).length,0);
  assert.equal((await bound.run('friendzone_list_requests',{})).length,0);
  assert.equal(plugin.timers.length,1);assert.equal(bound.timers.length,1);
});