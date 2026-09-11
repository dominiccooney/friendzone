const assert=require('node:assert/strict');
const test=require('node:test');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const http=require('node:http');
const vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'../src/plugin/friendzone.js'),'utf8');

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
    sandbox.module.exports.default.setup({registerTool:tool=>tools.set(tool.name,tool)},{session:{sessionId:session}});
    return {tools,timers,run:(name,args)=>tools.get(name).execute(args,{sessionId:session})};
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