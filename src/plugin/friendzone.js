// Friendzone managed plugin v1. Cline plugin/steer bridge contract checked at
// cline/cline dd50b97192e21e08408ee2ad1c5190aaf56d610e. No npm dependencies.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const http = require('node:http');
const https = require('node:https');
const crypto = require('node:crypto');

const MAX_UPLOAD = 10 * 1024 * 1024;
const MAX_RESPONSE = 32 * 1024 * 1024; // up to 4 MiB result, JSON escaped by broker
const observers = new Map();
const REQUIRED_IDLE_MS = 90000000;
function notificationDelivery(){
  const value=Number(process.env.CLINE_PLUGIN_IDLE_TIMEOUT_MS);
  const idle=Number.isInteger(value)&&value>0&&value<=2147483647?value:1800000;
  const bridge=typeof globalThis.__clinePluginHost?.emitEvent==='function';
  return {bridge_available:bridge,configured_idle_timeout_ms:idle,
    warning:!bridge?'Cline steer bridge unavailable; retrieve results with friendzone_get_request.':idle<REQUIRED_IDLE_MS?'Cline may stop the background observer before review completes. Update guest setup and restart the guest hub; get/list still recover accepted requests.':null};
}
function atomic(file, value) {
  fs.mkdirSync(path.dirname(file), {recursive:true,mode:0o700});
  const temp=file+'.'+crypto.randomUUID()+'.tmp';
  try { fs.writeFileSync(temp,JSON.stringify(value),{mode:0o600});fs.renameSync(temp,file); }
  finally {if(fs.existsSync(temp))fs.unlinkSync(temp);}
}
function request(config, method, route, body) {
  const url=new URL(route,config.broker);
  if(url.origin!==new URL(config.broker).origin)throw new Error('Broker origin mismatch');
  const payload=body===undefined?null:JSON.stringify(body);
  if(payload && Buffer.byteLength(payload)>MAX_UPLOAD+4096)throw new Error('Submission exceeds 10 MiB');
  return new Promise((resolve,reject)=>{
    // Node http(s) talks directly to this fixed bootstrap origin. Never follows
    // redirects or relies on the user's proxy/NO_PROXY interpretation.
    const req=(url.protocol==='https:'?https:http).request(url,{method,agent:false,headers:{
      Authorization:'Basic '+Buffer.from(config.container+':x').toString('base64'),
      ...(payload?{'content-type':'application/json','content-length':Buffer.byteLength(payload)}:{}),
    }},response=>{
      const chunks=[];let size=0;
      response.on('data',chunk=>{size+=chunk.length;if(size>MAX_RESPONSE){req.destroy(new Error('Broker response exceeds limit'));return;}chunks.push(chunk);});
      response.on('error',reject);
      response.on('end',()=>{
        const text=Buffer.concat(chunks).toString('utf8');
        if(response.statusCode<200||response.statusCode>=300){reject(new Error(`Friendzone HTTP ${response.statusCode}: ${text.slice(0,2000)}`));return;}
        try{resolve(text?JSON.parse(text):null);}catch{reject(new Error('Invalid broker JSON response'));}
      });
    });
    const timer=setTimeout(()=>req.destroy(new Error('Broker call timed out; use the same request_key to recover submission')),15000);
    req.on('close',()=>clearTimeout(timer));req.on('error',reject);
    req.end(payload);
  });
}

// Configuration and observers belong to a real session, not tool discovery.
// Each setup owns its runtime snapshots; a later setup replaces that session's
// observer without allowing an in-flight old poll to steer it afterwards.
function createSessionRuntime(session,ctx){
  const home=process.env.CLINE_DIR?.trim()||path.join(os.homedir(),'.cline');
  const config=JSON.parse(fs.readFileSync(path.join(home,'friendzone.json'),'utf8'));
  const origin=new URL(config.broker);
  if(!['http:','https:'].includes(origin.protocol)||origin.username||origin.password||origin.pathname!=='/'||origin.search||origin.hash||typeof config.container!=='string'||!config.container||config.container.includes(':'))throw new Error('Invalid Friendzone configuration; rerun guest setup');
  const base=(process.env.CLINE_DATA_DIR?.trim()||path.join(home,'data'));
  const key=crypto.createHash('sha256').update(JSON.stringify([origin.origin,config.container,session])).digest('hex');
  const file=path.join(base,'friendzone',key+'.json');
  let seen=fs.existsSync(file)?JSON.parse(fs.readFileSync(file,'utf8')):{};
  if(!seen||typeof seen!=='object'||Array.isArray(seen))throw new Error('Invalid Friendzone notification checkpoint');
  const previous=observers.get(key);if(previous){previous.stopped=true;clearInterval(previous.timer);}
  const observer={stopped:false,timer:null};observers.set(key,observer);
  const suffix='?session_id='+encodeURIComponent(session);
  let polling=false;
  async function poll(){
    if(polling||observer.stopped)return;polling=true;
    try{
      const emit=globalThis.__clinePluginHost?.emitEvent;
      if(typeof emit!=='function')return; // get/list remain available without steering.
      const jobs=await request(config,'GET','/guest/jobs'+suffix);
      if(observer.stopped)return;
      const next={};
      for(const job of jobs){
        if(job.session_id!==session||!job.terminal)continue;
        const version=job.status+':'+job.updated_at;next[job.id]=version;
        if(seen[job.id]===version)continue;
        // Fixed metadata only: never promote GitHub content into steer prompts.
        if(!/^[0-9a-f-]{36}$/i.test(job.id)||!['response_received','graphql_error','denied','cancelled','expired','blocked','unknown','upstream_error'].includes(job.status))continue;
        emit('steer_message',{sessionId:session,prompt:`Friendzone request ${job.id}: ${job.status}${Number.isInteger(job.http_status)?' (HTTP '+job.http_status+')':''}. Use friendzone_get_request to retrieve its result. Do not resubmit this operation automatically.`});
      }
      seen=next;atomic(file,seen);
    }catch(error){ctx.logger?.debug?.('Friendzone status poll unavailable',{message:String(error)});}
    finally{polling=false;}
  }
  const timer=setInterval(poll,3000);observer.timer=timer;timer.unref?.();void poll();
  // Sandboxed Cline kills the plugin child on session shutdown. No detached
  // process is launched; unref prevents an in-process host being kept alive.
  if(typeof globalThis.__clinePluginHost?.emitEvent!=='function')ctx.logger?.log?.('Friendzone automatic session updates unavailable; use get/list requests.');
  const delivery=notificationDelivery();if(delivery.warning)ctx.logger?.log?.(delivery.warning);
  return {config,session,base,key,suffix,observer};
}

function sessionId(value){return typeof value==='string' && value.trim() && Buffer.byteLength(value)<=256 ? value : undefined;}
function idRoute(id){if(typeof id!=='string'||!/^[0-9a-f-]{36}$/i.test(id))throw new Error('Invalid request ID');return '/guest/jobs/'+id;}

const plugin={name:'friendzone',manifest:{capabilities:['tools']},setup(api,ctx={}){
  const setupSession=sessionId(ctx?.session?.sessionId);
  const runtimes=new Map();
  function runtimeFor(context){
    const raw=context?.sessionId;
    const executionSession=sessionId(raw);
    if(raw!=null && !executionSession)throw new Error('A valid Cline session ID is required to execute Friendzone tools');
    if(setupSession && executionSession && setupSession!==executionSession)throw new Error('Friendzone tool session mismatch');
    const session=executionSession||setupSession;
    if(!session)throw new Error('A Cline session is required to execute Friendzone tools; discovery does not need one');
    if(!runtimes.has(session))runtimes.set(session,createSessionRuntime(session,ctx));
    const runtime=runtimes.get(session);
    if(runtime.observer.stopped)throw new Error('Friendzone session runtime was replaced; reload the session tools');
    return runtime;
  }
  // Cline's listPluginTools discovers contributions with {workspaceInfo}, no
  // session. Always register descriptors; resolve state only for real execution.
  const tool=(name,description,properties,required,execute)=>api.registerTool({name,description,inputSchema:{type:'object',properties,required,additionalProperties:false},timeoutMs:20000,retryable:false,execute:async(input,context)=>{
    return execute(input||{},runtimeFor(context));
  }});
  tool('friendzone_submit_graphql','Submit GitHub GraphQL asynchronously. Returns immediately; mutations require host Inbox approval. Completion arrives as a steer message. Use the same request_key to recover a failed submission, never generate a new key to blindly retry a write. Large payloads: provide an absolute request_file containing {query,variables,operationName}.',{
    request_key:{type:'string',description:'Stable unique key for this intended operation; reuse only with identical content.'},query:{type:'string'},variables:{type:['object','null']},operation_name:{type:['string','null']},request_file:{type:'string',description:'Absolute guest path to a GraphQL JSON envelope (up to 10 MiB); mutually exclusive with inline query/variables.'},
  },['request_key'],async (input,{config,session})=>{
    if(typeof input.request_key!=='string'||!input.request_key)throw new Error('request_key required');
    let query=input.query,variables=input.variables??null,operation_name=input.operation_name??null;
    if(input.request_file){
      if(query!==undefined||input.variables!==undefined||input.operation_name!==undefined)throw new Error('Use request_file OR inline GraphQL');
      if(!path.isAbsolute(input.request_file))throw new Error('request_file must be absolute');
      const fd=fs.openSync(input.request_file,fs.constants.O_RDONLY|fs.constants.O_NONBLOCK);
      try{const stat=fs.fstatSync(fd);if(!stat.isFile()||stat.size>MAX_UPLOAD)throw new Error('request_file must be a regular file up to 10 MiB');
        const buffer=Buffer.alloc(MAX_UPLOAD+1);let length=0;while(length<buffer.length){const n=fs.readSync(fd,buffer,length,buffer.length-length,null);if(!n)break;length+=n;}if(length>MAX_UPLOAD)throw new Error('Request file exceeds 10 MiB');
        const parsed=JSON.parse(buffer.subarray(0,length).toString('utf8'));if(Object.keys(parsed).some(k=>!['query','variables','operationName'].includes(k)))throw new Error('Unsupported GraphQL envelope fields');
        query=parsed.query;variables=parsed.variables??null;operation_name=parsed.operationName??null;
      }finally{fs.closeSync(fd);}
    }
    if(typeof query!=='string'||!query)throw new Error('query required');
    const accepted=await request(config,'POST','/guest/jobs',{request_key:input.request_key,session_id:session,query,variables,operation_name});
    return {...accepted,notification_delivery:notificationDelivery()};
  });
  tool('friendzone_get_request','Retrieve a submitted request result. Does not execute or retry it. Large results are saved to a guest file.',{id:{type:'string'}},['id'],async (input,{config,suffix,base,key})=>{
    const result=await request(config,'GET',idRoute(input.id)+suffix);
    if(typeof result.result==='string'&&result.result.length>48000){const resultFile=path.join(base,'friendzone',key+'-'+input.id+'-result.json');atomic(resultFile,{result:result.result});return {...result,result:result.result.slice(0,48000),result_truncated:true,result_file:resultFile};}
    return result;
  });
  tool('friendzone_list_requests','List this guest/session’s submitted requests and statuses.',{},[],(_, {config,suffix})=>request(config,'GET','/guest/jobs'+suffix));
  tool('friendzone_cancel_request','Cancel a pending or queued job. Execution already started cannot be cancelled or undone.',{id:{type:'string'}},['id'],async (input,{config,suffix})=>{await request(config,'POST',idRoute(input.id)+'/cancel'+suffix);return {id:input.id,cancelled:true};});
  tool('friendzone_remove_result','Remove a finished job and its deduplication key to release storage. Do not resubmit the removed operation.',{id:{type:'string'}},['id'],async (input,{config,suffix})=>{await request(config,'DELETE',idRoute(input.id)+suffix);return {id:input.id,removed:true};});
  // A resumed session must recover notifications without submitting another job.
  // Bad configuration is an execution error, never a missing-tool/discovery error.
  if(setupSession){try{runtimeFor();}catch{ctx.logger?.log?.('Friendzone notifications could not start; tool execution will report configuration errors.');}}
}};
// Cline imports this CommonJS file through Jiti/dynamic import, which supplies
// the default namespace wrapper. Export the plugin itself, not another wrapper.
module.exports=plugin;