const $ = (s) => document.querySelector(s);
let snapshot = { containers: [], requests: [] };
let order = JSON.parse(localStorage.getItem("fz-order") || "[]");

function esc(value) { return String(value).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#39;"); }
function displayTime(value) { return new Date(value).toLocaleTimeString([], {hour:"2-digit",minute:"2-digit",second:"2-digit"}); }
function ordered(containers) { return [...containers].sort((a,b) => { const ai=order.indexOf(a.id),bi=order.indexOf(b.id); if(ai<0&&bi<0)return 0;if(ai<0)return 1;if(bi<0)return-1;return ai-bi; }); }

async function setKilled(id, killed) {
  const response = await fetch(`/api/containers/${encodeURIComponent(id)}/kill`, {method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({killed})});
  if (!response.ok) throw new Error(`Kill request failed: ${response.status}`);
  await refresh();
}

function renderContainers() {
  const root = $("#containers"); root.innerHTML = "";
  if (!snapshot.containers.length) { root.append($("#empty-template").content.cloneNode(true)); return; }
  for (const c of ordered(snapshot.containers)) {
    const killed = c.state === "killed";
    const section = document.createElement("section");
    section.className = "container"; section.draggable = true; section.dataset.id = c.id;
    section.innerHTML = `<div class="container-head"><span class="status-dot ${killed?"":"live"}" style="${killed?"background:#999":""}"></span><div><div class="container-name">${esc(c.name)}</div><div class="meta">${c.request_count} requests · last traffic ${displayTime(c.last_activity)}</div></div><div class="actions"><span class="state ${killed?"killed":"working"}">${killed?"killed":"working"}</span><button class="stop ${killed?"resume":""}">${killed?"Resume":"Kill"}</button><button class="quiet remove">Remove</button></div></div><div class="container-body">No decisions waiting</div>`;
    section.querySelector(".stop").onclick = () => setKilled(c.id, !killed).catch(console.error);
    section.querySelector(".remove").onclick = async () => {
      if (!confirm(`Remove container '${c.name}'? Kill it first if it is still running.`)) return;
      await fetch(`/api/containers/${encodeURIComponent(c.id)}`, {method:"DELETE"});
      refresh();
    };
    section.addEventListener("dragstart", () => section.classList.add("dragging"));
    section.addEventListener("dragend", () => { section.classList.remove("dragging"); order=[...root.querySelectorAll(".container")].map(n=>n.dataset.id);localStorage.setItem("fz-order",JSON.stringify(order)); });
    root.append(section);
  }
  root.ondragover = e => { e.preventDefault(); const active=root.querySelector(".dragging");if(!active)return;const next=[...root.querySelectorAll(".container:not(.dragging)")].find(n=>e.clientY<n.getBoundingClientRect().top+n.offsetHeight/2);root.insertBefore(active,next||null); };
}

function renderLog() {
  const query = $("#search").value.toLowerCase(), container=$("#container-filter").value, verdict=$("#verdict-filter").value;
  $("#requests").innerHTML = snapshot.requests.filter(r => (!container||r.container===container)&&(!verdict||r.verdict===verdict)&&(!query||`${r.container} ${r.method} ${r.url}`.toLowerCase().includes(query))).map(r=>`<div class="log-row"><span>${displayTime(r.at)}</span><span class="container-id">${esc(r.container)}</span><span class="request"><span class="method">${esc(r.method)}</span>${esc(r.url)}</span><span class="verdict ${r.verdict}">${esc(r.verdict)}</span></div>`).join("");
  const selected=$("#container-filter").value; $("#container-filter").innerHTML='<option value="">All containers</option>'+snapshot.containers.map(c=>`<option value="${esc(c.id)}">${esc(c.name)}</option>`).join(""); $("#container-filter").value=selected;
}

async function refresh() { try { const response=await fetch("/api/state"); snapshot=await response.json(); renderContainers(); renderLog(); } catch(e) { console.error(e); } }

async function renderSettings() {
  const [escrow, mcp, env] = await Promise.all([
    fetch("/api/escrow").then(r=>r.json()),
    fetch("/api/mcp").then(r=>r.json()),
    fetch("/api/guest-env").then(r=>r.text()),
  ]);
  $("#escrow-list").innerHTML = escrow.entries.map(e=>`<div class="log-row"><span>${esc(e.name)}</span><span>${esc(e.hosts.join(", "))}</span><span class="request">${esc(e.header)} · fake <code>${esc(e.fake)}</code></span><span>${e.connected?'<span class="verdict allowed">connected</span>':`<button class="quiet" data-secret="${esc(e.name)}">Set key…</button>`}</span></div>`).join("") || '<div class="log-row">No escrow entries yet.</div>';
  $("#mcp-list").innerHTML = mcp.forwards.map(f=>`<div class="log-row"><span>${esc(f.name)}</span><span class="request">${esc(f.url)} · ${f.tools.length} tools</span><span>${f.connected?'<span class="verdict allowed">connected</span>':`<button class="quiet" data-oauth="${esc(f.name)}">Connect (OAuth)…</button>`}</span></div>`).join("") || '<div class="log-row">No MCP forwards configured (mcp-forwards.json).</div>';
  $("#guest-env").textContent = env;
  document.querySelectorAll("[data-secret]").forEach(b=>b.onclick=async()=>{
    const value = prompt(`Real value for '${b.dataset.secret}' (stored on host only):`);
    if (!value) return;
    await fetch(`/api/escrow/${encodeURIComponent(b.dataset.secret)}/secret`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({value})});
    renderSettings();
  });
  document.querySelectorAll("[data-oauth]").forEach(b=>b.onclick=async()=>{
    const r = await fetch(`/api/mcp/${encodeURIComponent(b.dataset.oauth)}/oauth/start`,{method:"POST"});
    if (!r.ok) { alert(`OAuth start failed: ${await r.text()}`); return; }
    const {authorize_url} = await r.json();
    alert(`Complete the login in your browser.\nIf it did not open: ${authorize_url}`);
    setTimeout(renderSettings, 3000);
  });
}

$("#add-container").onsubmit = async (e) => {
  e.preventDefault();
  const r = await fetch("/api/containers",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({name:$("#new-container-name").value})});
  if (!r.ok) { alert(await r.text()); return; }
  e.target.reset(); refresh();
};

$("#escrow-form").onsubmit = async (e) => {
  e.preventDefault();
  const body = {
    name: $("#e-name").value.trim(),
    hosts: $("#e-hosts").value.split(",").map(h=>h.trim()).filter(Boolean),
    header: $("#e-header").value.trim().toLowerCase(),
    prefix: $("#e-prefix").value,
    fake: "",
    guest_env: $("#e-guest").value.trim() || null,
  };
  const r = await fetch("/api/escrow",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});
  if (!r.ok) { alert(await r.text()); return; }
  e.target.reset(); renderSettings();
};

document.querySelectorAll(".nav").forEach(button=>button.onclick=()=>{document.querySelectorAll(".nav,.view").forEach(n=>n.classList.remove("active"));button.classList.add("active");$(`#${button.dataset.view}-view`).classList.add("active");if(button.dataset.view==="settings")renderSettings().catch(console.error);});
$("#refresh").onclick=refresh; ["#search","#container-filter","#verdict-filter"].forEach(s=>$(s).addEventListener("input",renderLog));
refresh(); setInterval(refresh,2000);
