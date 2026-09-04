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
    const pending = c.state === "pending";
    const section = document.createElement("section");
    section.className = "container"; section.draggable = true; section.dataset.id = c.id;
    const pin = c.pinned_ip ? (c.pinned_ip.startsWith("~") ? `last seen ${esc(c.pinned_ip.slice(1))}, not pinned` : `pinned to ${esc(c.pinned_ip)}`) : "any address";
    const actions = pending
      ? `<span class="state killed">awaiting approval</span><button class="approve">Approve</button><button class="approve-pin">Approve + pin IP</button><button class="quiet remove">Deny</button>`
      : `<span class="state ${killed?"killed":"working"}">${killed?"killed":"working"}</span><button class="stop ${killed?"resume":""}">${killed?"Resume":"Kill"}</button><button class="quiet pin-edit">Pin…</button><button class="quiet remove">Remove</button>`;
    section.innerHTML = `<div class="container-head"><span class="status-dot ${killed||pending?"":"live"}" style="${killed||pending?"background:#999":""}"></span><div><div class="container-name">${esc(c.name)}</div><div class="meta">${c.request_count} requests · last traffic ${displayTime(c.last_activity)} · ${pin}</div></div><div class="actions">${actions}</div></div><div class="container-body">${pending?"This container asked to join (first traffic or fz setup). Approving lets its requests through.":"No decisions waiting"}</div>`;
    section.querySelector(".stop")?.addEventListener("click", () => setKilled(c.id, !killed).catch(console.error));
    section.querySelector(".approve")?.addEventListener("click", async () => {
      await fetch(`/api/containers/${encodeURIComponent(c.id)}/approve`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({pin_to_last_ip:false})});
      refresh();
    });
    section.querySelector(".approve-pin")?.addEventListener("click", async () => {
      await fetch(`/api/containers/${encodeURIComponent(c.id)}/approve`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({pin_to_last_ip:true})});
      refresh();
    });
    section.querySelector(".pin-edit")?.addEventListener("click", async () => {
      const current = c.pinned_ip && !c.pinned_ip.startsWith("~") ? c.pinned_ip : "";
      const ip = prompt(`Pin '${c.name}' to an IP (empty = any address):`, current);
      if (ip === null) return;
      const r = await fetch(`/api/containers/${encodeURIComponent(c.id)}/pin`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({ip:ip||null})});
      if (!r.ok) alert(await r.text());
      refresh();
    });
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
  const query = $("#search").value.trim().toLowerCase(), container=$("#container-filter").value, verdict=$("#verdict-filter").value;
  $("#requests").innerHTML = snapshot.requests
    .filter(r => (!container||r.container===container)
      && (!verdict||r.verdict===verdict)
      && (!query||`${r.container} ${r.method} ${r.url} ${r.status??""} ${r.detail??""} ${r.verdict}`.toLowerCase().includes(query)))
    .map(r=>{
      const status = r.status ? `<span class="verdict ${r.status<400?"allowed":"blocked"}">${r.status}</span> ` : "";
      const detail = r.detail ? `<div class="meta">${esc(r.detail)}</div>` : "";
      return `<div class="log-row"><span>${displayTime(r.at)}</span><span class="container-id">${esc(r.container)}</span><span class="request">${status}<span class="method">${esc(r.method)}</span>${esc(r.url)}${detail}</span><span class="verdict ${r.verdict}">${esc(r.verdict)}</span></div>`;
    }).join("") || '<div class="log-row">No matching requests.</div>';
  const selected=$("#container-filter").value; $("#container-filter").innerHTML='<option value="">All containers</option>'+snapshot.containers.map(c=>`<option value="${esc(c.id)}">${esc(c.name)}</option>`).join(""); $("#container-filter").value=selected;
}

async function refresh() { try { const response=await fetch("/api/state"); snapshot=await response.json(); renderContainers(); renderLog(); } catch(e) { console.error(e); } }

const PROVIDER_PRESETS = {
  anthropic: {
    name: "anthropic", hosts: "api.anthropic.com", header: "x-api-key", prefix: "", guest: "ANTHROPIC_API_KEY",
    hint: "Get a key at console.anthropic.com → Settings → API keys. Agents read it from ANTHROPIC_API_KEY.",
  },
  cline: {
    name: "cline", hosts: "api.cline.bot", header: "authorization", prefix: "Bearer ", guest: "CLINE_API_KEY",
    hint: "Easiest: add the entry (key field empty), then click 'Sign in with Cline…' on its row — tokens are fetched and refreshed automatically. Or paste a static API key from app.cline.bot → Settings → API Keys. Agents read it from CLINE_API_KEY.",
  },
  github: {
    name: "github", hosts: "api.github.com,github.com,codeload.github.com", header: "authorization", prefix: "Bearer ", guest: "GITHUB_TOKEN",
    hint: "Use a fine-grained PAT from github.com → Settings → Developer settings → Personal access tokens (read-only scopes recommended), or reuse the gh CLI's token: run `gh auth token`. Agents and gh read it from GITHUB_TOKEN. Note: GitHub writes are blocked by policy regardless of the token's scopes.",
  },
  custom: { name: "", hosts: "", header: "", prefix: "", guest: "", hint: "Fill the advanced fields: pinned hosts, credential header, optional 'Bearer ' prefix, and the env var the agent expects." },
};

$("#e-provider").onchange = () => {
  const preset = PROVIDER_PRESETS[$("#e-provider").value];
  if (!preset) { $("#e-hint").textContent = ""; return; }
  $("#e-name").value = preset.name; $("#e-hosts").value = preset.hosts;
  $("#e-header").value = preset.header; $("#e-prefix").value = preset.prefix;
  $("#e-guest").value = preset.guest;
  $("#e-hint").textContent = preset.hint;
  $("#e-advanced").open = $("#e-provider").value === "custom";
};

async function renderSettings() {
  const [escrow, mcp, env] = await Promise.all([
    fetch("/api/escrow").then(r=>r.json()),
    fetch("/api/mcp").then(r=>r.json()),
    fetch("/api/guest-env").then(r=>r.text()),
  ]);
  window._escrowEntries = escrow.entries;
  $("#escrow-list").innerHTML = escrow.entries.map(e=>{
    const clineBtn = e.name === "cline" ? ` <button class="quiet" data-cline-oauth="${esc(e.name)}">Sign in with Cline…</button>` : "";
    return `<div class="log-row"><span>${esc(e.name)}</span><span>${esc(e.hosts.join(", "))}</span><span class="request">${esc(e.header)}${e.prefix?` · prefix '${esc(e.prefix)}'`:""} · fake <code>${esc(e.fake)}</code></span><span>${e.connected?'<span class="verdict allowed">connected</span>':`<button class="quiet" data-secret="${esc(e.name)}">Set key…</button>`}${clineBtn} <button class="quiet" data-escrow-edit="${esc(e.name)}">Edit</button> <button class="quiet" data-escrow-delete="${esc(e.name)}">Delete</button></span></div>`;
  }).join("") || '<div class="log-row">No escrow entries yet.</div>';
  $("#mcp-list").innerHTML = mcp.forwards.map(f=>{
    const expiry = f.expires_at ? ` · expires ${new Date(f.expires_at*1000).toLocaleString()}${f.refreshable?" (auto-refresh)":""}` : "";
    const status = f.auth==="oauth" ? `<span class="verdict allowed">OAuth</span>${esc(expiry)} <button class="quiet" data-oauth="${esc(f.name)}">Reauthorize…</button> <button class="quiet" data-oauth-disconnect="${esc(f.name)}">Disconnect</button>`
      : f.auth==="stored-key" || f.auth==="env-key" ? `<span class="verdict allowed">${esc(f.auth)}</span> <button class="quiet" data-oauth="${esc(f.name)}">Switch to OAuth…</button>`
      : `<button class="quiet" data-oauth="${esc(f.name)}">Connect (OAuth)…</button>`;
    return `<div class="log-row"><span>${esc(f.name)}</span><span class="request">${esc(f.url)} · ${f.tools.length} tools${f.scope?` · scope ${esc(f.scope)}`:""}</span><span>${status}</span></div>`;
  }).join("") || `<div class="log-row">No MCP forwards configured. Create <code>${esc(mcp.config_path)}</code> (see README for the format), then restart the broker.</div>`;
  const [curlLine, ...envRest] = env.split("\n");
  $("#guest-env-curl").textContent = curlLine.replace(/^# Fetch from a guest: /, "");
  $("#guest-env").textContent = envRest.join("\n");
  if (!$("#mcp-editor").value) {
    fetch("/api/mcp/config").then(r=>r.text()).then(text => { $("#mcp-editor").value = text; });
  }
  document.querySelectorAll("[data-secret]").forEach(b=>b.onclick=async()=>{
    const value = prompt(`Real value for '${b.dataset.secret}' (stored on host only):`);
    if (!value) return;
    await fetch(`/api/escrow/${encodeURIComponent(b.dataset.secret)}/secret`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({value})});
    renderSettings();
  });
  document.querySelectorAll("[data-cline-oauth]").forEach(b=>b.onclick=async()=>{
    const entry = b.dataset.clineOauth;
    const r = await fetch(`/api/escrow/${encodeURIComponent(entry)}/cline-oauth/start`,{method:"POST"});
    if (!r.ok) { alert(`Cline sign-in failed to start: ${await r.text()}`); return; }
    const login = await r.json();
    $("#e-hint").innerHTML = `Cline sign-in: confirm code <strong style="font-size:1.4em">${esc(login.user_code)}</strong> in the browser tab that opened (or visit ${esc(login.verification_uri)}). Waiting…`;
    const poll = setInterval(async () => {
      const s = await fetch(`/api/escrow/${encodeURIComponent(entry)}/cline-oauth/status`);
      if (!s.ok) return;
      const status = await s.json();
      if (status.state === "connected") {
        clearInterval(poll);
        $("#e-hint").textContent = "Cline account connected. Tokens auto-refresh.";
        renderSettings();
      } else if (status.state === "failed") {
        clearInterval(poll);
        $("#e-hint").textContent = `Cline sign-in failed: ${status.error}`;
      }
    }, 2000);
  });
  document.querySelectorAll("[data-escrow-edit]").forEach(b=>b.onclick=()=>{
    const entry = window._escrowEntries.find(e=>e.name===b.dataset.escrowEdit);
    if (!entry) return;
    $("#e-provider").value = PROVIDER_PRESETS[entry.name] ? entry.name : "custom";
    $("#e-name").value = entry.name; $("#e-hosts").value = entry.hosts.join(",");
    $("#e-header").value = entry.header; $("#e-prefix").value = entry.prefix || "";
    $("#e-guest").value = entry.guest_env || "";
    $("#e-advanced").open = true;
    editingEntry = entry.name;
    $("#escrow-form button[type=submit]").textContent = "Save changes";
    $("#e-hint").textContent = `Editing '${entry.name}' — the fake key stays the same, so guests keep working. Leave the key field empty to keep the current real key, or paste a new one to rotate it.`;
    $("#e-real").focus();
  });
  document.querySelectorAll("[data-escrow-delete]").forEach(b=>b.onclick=async()=>{
    if (!confirm(`Delete escrow entry '${b.dataset.escrowDelete}' and its stored real key? Containers holding its fake lose access.`)) return;
    await fetch(`/api/escrow/${encodeURIComponent(b.dataset.escrowDelete)}`,{method:"DELETE"});
    renderSettings();
  });
  document.querySelectorAll("[data-oauth-disconnect]").forEach(b=>b.onclick=async()=>{
    if (!confirm(`Disconnect OAuth for '${b.dataset.oauthDisconnect}'?`)) return;
    await fetch(`/api/mcp/${encodeURIComponent(b.dataset.oauthDisconnect)}/oauth`,{method:"DELETE"});
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

$("#mcp-save").onclick = async () => {
  const r = await fetch("/api/mcp/config",{method:"PUT",headers:{"content-type":"application/json"},body:$("#mcp-editor").value});
  if (!r.ok) { $("#mcp-editor-status").textContent = `✗ ${await r.text()}`; return; }
  const {forwards} = await r.json();
  $("#mcp-editor-status").textContent = `✓ applied, ${forwards} forward(s) active`;
  renderSettings();
};

$("#mcp-reload").onclick = async () => {
  const r = await fetch("/api/mcp/reload",{method:"POST"});
  if (!r.ok) { $("#mcp-editor-status").textContent = `✗ ${await r.text()}`; return; }
  const {forwards} = await r.json();
  const text = await (await fetch("/api/mcp/config")).text();
  $("#mcp-editor").value = text;
  $("#mcp-editor-status").textContent = `✓ reloaded, ${forwards} forward(s) active`;
  renderSettings();
};

$("#add-container").onsubmit = async (e) => {
  e.preventDefault();
  const r = await fetch("/api/containers",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({name:$("#new-container-name").value})});
  if (!r.ok) { alert(await r.text()); return; }
  e.target.reset(); refresh();
};

let editingEntry = null;

$("#escrow-form").onsubmit = async (e) => {
  e.preventDefault();
  if (!editingEntry && !$("#e-provider").value) { alert("Pick a provider (or Custom…) first."); return; }
  const body = {
    name: $("#e-name").value.trim(),
    hosts: $("#e-hosts").value.split(",").map(h=>h.trim()).filter(Boolean),
    header: $("#e-header").value.trim().toLowerCase(),
    prefix: $("#e-prefix").value,
    guest_env: $("#e-guest").value.trim() || null,
    real_value: $("#e-real").value || null,
  };
  if (!body.name || !body.hosts.length || !body.header) {
    alert("Missing name/hosts/header — open Advanced and fill them in."); return;
  }
  const r = editingEntry
    ? await fetch(`/api/escrow/${encodeURIComponent(editingEntry)}`,{method:"PUT",headers:{"content-type":"application/json"},body:JSON.stringify(body)})
    : await fetch("/api/escrow",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});
  if (!r.ok) { alert(await r.text()); return; }
  editingEntry = null;
  $("#escrow-form button[type=submit]").textContent = "Add";
  e.target.reset(); $("#e-hint").textContent = ""; renderSettings();
};

document.querySelectorAll(".nav").forEach(button=>button.onclick=()=>{document.querySelectorAll(".nav,.view").forEach(n=>n.classList.remove("active"));button.classList.add("active");$(`#${button.dataset.view}-view`).classList.add("active");if(button.dataset.view==="settings")renderSettings().catch(console.error);});
$("#refresh").onclick=refresh; ["#search","#container-filter","#verdict-filter"].forEach(s=>$(s).addEventListener("input",renderLog));

// Live updates over SSE: the broker pushes a full snapshot on every
// change; EventSource reconnects on its own. The initial fetch covers
// the gap before the stream opens.
refresh();
const events = new EventSource("/api/events");
events.onmessage = (e) => { snapshot = JSON.parse(e.data); renderContainers(); renderLog(); };
events.onerror = () => setTimeout(refresh, 3000); // bridge reconnect gaps
