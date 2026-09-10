const $ = (s) => document.querySelector(s);
let snapshot = { containers: [], requests: [], pending_requests: [] };
let logRows = [], logCursor = null, logPaused = false, logGeneration = 0, logTimer;
let order = readStoredOrder();
let mcpConnectData = null, mcpHostInitialized = false, mcpConnectGeneration = 0, mcpGuestSignature = "";
const mcpOAuthPolls = new Map();
let reviewingMcp = null;
let activeMcpOAuth = null;
let activeReview = null, reviewGeneration = 0, pendingSignature = "";
let notificationTimer = null, newNotificationIds = new Set();
let notificationsEnabled = readStoredValue("fz-notifications") === "enabled";
let notifiedIds;
try { const saved = JSON.parse(readStoredValue("fz-notified-requests") || "[]"); notifiedIds = new Set(Array.isArray(saved)?saved.filter(id=>typeof id==="string").slice(-128):[]); } catch { notifiedIds = new Set(); }

function esc(value) { return String(value).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#39;"); }
function displayTime(value) { return new Date(value).toLocaleTimeString([], {hour:"2-digit",minute:"2-digit",second:"2-digit"}); }
function readStoredValue(key) { try { return localStorage.getItem(key); } catch { return null; } }
function storeValue(key, value) { try { localStorage.setItem(key, value); } catch { /* Private/restricted browsers still work without persistence. */ } }
function readStoredOrder() {
  try { const value = JSON.parse(readStoredValue("fz-order") || "[]"); return Array.isArray(value) ? value.filter(v=>typeof v==="string") : []; } catch { return []; }
}
function containerStatus(container) {
  return container.state === "killed" ? "Killed" : container.approved ? "Approved" : "Awaiting approval";
}
function containerTraffic(container) {
  return container.last_activity ? `Last guest traffic: ${new Date(container.last_activity).toLocaleString()}` : "No guest traffic observed this broker session";
}
function ordered(containers) { return [...containers].sort((a,b) => { const ai=order.indexOf(a.id),bi=order.indexOf(b.id); if(ai<0&&bi<0)return 0;if(ai<0)return 1;if(bi<0)return-1;return ai-bi; }); }

async function setKilled(id, killed) {
  const response = await fetch(`/api/containers/${encodeURIComponent(id)}/kill`, {method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({killed})});
  if (!response.ok) throw rejectedContainerChange(await response.text());
  await refresh();
}

function rejectedContainerChange(message) { const error = new Error(message); error.policyUnchanged = true; return error; }
function showContainerError(error) {
  $("#container-error").textContent = error.policyUnchanged
    ? `Change not applied: ${error.message}. Existing policy remains in effect.`
    : `Could not confirm the change: ${error.message || error}. Refresh to check the actual policy; do not assume Kill or approval succeeded.`;
}
async function changeContainerPolicy(url, options) {
  $("#container-error").textContent = "";
  try {
    const response = await fetch(url, options);
    if (!response.ok) throw rejectedContainerChange(await response.text());
    await refresh();
    return true;
  } catch (error) { showContainerError(error); return false; }
}

function renderContainers() {
  renderPendingRequests();
  updateMcpConnectionGuests();
  const root = $("#containers"); root.innerHTML = "";
  if (!snapshot.containers.length) { root.append($("#empty-template").content.cloneNode(true)); return; }
  for (const c of ordered(snapshot.containers)) {
    const killed = c.state === "killed";
    const pending = !killed && !c.approved;
    const section = document.createElement("section");
    section.className = "container"; section.draggable = true; section.dataset.id = c.id;
    const pin = c.pinned_ip ? (c.pinned_ip.startsWith("~") ? `last seen ${esc(c.pinned_ip.slice(1))}, not pinned` : `pinned to ${esc(c.pinned_ip)}`) : "any address";
    const actions = pending
      ? `<span class="state killed">awaiting approval</span><button class="approve">Approve</button><button class="approve-pin">Approve + pin IP</button><button class="quiet remove">Deny</button>`
      : `<span class="state ${killed?"killed":"approved"}" title="Network authorization, not agent activity">${containerStatus(c)}</span><button class="stop ${killed?"resume":""}">${killed?"Resume":"Kill"}</button><button class="quiet pin-edit">Pin…</button><button class="quiet remove">Remove</button>`;
    section.innerHTML = `<div class="container-head"><span class="status-dot" style="background:${killed?"var(--red)":"#999"}" title="${esc(containerStatus(c))}; agent activity is not monitored"></span><div><div class="container-name">${esc(c.name)}</div><div class="meta">${c.request_count} retained requests · ${esc(containerTraffic(c))} · ${pin}</div></div><div class="actions">${actions}</div></div><div class="container-body">${pending?"This container asked to join. Approving permits network requests; it does not mean the agent is running.":"Agent activity is not monitored. Approval does not mean the container is busy or even online."}</div>`;
    section.querySelector(".stop")?.addEventListener("click", () => {$("#container-error").textContent="";return setKilled(c.id, !killed).catch(showContainerError);});
    section.querySelector(".approve")?.addEventListener("click", async () => {
      await changeContainerPolicy(`/api/containers/${encodeURIComponent(c.id)}/approve`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({pin_to_last_ip:false})});
    });
    section.querySelector(".approve-pin")?.addEventListener("click", async () => {
      await changeContainerPolicy(`/api/containers/${encodeURIComponent(c.id)}/approve`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({pin_to_last_ip:true})});
    });
    section.querySelector(".pin-edit")?.addEventListener("click", async () => {
      const current = c.pinned_ip && !c.pinned_ip.startsWith("~") ? c.pinned_ip : "";
      const ip = prompt(`Pin '${c.name}' to an IP (empty = any address):`, current);
      if (ip === null) return;
      await changeContainerPolicy(`/api/containers/${encodeURIComponent(c.id)}/pin`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({ip:ip||null})});
    });
    section.querySelector(".remove").onclick = async () => {
      if (!confirm(`Remove container '${c.name}'? Kill it first if it is still running.`)) return;
      await changeContainerPolicy(`/api/containers/${encodeURIComponent(c.id)}`, {method:"DELETE"});
    };
    section.addEventListener("dragstart", () => section.classList.add("dragging"));
    section.addEventListener("dragend", () => { section.classList.remove("dragging"); order=[...root.querySelectorAll(".container")].map(n=>n.dataset.id);storeValue("fz-order",JSON.stringify(order)); });
    root.append(section);
  }
  root.ondragover = e => { e.preventDefault(); const active=root.querySelector(".dragging");if(!active)return;const next=[...root.querySelectorAll(".container:not(.dragging)")].find(n=>e.clientY<n.getBoundingClientRect().top+n.offsetHeight/2);root.insertBefore(active,next||null); };
}

function renderLog() {
  $("#requests").innerHTML = logRows
    .map(r=>{
      const status = r.status ? `<span class="verdict ${r.status<400?"allowed":"blocked"}">${r.status}</span> ` : "";
      const detail = r.detail ? `<div class="meta">${esc(r.detail)}</div>` : "";
      return `<div class="log-row"><span>${displayTime(r.at)}</span><span class="container-id">${esc(r.container)}</span><span class="request">${status}<span class="method">${esc(r.method)}</span>${esc(r.url)}${detail}</span><span class="verdict ${r.verdict}">${esc(r.verdict)}</span></div>`;
    }).join("") || '<div class="log-row">No matching requests.</div>';
  const selected=$("#container-filter").value;
  const names = [...new Set([...snapshot.containers.map(c=>c.id), ...logRows.map(r=>r.container), ...(selected?[selected]:[])])];
  $("#container-filter").innerHTML='<option value="">All containers</option>'+names.map(id=>`<option value="${esc(id)}">${esc(id)}</option>`).join(""); $("#container-filter").value=selected;
}

function updateNotificationStatus() {
  const supported = typeof Notification !== "undefined" && window.isSecureContext;
  const button = $("#enable-notifications");
  button.disabled = !supported;
  button.textContent = notificationsEnabled ? "Disable notifications" : "Enable notifications";
  $("#notification-status").textContent = !supported ? "Desktop notifications unavailable. Use localhost/HTTPS and a supported desktop browser; Inbox still works."
    : Notification.permission === "denied" ? "Notifications blocked by browser permission. Change site settings to enable them; Inbox still works."
    : notificationsEnabled && Notification.permission === "granted" ? "Notifications enabled while this page is open. Clicking a notification opens Inbox, never approves a request."
    : "Desktop notifications are off. Enable them to be alerted when a guest requests approval.";
}

$("#enable-notifications").onclick = async () => {
  if (notificationsEnabled) {
    notificationsEnabled = false; clearTimeout(notificationTimer); notificationTimer = null; newNotificationIds.clear();
  } else if (typeof Notification !== "undefined" && window.isSecureContext) {
    try { notificationsEnabled = (Notification.permission === "granted" ? "granted" : await Notification.requestPermission()) === "granted"; }
    catch { notificationsEnabled = false; }
  }
  storeValue("fz-notifications", notificationsEnabled ? "enabled" : "disabled");
  updateNotificationStatus();
  notifyPendingRequests(snapshot.pending_requests || []);
};

function notifyPendingRequests(pending) {
  if (!notificationsEnabled || typeof Notification === "undefined" || !window.isSecureContext || Notification.permission !== "granted") return;
  for (const request of pending) if (!notifiedIds.has(request.id)) newNotificationIds.add(request.id);
  if (!newNotificationIds.size || notificationTimer) return;
  notificationTimer = setTimeout(() => {
    notificationTimer = null;
    const live = new Set((snapshot.pending_requests || []).map(request=>request.id));
    const ids = [...newNotificationIds].filter(id=>live.has(id) && !notifiedIds.has(id));
    newNotificationIds.clear();
    if (!ids.length || !notificationsEnabled || Notification.permission !== "granted") return;
    for (const id of ids) notifiedIds.add(id);
    notifiedIds = new Set([...notifiedIds].slice(-128));
    storeValue("fz-notified-requests", JSON.stringify([...notifiedIds]));
    try {
      const notification = new Notification("Friendzone: request approval needed", {
        body: `${ids.length} new request${ids.length===1?"":"s"} waiting. Open the host Inbox to review.`, tag:"friendzone-pending",
      });
      notification.onclick = () => { window.focus(); selectView("inbox"); $("#pending-requests").scrollIntoView({behavior:"smooth",block:"center"}); notification.close(); };
    } catch { $("#notification-status").textContent = "Browser could not display a notification. Requests remain in Inbox."; }
  }, 750);
}

function renderPendingRequests() {
  const pending = snapshot.pending_requests || [];
  $("#inbox-count").textContent = pending.length + snapshot.containers.filter(container=>!container.approved).length;
  const signature = JSON.stringify(pending);
  if (signature !== pendingSignature) {
    pendingSignature = signature;
    $("#pending-requests").innerHTML = pending.map(request=>`<article class="pending-request"><strong>${esc(request.container)}</strong> · ${esc(request.method)} <code>${esc(request.url)}</code><p class="meta">${request.body_bytes} body bytes · expires ${esc(displayTime(request.expires_at))}</p><button type="button" data-review="${esc(request.id)}">Review request</button></article>`).join("") || '<p>No requests waiting for review.</p>';
    document.querySelectorAll("[data-review]").forEach(button=>button.onclick=()=>openRequestReview(button.dataset.review));
  }
  if (activeReview && !pending.some(request=>request.id===activeReview.id)) {
    activeReview = null; ++reviewGeneration;
    $("#request-approve").disabled = true; $("#request-deny").disabled = true;
    $("#request-review-status").textContent = "This request is no longer waiting (decided, cancelled or expired). Check the log for its outcome.";
  }
  updateNotificationStatus(); notifyPendingRequests(pending);
}

async function openRequestReview(id) {
  const generation = ++reviewGeneration; activeReview = null;
  $("#request-review").hidden = true; $("#request-approve").disabled = true; $("#request-deny").disabled = true;
  $("#request-review-status").textContent = "Loading exact request…";
  try {
    const response = await fetch(`/api/requests/${encodeURIComponent(id)}`, {cache:"no-store"});
    if (!response.ok) throw new Error(await response.text());
    const detail = await response.json();
    if (generation !== reviewGeneration) return;
    activeReview = detail;
    $("#request-review-title").textContent = `${detail.container}: ${detail.method} ${detail.url}`;
    $("#request-review-reason").textContent = detail.reason;
    $("#request-review-meta").textContent = `Expires ${new Date(detail.expires_at).toLocaleString()} · SHA-256 ${detail.fingerprint}`;
    $("#request-review-headers").textContent = detail.headers.map(([name,value])=>`${name}: ${value}`).join("\n");
    $("#request-review-body").textContent = detail.body || "(empty body)";
    $("#request-review").hidden = false;
    $("#request-approve").disabled = false; $("#request-deny").disabled = false;
    $("#request-review-status").textContent = "Review all fields before approving. Approval is for this request only; upstream success is not guaranteed.";
    $("#request-review").scrollIntoView({behavior:"smooth",block:"start"});
  } catch (error) { if (generation === reviewGeneration) $("#request-review-status").textContent = String(error); }
}

async function decideRequest(decision) {
  if (!activeReview) return;
  const reviewed = activeReview;
  if (decision === "approve" && !confirm("Forward this exact request once? Only approve if the requesting client is still waiting. Retried writes are separate requests and may duplicate an operation.")) return;
  $("#request-approve").disabled = true; $("#request-deny").disabled = true;
  try {
    const response = await fetch(`/api/requests/${encodeURIComponent(reviewed.id)}/decision`, {method:"POST",headers:{"content-type":"application/json","x-friendzone-review":"1"},body:JSON.stringify({fingerprint:reviewed.fingerprint,decision})});
    if (!response.ok) throw new Error(await response.text());
    activeReview = null; ++reviewGeneration;
    $("#request-review-status").textContent = decision === "approve" ? "Approved once. Check the request log for upstream status; do not blindly retry." : "Denied. The request was not forwarded.";
    await refresh();
  } catch (error) {
    $("#request-review-status").textContent = `Could not confirm the decision: ${error}. Refresh the Inbox/log before retrying.`;
  }
}
$("#request-approve").onclick = () => decideRequest("approve");
$("#request-deny").onclick = () => decideRequest("deny");
$("#request-close").onclick = () => { activeReview = null; ++reviewGeneration; $("#request-review").hidden = true; };
updateNotificationStatus();

async function loadLog(older = false) {
  const generation = ++logGeneration;
  const query = new URLSearchParams({search:$("#search").value, container:$("#container-filter").value, verdict:$("#verdict-filter").value});
  if (older && logCursor !== null) query.set("before", logCursor);
  try {
    const response = await fetch(`/api/log?${query}`);
    if (!response.ok) throw new Error(await response.text());
    const page = await response.json();
    if (generation !== logGeneration) return;
    logRows = older ? [...logRows, ...page.requests] : page.requests;
    logCursor = page.next_before;
    $("#log-more").disabled = logCursor === null;
    $("#log-status").textContent = `${page.retained}/${page.capacity} retained · ${page.evicted} evicted · ${logPaused?"history paused":"live"}`;
    renderLog();
  } catch (error) { $("#log-status").textContent = String(error); }
}

function scheduleLog() {
  if (logPaused || logTimer) return;
  logTimer = setTimeout(() => { logTimer = null; loadLog(); }, 500);
}
$("#log-more").onclick = () => { logPaused = true; clearTimeout(logTimer); logTimer = null; loadLog(true); };
$("#log-live").onclick = () => { logPaused = false; loadLog(); };

async function refresh() { try { const response=await fetch("/api/state"); snapshot=await response.json(); renderContainers(); scheduleLog(); } catch(e) { console.error(e); } }

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
    hint: "Use a fine-grained PAT from github.com → Settings → Developer settings → Personal access tokens (narrow scopes recommended), or reuse the gh CLI's token: run `gh auth token`. Agents and gh read it from GITHUB_TOKEN. GitHub JSON/text writes and GraphQL POSTs require one-shot Inbox review; approval cannot grant scopes your token lacks. Binary git pushes remain blocked.",
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
  mcpConnectData = mcp;
  if (!mcpHostInitialized) {
    $("#mcp-connect-host").value = mcp.guest_host || "";
    mcpHostInitialized = true;
  }
  $("#mcp-connect-address").textContent = `Uses bootstrap port ${mcp.guest_port}, not the UI or proxy port. ${mcp.guest_address_warning || "The host is prefilled from the broker listener; change it only if your guest reaches the host by another address."}`;
  fillMcpConnectSelect("#mcp-connect-forward", mcp.forwards.map(f=>({value:f.name,label:f.name})), "Select a forward");
  updateMcpConnectionGuests();
  loadMcpConnection();
  window._escrowEntries = escrow.entries;
  $("#escrow-list").innerHTML = escrow.entries.map(e=>{
    const clineBtn = e.name === "cline" ? ` <button class="quiet" data-cline-oauth="${esc(e.name)}">Sign in with Cline…</button>` : "";
    return `<div class="log-row"><span>${esc(e.name)}</span><span>${esc(e.hosts.join(", "))}</span><span class="request">${esc(e.header)}${e.prefix?` · prefix '${esc(e.prefix)}'`:""} · fake <code>${esc(e.fake)}</code></span><span>${e.connected?'<span class="verdict allowed">connected</span>':`<button class="quiet" data-secret="${esc(e.name)}">Set key…</button>`}${clineBtn} <button class="quiet" data-escrow-edit="${esc(e.name)}">Edit</button> <button class="quiet" data-escrow-delete="${esc(e.name)}">Delete</button></span></div>`;
  }).join("") || '<div class="log-row">No escrow entries yet.</div>';
  $("#mcp-list").innerHTML = mcp.forwards.map(f=>{
    const expiry = f.expires_at ? ` · expires ${new Date(f.expires_at*1000).toLocaleString()}${f.refreshable?" (auto-refresh)":""}` : "";
    const status = f.auth==="cline-link" ? `<span class="verdict">Uses host Cline's credentials</span><p class="meta">Friendzone reads the saved token; host Cline must refresh it. For independent login and refresh, authorize in Friendzone. No guest OAuth login is needed.</p> <button class="quiet" data-oauth="${esc(f.name)}">Authorize in Friendzone…</button>`
      : f.auth==="oauth" ? `<span class="verdict allowed">Friendzone manages OAuth</span>${esc(expiry)} <button class="quiet" data-oauth="${esc(f.name)}">Reauthorize in Friendzone…</button> <button class="quiet" data-oauth-disconnect="${esc(f.name)}">Disconnect</button>`
      : f.auth==="stored-key" || f.auth==="env-key" ? `<span class="verdict allowed">${esc(f.auth)}</span> <button class="quiet" data-oauth="${esc(f.name)}">Switch to OAuth…</button>`
      : `<button class="quiet" data-oauth="${esc(f.name)}">Authorize in Friendzone…</button>`;
    const endpoint = f.guest_endpoint
      ? `<textarea data-mcp-endpoint rows="2" readonly spellcheck="false" aria-label="Friendzone URL for ${esc(f.name)}">${esc(f.guest_endpoint)}</textarea><button type="button" data-mcp-copy-url="${esc(f.name)}">Copy URL</button>`
      : `<code>/mcp/${esc(encodeURIComponent(f.name))}</code> — set the broker host in Connect from Cline below to get a complete URL.`;
    return `<article class="mcp-card"><header class="mcp-card-heading"><h3>${esc(f.name)}</h3><span>${f.tools.length} allowed tools · guests: ${f.guests===null?"all approved":esc(f.guests.join(", ")||"none")}</span></header><div class="mcp-card-endpoint"><strong>URL to add in guest Cline</strong><div class="mcp-endpoint">${endpoint}</div><p class="meta">URL alone is not enough: <button type="button" data-mcp-connect="${esc(f.name)}">Copy Cline setup…</button> includes the guest Authorization header.</p></div><div class="mcp-card-auth">${status}${f.scope?`<p class="meta">OAuth scope: ${esc(f.scope)}</p>`:""}</div><div class="mcp-card-actions"><button type="button" data-mcp-review="${esc(f.name)}">Choose tools and guests</button><button type="button" class="quiet" data-mcp-delete="${esc(f.name)}">Remove</button></div><p class="mcp-upstream">Upstream (broker only): <code>${esc(f.url)}</code></p></article>`;
  }).join("") || '<p class="mcp-empty">No MCP servers yet. Add or import one below, sign in, then choose what guests may use.</p>';
  fitMcpEndpoints();
  document.querySelectorAll("[data-mcp-copy-url]").forEach(button => button.onclick = () => {
    const input = button.closest(".mcp-card").querySelector("[data-mcp-endpoint]");
    return copyMcpText(input, $("#mcp-copy-status"), "Friendzone URL copied. Use Connect from Cline for the required guest Authorization header or complete JSON.", () => input.isConnected);
  });
  document.querySelectorAll("[data-mcp-connect]").forEach(button => button.onclick = () => {
    $("#mcp-connect-forward").value = button.dataset.mcpConnect;
    loadMcpConnection();
    $("#mcp-connect").scrollIntoView({behavior:"smooth", block:"start"});
  });
  document.querySelectorAll("[data-mcp-review]").forEach(button => button.onclick = () => reviewMcpAccess(button.dataset.mcpReview));
  document.querySelectorAll("[data-mcp-delete]").forEach(button => button.onclick = async () => {
    if (!confirm(`Remove '${button.dataset.mcpDelete}' for new requests? In-flight calls will finish.`)) return;
    try {
      const configs = await (await fetch("/api/mcp/config")).json();
      await saveMcp(configs.filter(f=>f.name!==button.dataset.mcpDelete));
    } catch (error) { $("#mcp-form-status").textContent = String(error); }
  });
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
    const name = b.dataset.oauthDisconnect;
    cancelMcpOAuth(name);
    const response = await fetch(`/api/mcp/${encodeURIComponent(name)}/oauth`,{method:"DELETE"});
    if (!response.ok) { $("#mcp-form-status").textContent = await response.text(); return; }
    renderSettings();
  });
  document.querySelectorAll("[data-oauth]").forEach(b=>b.onclick=async()=>{
    const name = b.dataset.oauth, forward = mcp.forwards.find(f=>f.name===name);
    const scope = prompt("OAuth scopes (space-separated). For Linear, 'read' is read-only; use 'read write' only if needed. Empty uses the server default. This does not expand Friendzone tool or guest permissions.", forward?.scope || (forward?.url.startsWith("https://mcp.linear.app/")?"read":""));
    if (scope === null) return;
    if (forward?.auth === "cline-link" && !confirm("Switch this forward to Friendzone-owned OAuth? Its current Cline credential link will stop being used. Cline's files and tokens stay untouched; tools and guest permissions are preserved.")) return;
    await startMcpOAuth(name, scope);
  });
}

function cancelMcpOAuth(name) {
  const poll = mcpOAuthPolls.get(name);
  if (poll) clearTimeout(poll.timer);
  mcpOAuthPolls.delete(name);
}

function fitMcpEndpoints() {
  for (const input of document.querySelectorAll("[data-mcp-endpoint]")) {
    input.style.height = "auto";
    input.style.height = `${input.scrollHeight + 2}px`;
  }
}
window.addEventListener("resize", fitMcpEndpoints);

function mcpOAuthStatus(message) {
  $("#mcp-oauth-status").textContent = message;
  $("#mcp-form-status").textContent = message;
}

async function startMcpOAuth(name, scope) {
  if (activeMcpOAuth && activeMcpOAuth !== name) cancelMcpOAuth(activeMcpOAuth);
  activeMcpOAuth = name;
  cancelMcpOAuth(name);
  const attempt = {timer:null}; mcpOAuthPolls.set(name, attempt);
  const current = () => mcpOAuthPolls.get(name) === attempt;
  $("#mcp-oauth-panel").hidden = false;
  $("#mcp-oauth-panel").scrollIntoView({behavior:"smooth",block:"center"});
  $("#mcp-oauth-url").value = ""; $("#mcp-oauth-redirect").value = "";
  $("#mcp-oauth-link").hidden = true; $("#mcp-copy-oauth").disabled = true;
  $("#mcp-oauth-next").hidden = true;
  mcpOAuthStatus(`Starting host sign-in for '${name}'…`);
  try {
    const response = await fetch(`/api/mcp/${encodeURIComponent(name)}/oauth/start`, {method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({scope})});
    if (!response.ok) throw new Error(await response.text());
    const {authorize_url, browser_opened} = await response.json();
    if (!current()) return;
    const link = $("#mcp-oauth-link"); link.href = authorize_url; link.hidden = false;
    $("#mcp-oauth-url").value = authorize_url;
    $("#mcp-oauth-redirect").value = new URL(authorize_url).searchParams.get("redirect_uri") || "";
    $("#mcp-copy-oauth").disabled = false;
    mcpOAuthStatus(browser_opened === false ? "The browser could not be opened. Use Open sign-in page or Copy sign-in URL below." : "Complete sign-in in the host browser. If it opened a broken page, open or copy the FULL sign-in URL below.");
    const poll = async () => {
      try {
        const response = await fetch(`/api/mcp/${encodeURIComponent(name)}/oauth/status`);
        if (!response.ok) throw new Error(await response.text());
        const status = await response.json();
        if (!current()) return;
        if (!status || status.state === "failed") {
          mcpOAuthPolls.delete(name); link.hidden = true;
          mcpOAuthStatus(status?.message || "Authorization was cancelled or the forward changed. Start again.");
          $("#mcp-copy-oauth").disabled = true;
          await renderSettings(); return;
        }
        if (status.state === "connected") {
          mcpOAuthPolls.delete(name); link.hidden = true;
          $("#mcp-copy-oauth").disabled = true;
          $("#mcp-oauth-next").hidden = false;
          $("#mcp-oauth-next").onclick = () => reviewMcpAccess(name);
          mcpOAuthStatus(`Signed in to '${name}'. Friendzone now refreshes its OAuth tokens. Next: choose the tools and guests you want to allow. Existing permissions are unchanged.`);
          await renderSettings(); return;
        }
        attempt.timer = setTimeout(poll, 1500);
      } catch (error) { if (current()) { cancelMcpOAuth(name); mcpOAuthStatus(String(error)); } }
    };
    attempt.timer = setTimeout(poll, 1500);
    await renderSettings();
  } catch (error) { if (current()) { cancelMcpOAuth(name); mcpOAuthStatus(`Sign-in could not start: ${error}. The server is saved; retry Authorize in Friendzone on its card.`); } }
}

$("#mcp-copy-oauth").onclick = () => {
  const input = $("#mcp-oauth-url"), value = input.value;
  return copyMcpText(input, $("#mcp-oauth-status"), "Full sign-in URL copied. Paste it into the host browser address bar, not a terminal.", () => input.value === value);
};

async function reviewMcpAccess(name) {
  try {
    const configs = await (await fetch("/api/mcp/config")).json();
    const config = configs.find(f=>f.name===name);
    if (!config) throw new Error("Forward no longer exists");
    reviewingMcp = config;
    clineLink = config.cline || null; validatedMcp = null;
    $("#mcp-name").value = config.name; $("#mcp-url").value = config.url;
    $("#mcp-bearer").value = config.bearer_env || ""; $("#mcp-owned-oauth").checked = !!config.oauth;
    $("#mcp-scope").value = config.scope || "";
    $("#mcp-guests").value = config.guests?.join(", ") || "";
    $("#mcp-source").textContent = `Editing access for '${config.name}'. Nothing changes until you click Save guest access.`;
    $("#mcp-access").scrollIntoView({behavior:"smooth",block:"start"});
    await $("#mcp-validate").onclick();
    for (const checkbox of document.querySelectorAll("#mcp-tools input")) checkbox.checked = config.tools.includes(checkbox.value);
  } catch (error) { $("#mcp-form-status").textContent = String(error); }
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

function fillMcpConnectSelect(selector, options, prompt) {
  const select = $(selector), selected = select.value;
  select.innerHTML = `<option value="">${esc(prompt)}</option>` + options.map(o=>`<option value="${esc(o.value)}">${esc(o.label)}</option>`).join("");
  select.value = options.some(o=>o.value===selected) ? selected : options.length===1 ? options[0].value : "";
}

function updateMcpConnectionGuests() {
  // SSE updates activity frequently; only policy/identity changes need to
  // regenerate instructions. Preserve the user's guest/host selections.
  const guests = snapshot.containers.map(g=>({id:g.id, name:g.name, approved:g.approved, state:g.state, pinned_ip:g.pinned_ip})).sort((a,b)=>a.id.localeCompare(b.id));
  const signature = JSON.stringify(guests);
  if (signature === mcpGuestSignature) return;
  mcpGuestSignature = signature;
  fillMcpConnectSelect("#mcp-connect-guest", guests.map(g=>({value:g.id,label:`${g.name}${!g.approved?" (awaiting approval)":g.state==="killed"?" (killed)":""}`})), "Select a guest");
  if (mcpConnectData) loadMcpConnection();
}

async function loadMcpConnection() {
  const generation = ++mcpConnectGeneration;
  for (const id of ["url", "auth", "json"]) $("#mcp-connect-"+id).value = "";
  for (const id of ["url", "auth", "json"]) $("#mcp-copy-"+id).disabled = true;
  $("#mcp-connect-warning").textContent = "";
  const name = $("#mcp-connect-forward").value, guest = $("#mcp-connect-guest").value, host = $("#mcp-connect-host").value.trim();
  if (!name || !guest || !host) {
    $("#mcp-connect-status").textContent = !name ? "Select or add a forward to see its Cline configuration." : !guest ? "Select a guest. If none appear, run fz setup in the guest or add it in the Inbox." : "Enter the broker host address reachable from this guest.";
    return;
  }
  $("#mcp-connect-status").textContent = "Generating guest connection instructions…";
  try {
    const query = new URLSearchParams({guest, host});
    const response = await fetch(`/api/mcp/${encodeURIComponent(name)}/guest-config?${query}`);
    if (!response.ok) throw new Error(await response.text());
    const result = await response.json();
    if (generation !== mcpConnectGeneration) return;
    $("#mcp-connect-url").value = result.endpoint;
    $("#mcp-connect-auth").value = result.authorization;
    $("#mcp-connect-json").value = JSON.stringify(result.cline_config, null, 2);
    const forward = mcpConnectData?.forwards.find(f=>f.name===name);
    const warnings = [...result.warnings];
    if (forward && !forward.tools.length) warnings.push("No tools are allowed yet. Select tools for this forward and apply.");
    if (forward?.auth === "oauth-required") warnings.push("Upstream OAuth is not connected. Use Authorize in Friendzone on the host, not in guest Cline.");
    $("#mcp-connect-warning").textContent = warnings.join("\n");
    $("#mcp-connect-status").textContent = `Configuration for '${name}' as '${guest}'. This is not a connectivity test.`;
    for (const id of ["url", "auth", "json"]) $("#mcp-copy-"+id).disabled = false;
  } catch (error) {
    if (generation === mcpConnectGeneration) $("#mcp-connect-status").textContent = String(error);
  }
}

for (const id of ["forward", "guest"]) $("#mcp-connect-"+id).addEventListener("change", loadMcpConnection);
$("#mcp-connect-host").addEventListener("input", () => {mcpHostInitialized=true;loadMcpConnection();});
for (const id of ["url", "auth", "json"]) $("#mcp-copy-"+id).onclick = async () => {
  const input = $("#mcp-connect-"+id), generation = mcpConnectGeneration;
  await copyMcpText(input, $("#mcp-connect-status"), "Copied. Paste into guest Cline, not the host's upstream server settings.", () => generation === mcpConnectGeneration);
};

async function copyMcpText(input, status, successMessage, isCurrent) {
  if (!input.value) return;
  try {
    await navigator.clipboard.writeText(input.value);
    if (isCurrent()) status.textContent = successMessage;
  } catch {
    if (!isCurrent()) return;
    input.focus(); input.select();
    status.textContent = "Clipboard access unavailable. Text selected; press Ctrl+C / Cmd+C to copy.";
  }
}

let clineLink = null, validatedMcp = null;
function mcpDraft() {
  return {name:$("#mcp-name").value.trim(), url:$("#mcp-url").value.trim(), bearer_env:$("#mcp-bearer").value.trim(), scope:null, tools:[], guests:[], cline:clineLink, oauth:$("#mcp-owned-oauth").checked};
}
async function saveMcp(configs) {
  const response = await fetch("/api/mcp/config", {method:"PUT", headers:{"content-type":"application/json"}, body:JSON.stringify(configs)});
  if (!response.ok) throw new Error(await response.text());
  $("#mcp-editor").value = JSON.stringify(configs, null, 2);
  await renderSettings();
}
$("#mcp-clear-link").onclick = () => {
  reviewingMcp = null;
  clineLink = null; validatedMcp = null; $("#mcp-tools").innerHTML = "";
  $("#mcp-owned-oauth").checked = false;
  $("#mcp-source").textContent = "Standalone server (no Cline link).";
};
$("#mcp-preview").onclick = async () => {
  const path = $("#mcp-cline-path").value.trim();
  try {
    const response = await fetch("/api/mcp/import/cline", {method:"POST", headers:{"content-type":"application/json"}, body:JSON.stringify({path})});
    if (!response.ok) throw new Error(await response.text());
    const candidates = await response.json();
    $("#mcp-candidates").innerHTML = "";
    for (const candidate of candidates) {
      const row = document.createElement("p");
      row.textContent = `${candidate.server}: ${candidate.reason} `;
      if (candidate.supported) {
        const select = document.createElement("button"); select.textContent = "Select";
        select.onclick = () => {
          reviewingMcp = null;
          clineLink = {path, server:candidate.server}; validatedMcp = null;
          $("#mcp-owned-oauth").checked = true;
          $("#mcp-name").value = candidate.server.replace(/[^a-zA-Z0-9_-]/g, "-");
          $("#mcp-url").value = candidate.url; $("#mcp-bearer").value = ""; $("#mcp-tools").innerHTML = "";
          $("#mcp-scope").value = candidate.url.startsWith("https://mcp.linear.app/") ? "read" : "";
          $("#mcp-source").textContent = `Imported ${candidate.server} from ${path}. Click Add & authorize to sign in, then choose guest access. Uncheck broker OAuth only to use Cline's credential link.`;
        };
        row.append(select);
      }
      $("#mcp-candidates").append(row);
    }
  } catch (error) { $("#mcp-form-status").textContent = String(error); }
};
$("#mcp-validate").onclick = async () => {
  validatedMcp = null; $("#mcp-tools").innerHTML = "";
  $("#mcp-form-status").textContent = "Connecting and listing tools (no tools called)…";
  try {
    const draft = mcpDraft();
    const response = await fetch("/api/mcp/validate", {method:"POST", headers:{"content-type":"application/json"}, body:JSON.stringify(draft)});
    if (!response.ok) throw new Error(await response.text());
    const result = await response.json();
    if (JSON.stringify(draft) !== JSON.stringify(mcpDraft())) throw new Error("Configuration changed; validate again.");
    validatedMcp = JSON.stringify(draft);
    for (const name of result.tools) {
      const label = document.createElement("label"), checkbox = document.createElement("input");
      checkbox.type = "checkbox"; checkbox.value = name;
      label.append(checkbox, document.createTextNode(name)); $("#mcp-tools").append(label, document.createElement("br"));
    }
    $("#mcp-form-status").textContent = `Tools loaded. Choose tools and guests below, then Save guest access.${result.more?" Server has more pages; use the advanced editor for additional known tool names.":""}`;
  } catch (error) { $("#mcp-form-status").textContent = String(error); }
};
$("#mcp-save-oauth").onclick = async () => {
  const button = $("#mcp-save-oauth"); button.disabled = true;
  try {
    const draft = mcpDraft(); draft.oauth = true; draft.bearer_env = "";
    if (!draft.name || !draft.url) throw new Error("Select an imported server or enter a server name and upstream URL first.");
    const scope = $("#mcp-scope").value.trim();
    draft.scope = scope || null;
    const configs = await (await fetch("/api/mcp/config")).json();
    if (configs.some(f=>f.name===draft.name)) throw new Error("Forward already exists. Use Authorize in Friendzone on its row.");
    await saveMcp([...configs, draft]);
    $("#mcp-owned-oauth").checked = true;
    reviewingMcp = draft;
    await startMcpOAuth(draft.name, scope);
  } catch (error) { $("#mcp-form-status").textContent = String(error); }
  finally { button.disabled = false; }
};
$("#mcp-add").onclick = async () => {
  try {
    const draft = mcpDraft();
    if (validatedMcp !== JSON.stringify(draft)) throw new Error("Validate this configuration before adding it.");
    draft.tools = [...document.querySelectorAll("#mcp-tools input:checked")].map(input=>input.value);
    draft.guests = $("#mcp-guests").value.split(",").map(s=>s.trim()).filter(Boolean);
    const configs = await (await fetch("/api/mcp/config")).json();
    const existing = configs.find(f=>f.name===draft.name);
    if (existing && !(reviewingMcp?.name === existing.name && existing.url === draft.url && !!existing.oauth === draft.oauth)) throw new Error("That name already exists or changed. Use Review tools / guests on its row before updating permissions.");
    if (existing) {
      if (!confirm("Apply these selected tool and guest permissions to the existing forward?")) return;
      await saveMcp(configs.map(f=>f.name===draft.name?{...f,tools:draft.tools,guests:draft.guests}:f));
    } else await saveMcp([...configs, draft]);
    validatedMcp = null;
    $("#mcp-form-status").textContent = "Guest access saved. Use Copy Cline setup on the server card to connect the guest.";
  } catch (error) { $("#mcp-form-status").textContent = String(error); }
};

$("#add-container").onsubmit = async (e) => {
  e.preventDefault();
  if (await changeContainerPolicy("/api/containers",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({name:$("#new-container-name").value})})) e.target.reset();
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

function selectView(view) {
  const selected = ["inbox", "log", "settings"].includes(view) ? view : "inbox";
  document.querySelectorAll(".nav").forEach(button=>{
    const active = button.dataset.view === selected;
    button.classList.toggle("active", active);
    if (active) button.setAttribute("aria-current", "page"); else button.removeAttribute("aria-current");
  });
  document.querySelectorAll(".view").forEach(section=>section.classList.toggle("active", section.id === `${selected}-view`));
  storeValue("fz-active-view", selected);
  if (selected === "settings") renderSettings().catch(console.error);
  if (selected === "log") loadLog();
}
document.querySelectorAll(".nav").forEach(button=>button.onclick=()=>selectView(button.dataset.view));
$("#refresh").onclick=refresh; ["#search","#container-filter","#verdict-filter"].forEach(s=>$(s).addEventListener("input",()=>{logPaused=false;loadLog();}));

// Live updates over SSE: the broker pushes a full snapshot on every
// change; EventSource reconnects on its own. The initial fetch covers
// the gap before the stream opens.
refresh();
const events = new EventSource("/api/events");
events.onmessage = (e) => { snapshot = JSON.parse(e.data); renderContainers(); scheduleLog(); };
events.onerror = () => setTimeout(refresh, 3000); // bridge reconnect gaps
selectView(readStoredValue("fz-active-view"));
