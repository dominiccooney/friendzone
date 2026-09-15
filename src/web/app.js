const $ = (s) => document.querySelector(s);
let snapshot = { containers: [], requests: [], pending_requests: [] };
let snapshotRevision = 0;
let logRows = [], logCursor = null, logPaused = false, logGeneration = 0, logTimer;
let order = readStoredOrder();
let mcpConnectData = null, mcpHostInitialized = false, mcpConnectGeneration = 0, mcpGuestSignature = "";
const mcpOAuthPolls = new Map();
let reviewingMcp = null;
let activeMcpOAuth = null;
let setupInitialized = false, setupGeneration = 0;
let connectedMcpName = null;
let activeReview = null, reviewGeneration = 0, pendingSignature = "", decisionInFlight = null;
let commentPermissionGeneration = 0, commentPermissionSignature = "";
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
function showContainerError(error, target = "#container-error") {
  if (target === "#join-error") $("#guest-joins").hidden = false;
  $(target).textContent = error.policyUnchanged
    ? `Change not applied: ${error.message}. Existing policy remains in effect.`
    : `Could not confirm the change: ${error.message || error}. Refresh to check the actual policy; do not assume Kill or approval succeeded.`;
}
async function changeContainerPolicy(url, options, errorTarget = "#container-error") {
  $(errorTarget).textContent = "";
  try {
    const response = await fetch(url, options);
    if (!response.ok) throw rejectedContainerChange(await response.text());
    await refresh();
    return true;
  } catch (error) { showContainerError(error, errorTarget); return false; }
}

function guestJoinRequests() { return snapshot.containers.filter(c=>!c.approved && c.state!=="killed"); }

function renderContainers() {
  renderPendingRequests();
  updateMcpConnectionGuests();
  renderGuestRegistry();
}

// A guest has one card: actionable joins in Inbox, managed guests in Settings.
// Both use the same policy handlers; moving a card never changes its permissions.
function renderGuestRegistry() {
  const joins = guestJoinRequests();
  const joining = $("#joining-guests"); joining.innerHTML = "";
  const root = $("#containers"); root.innerHTML = "";
  $("#join-count").textContent = joins.length;
  $("#guest-joins").hidden = !joins.length && !$("#join-error").textContent;
  $("#review-guest-joins").hidden = !joins.length;
  $("#review-guest-joins").textContent = `Review ${joins.length} join request${joins.length===1?"":"s"} in Inbox`;
  if (snapshot.containers.length === joins.length) root.append($("#empty-template").content.cloneNode(true));
  for (const c of ordered(snapshot.containers)) {
    const killed = c.state === "killed";
    const pending = !killed && !c.approved;
    const section = document.createElement("section");
    section.className = "container"; section.draggable = !pending; section.dataset.id = c.id;
    const errorTarget = pending ? "#join-error" : "#container-error";
    const pin = c.pinned_ip ? (c.pinned_ip.startsWith("~") ? `last seen ${esc(c.pinned_ip.slice(1))}, not pinned` : `pinned to ${esc(c.pinned_ip)}`) : "any address";
    const actions = pending
      ? `<span class="state killed">awaiting approval</span><button class="approve-pin">Approve + pin IP</button><button class="quiet approve">Approve without pin (legacy)</button><button class="quiet remove">Deny</button>`
      : `<span class="state ${killed?"killed":"approved"}" title="Network authorization, not agent activity">${containerStatus(c)}</span><button class="stop ${killed?"resume":""}">${killed?"Resume":"Kill"}</button><button class="quiet pin-edit">Pin…</button><button class="quiet remove">Remove</button>`;
    section.innerHTML = `<div class="container-head"><span class="status-dot" style="background:${killed?"var(--red)":"#999"}" title="${esc(containerStatus(c))}; agent activity is not monitored"></span><div><div class="container-name">${esc(c.name)}</div><div class="meta">${c.request_count} retained requests · ${esc(containerTraffic(c))} · ${pin}</div></div><div class="actions">${actions}</div></div>${pending?'<div class="container-body">Join request · Approve + pin IP for credential-free access.</div>':""}`;
    section.querySelector(".stop")?.addEventListener("click", () => {$("#container-error").textContent="";return setKilled(c.id, !killed).catch(showContainerError);});
    section.querySelector(".approve")?.addEventListener("click", async () => {
      await changeContainerPolicy(`/api/containers/${encodeURIComponent(c.id)}/approve`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({pin_to_last_ip:false})}, errorTarget);
    });
    section.querySelector(".approve-pin")?.addEventListener("click", async () => {
      await changeContainerPolicy(`/api/containers/${encodeURIComponent(c.id)}/approve`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({pin_to_last_ip:true})}, errorTarget);
    });
    section.querySelector(".pin-edit")?.addEventListener("click", async () => {
      const current = c.pinned_ip && !c.pinned_ip.startsWith("~") ? c.pinned_ip : "";
      const ip = prompt(`Pin '${c.name}' to an IP (empty = any address):`, current);
      if (ip === null) return;
      await changeContainerPolicy(`/api/containers/${encodeURIComponent(c.id)}/pin`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({ip:ip||null})});
    });
    section.querySelector(".remove").onclick = async () => {
      if (!confirm(pending ? `Dismiss join request from '${c.name}'? It remains unapproved and may ask again.` : `Remove guest '${c.name}'? Kill it first if it is still running.`)) return;
      await changeContainerPolicy(`/api/containers/${encodeURIComponent(c.id)}`, {method:"DELETE"}, errorTarget);
    };
    section.addEventListener("dragstart", () => section.classList.add("dragging"));
    section.addEventListener("dragend", () => { section.classList.remove("dragging"); order=[...root.querySelectorAll(".container")].map(n=>n.dataset.id);storeValue("fz-order",JSON.stringify(order)); });
    (pending ? joining : root).append(section);
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
  $("#notification-status").textContent = !supported ? "Notifications unavailable in this browser/context."
    : Notification.permission === "denied" ? "Notifications blocked in browser site settings."
    : notificationsEnabled && Notification.permission === "granted" ? "Notifications on while this page is open."
    : "Notifications off.";
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
  for (const request of pending) if ((request.status || "pending") === "pending" && !notifiedIds.has(request.id)) newNotificationIds.add(request.id);
  if (!newNotificationIds.size || notificationTimer) return;
  notificationTimer = setTimeout(() => {
    notificationTimer = null;
    const live = new Set((snapshot.pending_requests || []).filter(request=>(request.status || "pending") === "pending").map(request=>request.id));
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
  renderCommentPermissions();
  const pending = snapshot.pending_requests || [];
  $("#inbox-count").textContent = pending.length + guestJoinRequests().length;
  const recent = snapshot.recent_reviews || [];
  $("#pending-count").textContent = pending.length;
  $("#pending-section").hidden = pending.length === 0;
  $("#attention-empty").hidden = pending.length !== 0 || guestJoinRequests().length !== 0;
  $("#recent-count").textContent = recent.length;
  const signature = JSON.stringify([pending, recent]);
  if (signature !== pendingSignature) {
    pendingSignature = signature;
    $("#pending-requests").innerHTML = reviewTable(pending, "No pending requests.");
    $("#recent-reviews").innerHTML = reviewTable(recent, "No recent reviews.");
    document.querySelectorAll("[data-review]").forEach(button=>button.onclick=()=>openRequestReview(button.dataset.review));
  }
  if (activeReview) {
    const current = [...pending, ...recent].find(request=>request.id===activeReview.id);
    if (current && (current.updated_at || "") >= (activeReview.updated_at || "")) applyReviewOutcome(current);
    else if (!current) applyReviewOutcome({status:"unavailable", outcome:"Not retained: broker restarted or history limit reached."});
  }
  updateNotificationStatus(); notifyPendingRequests(pending);
}

const REVIEW_STATUSES = {
  preparing:["Preparing review","sending"],
  pending:["Pending","pending"], approved:["Approved","sending"], sending:["Sending","sending"],
  response_received:["Response received","response"], denied:["Denied","blocked"], expired:["Expired","muted"],
  graphql_error:["GraphQL error","blocked"],
  cancelled:["Cancelled","muted"], blocked:["Blocked","blocked"], upstream_error:["Upstream error","blocked"],
  unknown:["No response received","blocked"], unavailable:["Not retained","muted"],
};
function reviewStatus(request) {
  const [label, color] = REVIEW_STATUSES[request.status || "pending"] || REVIEW_STATUSES.unavailable;
  const observed = request.status === "unknown" && request.http_status ? `Response incomplete · HTTP ${request.http_status}`
    : request.http_status>=400 ? `HTTP ${request.http_status}` : label + (request.http_status ? ` · HTTP ${request.http_status}` : "");
  return {label:observed, color:request.http_status>=400?"blocked":color};
}
function reviewOutcomeText(request) {
  // Explain the evidence, including older brokers' retained `unknown` records.
  // Receiving HTTP headers is not the same as observing a complete response.
  if (request.status === "unknown") return request.http_status
    ? "The server replied, but Friendzone did not observe the complete response. This does not mean the operation failed."
    : "Friendzone did not receive a reply after approval. The operation may have completed.";
  if(request.http_status>=400 && request.status!=="unknown")return request.outcome && !/^Response received\.?$/.test(request.outcome)
    ? request.outcome : `Upstream returned HTTP ${request.http_status}. Inspect the result before retrying.`;
  return request.outcome || "";
}
function upstreamDiagnostics(request) {
  const upstream=request.upstream;
  if(!upstream)return "";
  const lines=[];
  if(Number.isFinite(upstream.accepted_to_approval_ms))lines.push(`Accepted → approval: ${upstream.accepted_to_approval_ms} ms`);
  if(Number.isFinite(upstream.approval_to_admission_ms))lines.push(`Approval → admission: ${upstream.approval_to_admission_ms} ms`);
  else if(Number.isFinite(upstream.accepted_to_admission_ms))lines.push(`Accepted → admission: ${upstream.accepted_to_admission_ms} ms`);
  if(Number.isFinite(upstream.time_to_headers_ms))lines.push(`Admission → response headers: ${upstream.time_to_headers_ms} ms`);
  if(Number.isFinite(upstream.total_ms))lines.push(`Admission → completion: ${upstream.total_ms} ms`);
  if(upstream.remote_addr)lines.push(`Connected peer: ${upstream.remote_addr}`);
  if(upstream.http_version)lines.push(`HTTP version: ${upstream.http_version}`);
  if(Number.isFinite(upstream.response_bytes))lines.push(`Observed response body: ${upstream.response_bytes} bytes${upstream.response_complete===false?' (incomplete)':''}`);
  if(upstream.transport_error)lines.push(`Transport result: ${upstream.transport_error}`);
  for(const pair of upstream.response_headers || [])if(Array.isArray(pair)&&pair.length===2)lines.push(`${pair[0]}: ${pair[1]}`);
  return lines.join("\n");
}
function reviewTable(requests, empty) {
  if(!requests.length)return `<p>${esc(empty)}</p>`;
  return `<div class="review-table-scroll"><table class="review-table"><thead><tr><th scope="col">Operation</th><th scope="col">Repository / target</th><th scope="col">Guest</th><th scope="col">Status</th><th scope="col">Time</th><th scope="col"><span class="sr-only">Action</span></th></tr></thead><tbody>${requests.map(reviewRow).join("")}</tbody></table></div>`;
}
function reviewTarget(facts) {
  const repositories=Array.isArray(facts?.repositories)?facts.repositories:[];
  const targets=Array.isArray(facts?.targets)?facts.targets:[];
  const text=[...repositories,...targets].join(" · ");
  const parseRepository=value=>typeof value==="string"?/^([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))\/([A-Za-z0-9._-]{1,100})$/.exec(value):null;
  const link=(url,label)=>`<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(label)}</a>`;
  const repositoryUrl=value=>{const match=parseRepository(value);return match?`https://github.com/${encodeURIComponent(match[1])}/${encodeURIComponent(match[2])}`:null;};
  const parts=repositories.map(repository=>{const url=repositoryUrl(repository);return url?link(url,repository):esc(repository);});
  const artifacts=Array.isArray(facts?.artifacts)?facts.artifacts:[];
  const represented=new Set();
  for(const artifact of artifacts){
    const number=String(artifact?.number??"");
    const repository=artifact?.repository;
    const base=repositoryUrl(repository);
    if(!base||!/^([1-9][0-9]*)$/.test(number)||!["issue","pull_request","issue_or_pull_request"].includes(artifact?.kind))continue;
    const segment=artifact.kind==="pull_request"?"pull":"issues";
    parts.push(link(`${base}/${segment}/${number}`,`#${number}`));
    represented.add(`${repository}\u0000${number}`);
  }
  for(const target of targets){
    const numbered=typeof target==="string"?/^#([1-9][0-9]*)$/.exec(target):null;
    const matching=numbered?artifacts.filter(artifact=>String(artifact?.number)===numbered[1]&&represented.has(`${artifact?.repository}\u0000${numbered[1]}`)):[];
    if(matching.length)continue;
    if(numbered&&repositories.length===1&&artifacts.length===0){
      const base=repositoryUrl(repositories[0]);
      if(base){parts.push(link(`${base}/issues/${numbered[1]}`,target));continue;}
    }
    parts.push(esc(target));
  }
  return {text,markup:parts.join(" · ")||"Not identified"};
}
function reviewRow(request) {
  const status = reviewStatus(request), pending = !request.status || request.status === "pending";
  const outcome = reviewOutcomeText(request);
  const facts=request.facts;
  const operation=facts?.operation_name || facts?.fields?.join(", ") || `${request.method} ${request.url}`;
  const target=reviewTarget(facts);
  const description=[facts?.operation_type,...(facts?.fields || []),facts?.more?"More operations/targets in details":"",request.url].filter(Boolean).join(" · ");
  return `<tr class="review-row"><td class="review-operation" data-label="Operation" title="${esc(description)}">${esc(operation)}</td><td class="review-target" data-label="Target" title="${esc(target.text || 'Repository not identified; inspect request details')}">${target.markup}${facts?.more?" …":""}</td><td class="review-guest" data-label="Guest">${esc(request.container)}</td><td class="review-state" data-label="Status"><span class="request-badge ${status.color}" title="${esc(outcome)}">${esc(status.label)}</span></td><td class="review-time" data-label="Time" title="${pending?'Approval deadline':'Last update'}">${pending?'by ':''}${esc(displayTime(pending?request.expires_at:request.updated_at || request.created_at))}</td><td class="review-action"><button type="button" data-review="${esc(request.id)}">${pending?"Review":"Details"}</button></td></tr>`;
}
function applyReviewOutcome(summary) {
  if (!activeReview) return;
  const oldStatus = activeReview.status || "pending";
  if(oldStatus==="preparing" && summary.status==="pending"){
    const id=activeReview.id;void openRequestReview(id);return;
  }
  // An older fetch must not reopen a one-shot decision acknowledged locally.
  if (oldStatus !== "pending" && oldStatus !== "preparing" && (summary.status || "pending") === "pending") return;
  Object.assign(activeReview, summary);
  const waiting = (activeReview.status || "pending") === "pending";
  if (oldStatus === "pending" && !waiting) { ++commentPermissionGeneration; renderCommentPermissionPanel(null); }
  const status = reviewStatus(activeReview);
  $("#request-review-badge").textContent = status.label;
  $("#request-review-badge").className = `request-badge ${status.color}`;
  $("#request-review-outcome").textContent = reviewOutcomeText(activeReview) || (waiting ? "Waiting for your decision." : "");
  $("#request-review-upstream").textContent = upstreamDiagnostics(activeReview);
  $("#request-review-actions").hidden = !waiting;
  $("#request-approve").disabled = !waiting || decisionInFlight === activeReview.id;
  $("#request-deny").disabled = !waiting || decisionInFlight === activeReview.id;
  updateReviewTiming();
}

let reviewClock = null;
function reviewTiming(request, now = Date.now()) {
  const created = Date.parse(request.created_at), expires = Date.parse(request.expires_at);
  if (request.asynchronous) {
    if(request.status==="preparing")return "Async Git job · validating the bundle and deriving a review. No publication is approvable yet.";
    if ((request.status || "pending") === "pending") return `Async job · review by ${new Date(request.expires_at).toLocaleString()}. Client does not need to wait.`;
    const upstream=request.upstream;
    if(upstream?.started_at){
      const approved=Number.isFinite(upstream.accepted_to_approval_ms)?`${upstream.accepted_to_approval_ms} ms to approval`:"approved";
      const admitted=Number.isFinite(upstream.approval_to_admission_ms)?`${upstream.approval_to_admission_ms} ms approval to admission`:"admitted";
      const transfer=Number.isFinite(upstream.total_ms)?`${upstream.total_ms} ms in upstream transport`:"upstream transport finished";
      return `Async job · ${approved} · ${admitted} · ${transfer}. Result available to the submitting Cline session.`;
    }
    return "Async job · result available to the submitting Cline session.";
  }
  if ((request.status || "pending") === "pending") {
    if (!Number.isFinite(expires)) return "Client may stop waiting before the broker deadline.";
    const remaining = Math.max(0, Math.ceil((expires - now) / 1000));
    const elapsed = Number.isFinite(created) ? `Waiting ${Math.max(0, Math.floor((now-created)/1000))}s · ` : "";
    return `${elapsed}${remaining}s until broker expiry. Client timeout may be shorter.`;
  }
  const elapsed = Math.round((Date.parse(request.updated_at) - created) / 1000);
  if (!Number.isFinite(elapsed) || elapsed < 0) return "";
  return `${elapsed}s after arrival${request.status === "cancelled" ? " · cancelled before forwarding; client timeout or cancellation is possible" : ""}.`;
}
function updateReviewTiming() {
  clearTimeout(reviewClock); reviewClock = null;
  $("#request-review-timing").textContent = activeReview ? reviewTiming(activeReview) : "";
  if (activeReview && (activeReview.status || "pending") === "pending") reviewClock = setTimeout(updateReviewTiming, 1000);
}

async function openRequestReview(id) {
  const generation = ++reviewGeneration; activeReview = null;
  ++commentPermissionGeneration; renderCommentPermissionPanel(null);
  $("#request-review").hidden = true; $("#request-approve").disabled = true; $("#request-deny").disabled = true;
  $("#request-review-status").textContent = "Loading exact request…";
  try {
    const response = await fetch(`/api/requests/${encodeURIComponent(id)}`, {cache:"no-store"});
    if (!response.ok) throw new Error(await response.text());
    const detail = {...await response.json()};
    if (generation !== reviewGeneration) return;
    activeReview = detail;
    // A detail fetch may finish after a newer SSE decision/response update.
    const current = [...(snapshot.pending_requests || []), ...(snapshot.recent_reviews || [])].find(request=>request.id===id);
    if (current && (current.updated_at || "") >= (detail.updated_at || "")) Object.assign(detail, current);
    $("#request-review-title").textContent = `${detail.container} · ${detail.method}`;
    $("#request-review-url").textContent = detail.url;
    $("#request-review-reason").textContent = detail.reason;
    $("#request-review-meta").textContent = `${detail.request_key?`Correlation: ${detail.request_key} · `:""}${detail.body_bytes} bytes · SHA-256 ${detail.fingerprint}`;
    $("#request-review-headers").textContent = detail.headers.map(([name,value])=>`${name}: ${value}`).join("\n");
    $("#request-review-body").textContent = detail.body || "(empty body)";
    renderGraphqlReview(detail.graphql);
    renderGitPushReview(detail.git_push);
    $("#request-raw-summary").textContent=detail.git_push?"Publication identity":"Exact request body";
    $("#request-raw").open = !detail.git_push && detail.graphql?.status !== "parsed";
    renderCommentPermissionPanel(detail);
    $("#request-review").hidden = false;
    applyReviewOutcome(detail);
    $("#request-review-status").textContent = "";
    $("#request-review").scrollIntoView({behavior:"smooth",block:"start"});
  } catch (error) { if (generation === reviewGeneration) $("#request-review-status").textContent = String(error); }
}

function renderCommentPermissionPanel(detail) {
  $("#comment-permission-panel").hidden = !detail?.comment_permission_supported || (detail.status && detail.status !== "pending");
  $("#resolve-comment-target").disabled = !detail?.comment_permission_supported;
  $("#save-comment-permission").disabled = !detail?.resolution_id || !detail?.resolved_target;
  $("#comment-permission-status").textContent = "";
  const resolved = detail?.resolved_target;
  $("#resolved-comment-target").textContent = resolved
    ? `Verified with GitHub credential '${resolved.credential}':\n${resolved.target.kind}: ${resolved.target.repository} #${resolved.target.number}\n${resolved.target.title}\n${resolved.target.url}\nNode ID: ${resolved.target.node_id}\nRepository ID: ${resolved.target.repository_id}` : "";
}

$("#resolve-comment-target").onclick = async () => {
  if (!activeReview?.comment_permission_supported) return;
  const reviewed = activeReview, generation = ++commentPermissionGeneration;
  $("#resolve-comment-target").disabled = true; $("#save-comment-permission").disabled = true;
  $("#comment-permission-status").textContent = "Looking up this issue/PR with a fixed GitHub read…";
  try {
    const response = await fetch(`/api/requests/${encodeURIComponent(reviewed.id)}/github-target`,{method:"POST",headers:{"content-type":"application/json","x-friendzone-review":"1"},body:JSON.stringify({fingerprint:reviewed.fingerprint})});
    if (!response.ok) throw new Error(await response.text());
    const detail = await response.json();
    if (generation !== commentPermissionGeneration || activeReview?.id !== reviewed.id) return;
    activeReview = {...detail}; renderCommentPermissionPanel(activeReview);
    $("#comment-permission-status").textContent = "Inspect the repository, number and title above. Resolving has not granted anything.";
  } catch (error) {
    if (generation !== commentPermissionGeneration) return;
    $("#resolve-comment-target").disabled = false;
    $("#comment-permission-status").textContent = `Target not verified: ${error}. You can still review the raw request manually.`;
  }
};

$("#save-comment-permission").onclick = async () => {
  const reviewed = activeReview;
  if (!reviewed?.resolution_id || !reviewed.resolved_target) return;
  const target = reviewed.resolved_target.target;
  if (!confirm(`Allow ${reviewed.container} to post future comments with arbitrary text on ${target.repository} #${target.number} (${target.kind}) using ${reviewed.resolved_target.credential}? This persists until revoked; it does NOT approve the current request.`)) return;
  const generation = ++commentPermissionGeneration;
  $("#save-comment-permission").disabled = true;
  try {
    const response = await fetch(`/api/requests/${encodeURIComponent(reviewed.id)}/comment-permission`,{method:"POST",headers:{"content-type":"application/json","x-friendzone-review":"1"},body:JSON.stringify({fingerprint:reviewed.fingerprint,resolution_id:reviewed.resolution_id})});
    if (!response.ok) throw new Error(await response.text());
    if (generation === commentPermissionGeneration) $("#comment-permission-status").textContent = "Permission saved for future comments. This request still needs Approve once or Deny below.";
    await refresh();
  } catch (error) { if (generation === commentPermissionGeneration) $("#comment-permission-status").textContent = `Could not confirm the grant: ${error}. Check saved permissions before retrying.`; }
};

function renderCommentPermissions() {
  const permissions = snapshot.comment_permissions || [], signature = JSON.stringify(permissions);
  if (signature === commentPermissionSignature) return;
  commentPermissionSignature = signature;
  $("#comment-permissions").innerHTML = permissions.map(grant=>`<div class="comment-permission"><strong>${esc(grant.container)}</strong> has a saved comment permission for <strong>${esc(grant.target.repository)} #${esc(grant.target.number)}</strong> (${esc(grant.target.kind)})<p>${esc(grant.target.title)}</p><p>${esc(grant.target.url)} · credential: ${esc(grant.credential)}</p><p>${grant.credential_active===false?"Inactive: credential changed or unavailable. Resolve and grant a new request.":"Each request must still pass current credential, target and guest authorization checks."}</p><button data-comment-revoke="${esc(grant.id)}" data-container="${esc(grant.container)}" type="button">Revoke</button></div>`).join("") || "<p>No saved comment permissions.</p>";
  document.querySelectorAll("[data-comment-revoke]").forEach(button=>button.onclick=async()=>{
    button.disabled = true;
    try {
      const response = await fetch(`/api/containers/${encodeURIComponent(button.dataset.container)}/comment-permissions/${encodeURIComponent(button.dataset.commentRevoke)}`,{method:"DELETE",headers:{"x-friendzone-review":"1"}});
      if (!response.ok) throw new Error(await response.text());
      $("#comment-permissions-status").textContent = "Revoked for subsequent admission. Already-sent comments cannot be undone.";
      await refresh();
    } catch (error) { button.disabled=false; $("#comment-permissions-status").textContent=`Could not confirm revocation: ${error}. Refresh to check permissions.`; }
  });
}

// Values come from the broker's typed AST, never reparse GraphQL or use these
// display rows as approval input. Expand every input, including unknown fields.
function graphqlValueRows(value, path, labels = {}, rows = [], largeValues = {}) {
  if (value?.kind === "object" && Object.keys(value.value).length) {
    for (const [name, child] of Object.entries(value.value)) graphqlValueRows(child, path ? `${path}.${name}` : name, labels, rows, largeValues);
  } else if (value?.kind === "list" && value.value.length) {
    value.value.forEach((child,index)=>graphqlValueRows(child, `${path}[${index}]`, labels, rows, largeValues));
  } else {
    const kind = value?.kind || "unknown";
    const text = kind === "reference" ? (Object.hasOwn(largeValues,value.value)?largeValues[value.value]:`Missing value ${value.value}; inspect the raw request`)
      : kind === "null" ? "null" : kind === "object" ? "{}" : kind === "list" ? "[]"
      : kind === "missing_variable" ? `Not supplied ($${value.value})` : kind === "variable" ? `Unresolved $${value.value}`
      : kind === "string" && value.value === "" ? "(empty string)"
      : value?.value === undefined ? JSON.stringify(value) : String(value.value);
    rows.push({path, label:labels[path] || path, kind:kind==="reference"?"string":kind, text});
  }
  return rows;
}
function graphqlValuesMarkup(rows) {
  return `<dl class="graphql-values">${rows.map(row=>`<div class="graphql-value"><dt>${esc(row.label)}${row.label!==row.path?` <code>${esc(row.path)}</code>`:""}<small>${esc(row.kind)}</small></dt><dd><pre>${esc(row.text)}</pre></dd></div>`).join("")}</dl>`;
}
function graphqlFieldMarkup(field, largeValues = {}) {
  const target = field.target, conditions = field.conditions_text || [];
  const inputs = field.mutation_inputs || [];
  const labels = Object.fromEntries(inputs.map(input=>[input.path, input.label]));
  if (field.comment_body !== null && field.comment_body !== undefined) labels["input.body"] = "Comment text";
  const rows = Object.entries(field.arguments || {}).flatMap(([name,value])=>graphqlValueRows(value, name, labels, [], largeValues));
  // Compatibility with older snapshots without typed arguments: never hide the
  // broker's text representation or recognized values just because it is unknown.
  if (!rows.length) {
    for (const input of inputs) rows.push({path:input.path,label:input.label,kind:"value",text:input.value});
    if (field.comment_body !== null && field.comment_body !== undefined) rows.push({path:"input.body",label:"Comment text",kind:"string",text:field.comment_body});
    if (field.arguments_text) rows.push({path:"Arguments",label:"Arguments",kind:"GraphQL",text:field.arguments_text});
  }
  const targetText = !target ? "" : target.kind === "node_id"
    ? `${target.expected_type} node ID (unverified): ${target.id}. Not an issue/PR number.`
    : `${target.owner}/${target.repository} #${target.number} · ${target.expected_type} (not a verified pin).`;
  const context = [field.action ? field.field : "", field.response_name !== field.field ? `alias ${field.response_name}` : "", field.parent===null?"":field.path.join(" → ")].filter(Boolean).join(" · ");
  return `<article class="graphql-field"><h4>${esc(field.action || field.field)}</h4>${context?`<p class="meta">${esc(context)}</p>`:""}${targetText?`<p class="graphql-target">${esc(targetText)}</p>`:""}${conditions.length?`<p class="graphql-conditions">Conditions: ${esc(conditions.join("; "))}</p>`:""}${rows.length?graphqlValuesMarkup(rows):'<p class="meta">No arguments.</p>'}</article>`;
}
function renderGraphqlReview(graphql) {
  $("#request-graphql").hidden = !graphql;
  for (const id of ["operation","warning","notes","document","variables","data"]) $("#request-graphql-"+id).textContent = "";
  $("#request-graphql-fields").innerHTML = "";
  $("#request-graphql-effective").innerHTML = "";
  $("#request-graphql-response").textContent = "";
  $("#request-graphql-variables-panel").hidden = true;
  if (!graphql) return;
  if (graphql.status !== "parsed") {
    $("#request-graphql-warning").textContent = `Structured review unavailable: ${graphql.message || "unsupported response"}. No operation or target was inferred. Review the raw body; this does not make the request safe.`;
    return;
  }
  const analysis = graphql.analysis;
  $("#request-graphql-operation").textContent = `${analysis.operation_type.toUpperCase()} · ${analysis.operation_name || "(anonymous)"} · ${analysis.operation_count} operation(s)`;
  $("#request-graphql-notes").textContent = (analysis.warnings || []).join("\n");
  // Show request-specific warnings immediately; keep repeated parser caveats
  // in notes. Missing/unknown variable values remain visible in the value rows.
  const genericNotes = ["GitHub queries flow automatically", "Targets come from request arguments", "The target hint identifies", "Formatting removes comments"];
  $("#request-graphql-warning").textContent = (analysis.warnings || []).filter(warning=>!genericNotes.some(prefix=>warning.startsWith(prefix))).join("\n");
  $("#request-graphql-document").textContent = analysis.formatted_document;
  $("#request-graphql-variables").textContent = analysis.supplied_variables;
  $("#request-graphql-data").textContent = JSON.stringify({version:analysis.version, effective_variables:analysis.effective_variables, fields:analysis.fields, large_values:analysis.large_values || {}},null,2);
  const hasInputs = field => field.parent === null || Object.keys(field.arguments || {}).length || field.arguments_text || field.target || (field.conditions_text || []).length;
  $("#request-graphql-fields").innerHTML = analysis.fields.filter(hasInputs).map(field=>graphqlFieldMarkup(field,analysis.large_values || {})).join("");
  $("#request-graphql-response").textContent = analysis.fields.filter(field=>!hasInputs(field)).map(field=>`${field.path.join(" → ")}${field.response_name !== field.field?` (${field.field})`:""}`).join("\n") || "(none)";
  const variables = analysis.effective_variables || [];
  $("#request-graphql-effective").innerHTML = variables.map(variable=>`<section class="graphql-variable"><h5>$${esc(variable.name)} <span class="meta">${esc(variable.declared_type)} · ${esc(variable.source)}</span></h5>${graphqlValuesMarkup(graphqlValueRows(variable.value, `$${variable.name}`, {}, [], analysis.large_values || {}))}</section>`).join("");
  $("#request-graphql-variables-panel").hidden = !variables.length && (!analysis.supplied_variables || analysis.supplied_variables === "{}");
}

function renderGitPushReview(review) {
  $("#request-git-push").hidden=!review;
  $("#request-git-push-refs").textContent=review?`Repository: ${review.repository}\nTarget: refs/heads/${review.branch}\nExpected current target: ${review.expected_oid}\nBase branch: refs/heads/${review.base_branch}\nBase OID: ${review.base_oid}\nReviewed head OID: ${review.head_oid}\nBundle: ${review.bundle_bytes} bytes · SHA-256 ${review.bundle_sha256}`:"";
  $("#request-git-push-commits").innerHTML=review?(review.commits||[]).map(commit=>`<article class="graphql-field"><strong>${esc(commit.oid)}</strong><pre>${esc(commit.message)}</pre><p class="meta">${esc(commit.author)} &lt;${esc(commit.email)}&gt; · ${esc(commit.authored_at)} · parent: ${esc(commit.parents.join(", "))}</p></article>`).join(""):"";
  $("#request-git-push-files").innerHTML=review?(review.files||[]).map(file=>`<div class="graphql-value"><strong>${esc(file.status)}</strong> ${file.old_path?`${esc(file.old_path)} → `:""}${esc(file.path)} <span class="meta">in ${esc(file.commit_oid)}</span></div>`).join(""):"";
  $("#request-git-push-patch").textContent=review?.patch||"";
}

async function decideRequest(decision) {
  if (!activeReview || (activeReview.status && activeReview.status !== "pending") || decisionInFlight === activeReview.id) return;
  const reviewed = activeReview;
  const generation = reviewGeneration;
  // Approve once is the explicit user confirmation. The broker atomically
  // checks that this exact request is still pending; no second dialog/replay.
  decisionInFlight = reviewed.id;
  $("#request-approve").disabled = true; $("#request-deny").disabled = true;
  try {
    const response = await fetch(`/api/requests/${encodeURIComponent(reviewed.id)}/decision`, {method:"POST",headers:{"content-type":"application/json","x-friendzone-review":"1"},body:JSON.stringify({fingerprint:reviewed.fingerprint,decision})});
    if (!response.ok) throw new Error(await response.text());
    if (generation === reviewGeneration && activeReview?.id === reviewed.id) {
      if ((activeReview.status || "pending") === "pending") applyReviewOutcome({status:decision === "approve"?"approved":"denied", outcome:decision === "approve"?"Approved once; awaiting broker update.":"Denied by host. Not sent."});
      $("#request-review-status").textContent = "";
    }
    await refresh();
  } catch (error) {
    if (generation === reviewGeneration && activeReview?.id === reviewed.id) $("#request-review-status").textContent = `Could not confirm decision: ${error}. Refresh to reconcile.`;
  } finally { if (decisionInFlight === reviewed.id) decisionInFlight = null; }
}
$("#request-approve").onclick = () => decideRequest("approve");
$("#request-deny").onclick = () => decideRequest("deny");
$("#request-close").onclick = () => { activeReview = null; updateReviewTiming(); ++reviewGeneration; ++commentPermissionGeneration; renderCommentPermissionPanel(null); $("#request-review").hidden = true; };
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

async function refresh() {
  const revision = snapshotRevision;
  try {
    const response = await fetch("/api/state", {cache:"no-store"});
    if (response.ok === false) throw new Error(await response.text());
    const next = await response.json();
    if (revision !== snapshotRevision) return; // A newer SSE/fetch snapshot already won.
    ++snapshotRevision; snapshot = next; renderContainers(); scheduleLog();
  } catch(e) { console.error(e); }
}

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
    hint: "Use a fine-grained PAT from github.com → Settings → Developer settings → Personal access tokens (narrow scopes recommended), or reuse the gh CLI's token: run `gh auth token`. Agents and gh read the fake from GITHUB_TOKEN. GitHub GraphQL queries flow automatically. PR/review writes and tool-submitted Git branch bundles require Approve once in Inbox. Ordinary git push remains blocked. Approval cannot grant scopes your token lacks.",
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
  const [escrow, mcp] = await Promise.all([
    fetch("/api/escrow").then(r=>r.json()),
    fetch("/api/mcp").then(r=>r.json()),
  ]);
  mcpConnectData = mcp;
  if (!setupInitialized) {
    $("#setup-host").value = mcp.guest_host || "";
    setupInitialized = true;
  }
  $("#setup-address").textContent = mcp.guest_address_warning || `Guest connections use port ${mcp.guest_port}.`;
  loadGuestSetup();
  if (!mcpHostInitialized) {
    $("#mcp-connect-host").value = mcp.guest_host || "";
    mcpHostInitialized = true;
  }
  $("#mcp-connect-address").textContent = mcp.guest_address_warning || `Guest endpoint uses port ${mcp.guest_port}.`;
  fillMcpConnectSelect("#mcp-connect-forward", mcp.forwards.map(f=>({value:f.name,label:f.name})), "Select a forward");
  updateMcpConnectionGuests();
  loadMcpConnection();
  window._escrowEntries = escrow.entries;
  $("#escrow-list").innerHTML = escrow.entries.map(e=>{
    const clineBtn = e.name === "cline" ? ` <button class="quiet" data-cline-oauth="${esc(e.name)}">Sign in with Cline…</button>` : "";
    return `<div class="log-row"><span>${esc(e.name)}</span><span>${esc(e.hosts.join(", "))}</span><span class="request">${esc(e.header)}${e.prefix?` · prefix '${esc(e.prefix)}'`:""} · fake <code>${esc(e.fake)}</code></span><span>${e.connected?'<span class="verdict allowed">connected</span>':`<button class="quiet" data-secret="${esc(e.name)}">Set key…</button>`}${clineBtn} <button class="quiet" data-escrow-edit="${esc(e.name)}">Edit</button> <button class="quiet" data-escrow-delete="${esc(e.name)}">Delete</button></span></div>`;
  }).join("") || '<div class="log-row">No escrow entries yet.</div>';
  // Keep the single connection form alive while rebuilding server rows.
  $("#mcp-connect-parking").append($("#mcp-connect"));
  $("#mcp-list").innerHTML = mcp.forwards.map(f=>{
    const expiry = f.expires_at ? ` · expires ${new Date(f.expires_at*1000).toLocaleString()}${f.refreshable?" (auto-refresh)":""}` : "";
    const status = f.auth==="cline-link" ? `<span class="verdict">Uses host Cline's credentials</span><p class="meta">Friendzone reads the saved token; host Cline must refresh it. For independent login and refresh, authorize in Friendzone. No guest OAuth login is needed.</p> <button class="quiet" data-oauth="${esc(f.name)}">Authorize in Friendzone…</button>`
      : f.auth==="oauth" ? `<span class="verdict allowed">Friendzone manages OAuth</span>${esc(expiry)} <button class="quiet" data-oauth="${esc(f.name)}">Reauthorize in Friendzone…</button> <button class="quiet" data-oauth-disconnect="${esc(f.name)}">Disconnect</button>`
      : f.auth==="stored-key" || f.auth==="env-key" ? `<span class="verdict allowed">${esc(f.auth)}</span> <button class="quiet" data-oauth="${esc(f.name)}">Switch to OAuth…</button>`
      : `<button class="quiet" data-oauth="${esc(f.name)}">Authorize in Friendzone…</button>`;
    const endpoint = f.guest_endpoint
      ? `<textarea data-mcp-endpoint rows="2" readonly spellcheck="false" aria-label="Friendzone URL for ${esc(f.name)}">${esc(f.guest_endpoint)}</textarea><button type="button" data-mcp-copy-url="${esc(f.name)}">Copy URL</button>`
      : `<code>/mcp/${esc(encodeURIComponent(f.name))}</code> — choose Connect guest to enter a reachable host.`;
    return `<article class="mcp-card"><header class="mcp-card-heading"><h3>${esc(f.name)}</h3><span>${f.tools.length} allowed tools · guests: ${f.guests===null?"all approved":esc(f.guests.join(", ")||"none")}</span></header><div class="mcp-card-endpoint"><strong>Guest endpoint</strong><div class="mcp-endpoint">${endpoint}</div></div><div class="mcp-card-auth">${status}${f.scope?`<p class="meta">OAuth scope: ${esc(f.scope)}</p>`:""}</div><div class="mcp-card-actions"><button type="button" data-mcp-connect="${esc(f.name)}">Connect guest</button><button type="button" data-mcp-review="${esc(f.name)}">Tools and guests</button><button type="button" class="quiet" data-mcp-delete="${esc(f.name)}">Remove</button></div><p class="mcp-upstream">Upstream: <code>${esc(f.url)}</code></p><div data-mcp-connection="${esc(f.name)}"></div></article>`;
  }).join("") || '<p class="mcp-empty">No MCP servers yet. Add or import one below, sign in, then choose what guests may use.</p>';
  fitMcpEndpoints();
  document.querySelectorAll("[data-mcp-copy-url]").forEach(button => button.onclick = () => {
    const input = button.closest(".mcp-card").querySelector("[data-mcp-endpoint]");
    return copyMcpText(input, $("#mcp-copy-status"), "Endpoint copied.", () => input.isConnected);
  });
  document.querySelectorAll("[data-mcp-connect]").forEach(button => button.onclick = () => {
    openMcpConnection(button.dataset.mcpConnect);
  });
  document.querySelectorAll("[data-mcp-review]").forEach(button => button.onclick = () => reviewMcpAccess(button.dataset.mcpReview));
  document.querySelectorAll("[data-mcp-delete]").forEach(button => button.onclick = async () => {
    if (!confirm(`Remove '${button.dataset.mcpDelete}' for new requests? In-flight calls will finish.`)) return;
    try {
      const configs = await (await fetch("/api/mcp/config")).json();
      await saveMcp(configs.filter(f=>f.name!==button.dataset.mcpDelete));
    } catch (error) { $("#mcp-form-status").textContent = String(error); }
  });
  if (connectedMcpName) attachMcpConnection();
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
  $("#mcp-add-panel").hidden = false;
  $("#mcp-setup-title").textContent = `Tools and guests: ${name}`;
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
    $("#mcp-connect-status").textContent = !name ? "Select or add a forward to see its Cline configuration." : !guest ? "Select a guest. Set up a new one under Settings → Guests." : "Enter the broker host address reachable from this guest.";
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
    $("#mcp-connect-auth").value = result.authorization || "Not required — guest is identified by its pinned source IP";
    $("#mcp-connect-json").value = JSON.stringify(result.cline_config, null, 2);
    const forward = mcpConnectData?.forwards.find(f=>f.name===name);
    const warnings = [...result.warnings];
    if (forward && !forward.tools.length) warnings.push("No tools are allowed yet. Select tools for this forward and apply.");
    if (forward?.auth === "oauth-required") warnings.push("Upstream OAuth is not connected. Use Authorize in Friendzone on the host, not in guest Cline.");
    $("#mcp-connect-warning").textContent = warnings.join("\n");
    $("#mcp-connect-status").textContent = `Configuration for '${name}' as '${guest}'. This is not a connectivity test.`;
    for (const id of ["url", "json"]) $("#mcp-copy-"+id).disabled = false;
    $("#mcp-copy-auth").disabled = !result.authorization;
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

async function loadGuestSetup() {
  const generation=++setupGeneration;
  for (const shell of ["sh","powershell"]) {
    $("#setup-"+shell).value=""; $("#setup-copy-"+shell).disabled=true; $("#setup-view-"+shell).hidden=true;
  }
  const host=$("#setup-host").value.trim();
  if (!host) { $("#setup-status").textContent="Enter the broker host IP or DNS name reachable from the guest."; return; }
  $("#setup-status").textContent="Preparing guest setup commands…";
  const query=new URLSearchParams({host,container:$("#setup-container").value.trim()});
  try {
    const response=await fetch(`/api/bootstrap/commands?${query}`);
    if (!response.ok) throw new Error(await response.text());
    const commands=await response.json();
    if (generation!==setupGeneration) return;
    for (const shell of ["sh","powershell"]) {
      $("#setup-"+shell).value=commands[shell]; $("#setup-copy-"+shell).disabled=false;
      $("#setup-view-"+shell).href=commands[shell+"_url"]; $("#setup-view-"+shell).hidden=false;
    }
    $("#setup-status").textContent="";
  } catch(error) { if(generation===setupGeneration) $("#setup-status").textContent=String(error); }
}
for (const id of ["setup-host","setup-container"]) $("#"+id).addEventListener("input",loadGuestSetup);
for (const shell of ["sh","powershell"]) $("#setup-copy-"+shell).onclick=()=>{
  const generation=setupGeneration;
  return copyMcpText($("#setup-"+shell),$("#setup-status"),"Download command copied. Run it in the guest terminal.",()=>generation===setupGeneration);
};

function attachMcpConnection() {
  const slot=[...document.querySelectorAll("[data-mcp-connection]")].find(node=>node.dataset.mcpConnection===connectedMcpName);
  $("#mcp-connect").hidden=!slot;
  if(slot) slot.append($("#mcp-connect")); else connectedMcpName=null;
}
function openMcpConnection(name) {
  connectedMcpName=name; $("#mcp-connect-forward").value=name;
  $("#mcp-connect-title").textContent="Connect guest Cline";
  attachMcpConnection(); loadMcpConnection();
  $("#mcp-connect").scrollIntoView({behavior:"smooth",block:"nearest"});
}
$("#mcp-connect-close").onclick=()=>{connectedMcpName=null;$("#mcp-connect").hidden=true;};
$("#mcp-show-add").onclick=()=>{
  const opening=$("#mcp-add-panel").hidden || reviewingMcp!==null;
  $("#mcp-add-panel").hidden=!opening;
  if(opening){
    reviewingMcp=null;clineLink=null;validatedMcp=null;
    for(const id of ["name","url","bearer","scope","guests"]) $("#mcp-"+id).value="";
    $("#mcp-tools").innerHTML="";$("#mcp-owned-oauth").checked=true;
    $("#mcp-source").textContent="Select a host Cline server or enter a URL.";
    $("#mcp-form-status").textContent="";$("#mcp-setup-title").textContent="Add a server";
  }
};
function selectSettings(section) {
  const selected=["guests","credentials","mcp"].includes(section)?section:"guests";
  for(const name of ["guests","credentials","mcp"]) $("#settings-"+name).hidden=name!==selected;
  document.querySelectorAll("[data-settings]").forEach(button=>{button.classList.toggle("active",button.dataset.settings===selected);button.setAttribute("aria-pressed",String(button.dataset.settings===selected));});
  storeValue("fz-settings-section",selected);
  if(selected==="mcp") fitMcpEndpoints();
}
document.querySelectorAll("[data-settings]").forEach(button=>button.onclick=()=>selectSettings(button.dataset.settings));
function selectSetupPlatform(value) {
  const platform=value==="powershell"?"powershell":"sh";
  $("#setup-platform").value=platform;
  $("#setup-platform-sh").hidden=platform!=="sh";
  $("#setup-platform-powershell").hidden=platform!=="powershell";
  storeValue("fz-setup-platform",platform);
}
$("#setup-platform").onchange=()=>selectSetupPlatform($("#setup-platform").value);
selectSettings(readStoredValue("fz-settings-section"));
selectSetupPlatform(readStoredValue("fz-setup-platform"));

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
    $("#mcp-add-panel").hidden=true;
    openMcpConnection(draft.name);
  } catch (error) { $("#mcp-form-status").textContent = String(error); }
};

$("#add-container").onsubmit = async (e) => {
  e.preventDefault();
  const name = $("#new-container-name").value.trim(), button = $("#preapprove-guest");
  if (button.disabled || !name) return;
  $("#preapprove-status").textContent = "";
  if (snapshot.containers.some(c=>c.id===name)) { $("#preapprove-status").textContent = "This guest already exists. Use its existing approval or management controls."; return; }
  if (!confirm(`Preapprove '${name}' from any IP? This grants network access but does not set up the guest.`)) return;
  button.disabled = true;
  try {
    if (await changeContainerPolicy("/api/containers",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({name})}, "#preapprove-status")) {
      e.target.reset(); $("#preapprove-status").textContent = `Preapproved '${name}'. Use Pin on its guest card to restrict the address.`;
    }
  } finally { button.disabled = false; }
};

$("#show-guest-setup").onclick = () => {
  const open = $("#guest-setup").hidden;
  $("#guest-setup").hidden = !open;
  $("#show-guest-setup").textContent = open ? "Close setup" : "Set up guest";
  $("#show-guest-setup").setAttribute("aria-expanded", String(open));
  if (open) { $("#guest-setup-title").focus({preventScroll:true}); $("#guest-setup").scrollIntoView({behavior:"smooth",block:"start"}); }
};
$("#review-guest-joins").onclick = () => { selectView("inbox"); $("#guest-joins").scrollIntoView({behavior:"smooth",block:"start"}); };

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
events.onmessage = (e) => { ++snapshotRevision; snapshot = JSON.parse(e.data); renderContainers(); scheduleLog(); };
events.onerror = () => setTimeout(refresh, 3000); // bridge reconnect gaps
selectView(readStoredValue("fz-active-view"));
