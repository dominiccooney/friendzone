# Friendzone — Design

Friendzone lets developers run agents in containers that handle malicious
input. Real credentials stay on the host in the Friendzone broker, which
substitutes them into approved requests, applies per-operation policy,
and buffers writes for human review. Version 1 scope: agents in local VMs
(Hyper-V on Windows, tart on macOS) reviewing untrusted PRs and issues on
a public GitHub repo, plus MCP forwarding of host-configured servers
(first: Linear), filtered by server and tool.

Terms:

- **broker**: the host process holding real credentials and enforcing
  policy. CLI binary: `fz`.
- **fake token**: the placeholder credential inside the container.
- **host pinning**: real tokens go only to fixed, named hosts.
- **capability pinning**: a container gets a fixed, narrow set of
  operations, e.g. "comment on PR #482".
- **pending request**: a write buffered in the broker awaiting approval.
- **MCP forwarding**: re-exposing a host-configured MCP server to
  containers through the broker, filtered by server and tool.
- **ruleset**: a named, shareable file of policy: approval rules, escrow
  entries, capability pins, MCP forwards.

Principles: secure by construction (§1); the user owns policy (§2); the
product manages the user's attention (§3). §4 gives the interface
structure. §5 scenarios test the design; a scenario that breaks a
decision reopens it.

## 1. Secure architecture

Security holds by construction. Detection raises alarms; no security
property depends on it.

- **Escrow.** An escrow entry: fake value, real value, pinned hosts,
  substitution locations. A fake token is worthless in any encoding, so
  escrowed credentials cannot be exfiltrated.
- **Egress is default-deny, enforced outside the container.** Hyper-V:
  internal switch, no NAT — no route exists except the broker. tart:
  softnet with block-all policy allowing only the host. UDP, DNS, and
  port 22 have no path out. Fail closed: broker down means no network.
- **The parser holds no secrets.** Container bytes are hostile; the
  parsing process is separate from the credential-holding process.
- **Approvals bind to what the human saw.** Views render from
  broker-parsed data, never container-supplied text. Opening a pending
  request locks it against agent edits; approval executes the locked
  content, pinned to ref and SHA.
- **Semantic parsing.** The GitHub module parses REST, GraphQL, and git
  smart-HTTP into operations ("comment on PR #482", "push to
  refs/heads/x"); policy speaks in operations, not URLs. A GraphQL
  operation's type (query vs mutation) is explicit after parsing.
  Unparseable protocols are blocked and replaced by MCP tools; the
  broker reconstructs the real request outside.
- **MCP forwarding terminates, never tunnels.** The broker is an MCP
  server toward containers and an MCP client toward upstream (Linear
  first). OAuth runs on the host — broker-owned client registration,
  login in the host browser — and the token becomes an escrow entry; no
  token-bearing byte enters the container, and upstream MCP hosts stay
  unroutable from it. One resolver computes both the filtered
  `tools/list` and each `tools/call` verdict, so the advertised and
  callable sets cannot diverge. Read/write class per (server, tool) is
  broker-assigned — upstream `readOnlyHint` is advisory — and
  unclassified tools default to write.
- **Compatibility is a security requirement.** Fake tokens are
  format-valid (`ghp_…`); the broker answers probes like `GET /user`.
  Tools that reject the fake fail before Friendzone can protect them.
- **Containers have identity.** Per-container credentials in the proxy
  URL; source addresses are spoof-proof (Hyper-V blocks MAC spoofing;
  softnet pins MAC and IP). A fake token on the wrong container's
  connection is an alert.

## 2. User control

Risk judgment varies per repo, per container, and per task — permissive
for a colleague's PR, strict for a first-time contributor's. The engine
ships mechanism; rulesets supply judgment.

- **Rulesets** bundle approval rules, escrow entries, and capability
  pins; versionable, exportable, attached to a container at start.
- **Escrow is configurable.** Users choose what to escrow; low-value
  credentials may live in the container.
- **Approval scopes**: once; for this broker's life; always (writes a
  rule).
- **A default ruleset gates destructive git operations**: force-push,
  ref deletion, protected branches, workflow/CI files, repo settings.
  Adjustable like any ruleset; a repo that releases through Actions can
  deny Actions writes entirely.
- **Kill switch per container, reversible**: rejects new connections,
  terminates in-flight ones, holds pending requests. Audit-logged.
- **The broker impersonates the host's logged-in GitHub user** (org
  constraint; no GitHub App tokens yet). The token is full-power, so
  policy is the containment.
- **MCP forwards are per-container policy.** A forward names a server
  and a tool allowlist; rulesets carry forwards like any other rule.
  The broker owns its MCP server registry (settings page); it does not
  reuse host clients' auth sessions — each forward logs in once through
  the broker. Revocation is immediate at call granularity: every
  `tools/call` checks current policy, so a stale tool list in the
  container is harmless.
- **Secrets rest in the OS secret store.** Rulesets reference secrets by
  name, never value.

## 3. Visibility and attention

Automate easy decisions, present hard ones well, never train the user to
click "allow".

- **Reads flow, writes queue.** Read vs write is the semantic
  classification, not the HTTP method: git fetch and GraphQL queries are
  reads despite being POSTs. Writes become pending requests via MCP
  tools; agents enumerate, edit, and delete their own by ID. Forwarded
  MCP tools obey the same rule: read-class calls flow, write-class calls
  become pending requests rendered from broker-parsed arguments in the
  structured-API-call viewer, with the same lock-on-open semantics.
- **Origin rules cover the long tail.** A rule matches origin (protocol
  + host + port, wildcard subdomains) × read/write. "Read from
  `*.crates.io`" is one decision for a whole registry. Parsed endpoints
  use capability pins instead.
- **Feedback flows to agents.** Any decision can carry a note; a denial
  with a reason converges the agent, a bare denial breeds retries. Safe
  because the boundary constrains what leaves and executes, not what the
  agent reads.
- **Flooding is rate-limited**, per container, with exponential backoff.
  No deduplication: agents manage their own resubmissions.
- **Detection is loud.** Outbound content is scanned for fake tokens and
  secret-shaped strings; hits block, quarantine, and alert. Quarantined
  items build a labeled corpus — the prerequisite for any future risk
  scoring.
- **Inbound content is screened.** The GitHub module parses issues,
  comments, and reviews on the read path into author identity and text.
  Identity checks are deterministic; text checks are heuristic:
  instruction-shaped content, hidden text (HTML comments, zero-width
  characters), encoded blobs.
- **Identity is presented, not just checked.** The broker keeps a
  per-repo account table keyed to numeric user IDs, never logins
  (logins are mutable and reusable). For every author it shows standing:
  collaborator or not, commit history in this repo (how many, first and
  last date), and first-seen date. Warnings, in order of severity: login
  within small edit distance of a collaborator's or past committer's
  login but a different ID; a known login now resolving to a new ID; a
  first-interaction account. Standing and warnings appear wherever the
  author does — cards, reading pane, log rows.
- **Hits annotate, taint, or withhold**, by severity and ruleset.
  Withheld content becomes an inbox item (release or deny) and the agent
  receives a placeholder. Either way the container is tainted: its
  subsequent writes carry the flag glyph and are excluded from group
  approval. Hits are quarantined, so evidence survives upstream
  deletion. Screening is advisory — escrow and gating hold when it
  misses; its job is to redirect scrutiny.
- **Retention**: bodies ~1 hour, metadata ~1 week, searchable by
  container. Flagged and quarantined items never expire.
- **`fz setup`** bootstraps a guest over the network: the broker serves
  the `fz` binary and CA certificate over plain HTTP, and setup installs
  the CA into the OS store and each language runtime. Trust-on-first-use
  is sound because the broker is structurally the only reachable
  endpoint.
- **`fz doctor`** diagnoses from inside: direct IPs, DNS, UDP, and port
  22 must fail; CA trusted per runtime; broker reachable; fake
  credentials in place. Gates CI builds of images. Doctor diagnoses;
  enforcement lives outside.

## 4. Structure

Three tiers by visit frequency: inbox (daily), log (investigation),
settings — credentials and rulesets (rarely). Viewers drill in from
items.

**Inbox.** Every item needing the user: pending writes, agent questions,
new-container acks, detection alerts, expiring credentials, idle
containers. An item is a source, content in a typed viewer, and a verb
set (approve/deny, answer, ack, dismiss). New item types add verbs, not
structure. Deciding an item moves it to the log. Urgent types also raise
an OS notification; the item remains the record.

Questions have two guards: answers relay as text, never interpreted —
gated operations gate through their own items; and answers pass the
secret scan before delivery, because the natural phish against escrow is
asking the human for the real token.

**Feedback channel.** An `fz` daemon in the container subscribes to the
broker for decision events; an agent-side plugin injects them at turn
boundaries. The same connection registers agents and carries heartbeats.

**Agents are attribution, not identity.** Labels are container-reported
and bear no policy; credentials, ruleset, and kill switch stay
container-level. Each agent gets a dot, shown on items it is blocked on.
No task noun: ruleset-attach events mark task boundaries in the log.

**Sections.** The inbox groups by container, then by target (PR, issue,
repo). Sections sit in user-chosen order; empty ones compact to a header
line. The header is the dashboard: live/killed, doctor state, ruleset,
agent dots, working/waiting/idle, kill switch. At inbox zero the surface
is just headers.

**Cards.** One line: agent dot, verb + object ("Post comment"), target
("cline/cline #1234"), age, flag glyph (scan hit, taint, or floor rule).
Container omitted — the section says that. Subjects scan; bodies read.

**Reading pane.** Header: the full operation and why it needs a decision
(no rule matched / floor rule / scan flag). Body: typed viewer(s), in
sequence for multi-part items. Decision bar: verbs, scope, note field.
"Always" previews the rule before writing it.

**Keyboard workflow.** Cursor down; single keys approve, deny, answer,
flag, open; deciding advances. Group actions decide a target's batch;
flagged items are excluded — they exist to be read, so each opens
individually. Goal: inbox zero for agents.

**Two surfaces.** A tray strip: one light per container, color for
state, flicker on traffic, count of waiting decisions. Traffic from a
supposedly idle container is visible without opening anything. The big
surface spends pixels: inbox, log, reading pane.

**New containers.** Unknown proxy credentials create an ack item; until
decided, the broker serves only `fz setup`/`fz doctor` and refuses the
rest (agents retry as after a broker restart). Ack names the container
and attaches a ruleset (default preselected); the section starts on top.
Denying kills the container.

**Log.** A log row is a card plus a verdict (allowed, substituted,
approved, denied, blocked), drilling into the same reading pane minus
the decision bar. Filters: container, agent, time, verdict, read/write,
flag. Search covers metadata for the week, bodies while they live;
expired bodies degrade to metadata, flagged items keep everything — flag
first, read later. Ruleset-attach events draw as dividers: "what has it
done since taking this job" is one filter. A live tail follows one
container in real time.

**Rules are written where the evidence is.** Inbox: "always" creates a
rule. Log: promote an over-denial into an allow rule. Rules record the
request that created them. The ruleset page is import/export/repair, not
authoring. Rulesets are YAML; machine-appended rules preserve hand-edits
and comments.

**Credentials are set-and-forget.** A settings page for escrow entries;
failures announce themselves as inbox items.

**Viewers are typed by content, not operation.** A closed set — diff,
markdown, image, structured API call, raw HTTP — renders every item.
Operations are an open set mapping onto existing viewers: "approve PR"
and "create PR" both show a diff.

## 5. Scenarios

Attacks and workflows the design must survive, each with its resolution.

- **Naive exfiltration.** Agent POSTs env vars to attacker.com. Egress
  default-deny blocks; a canary alert fires if a fake token is included.
- **Exfiltration via a permitted channel.** Agent leaks secrets through
  an allowed write. Escrowed credentials cannot leak (only fakes were
  present). Non-escrowed material can; the scan catches careless
  attempts, capability pins bound the audience, and the careful
  remainder is accepted risk.
- **Scope escalation.** Agent pinned to PR #482 tries `DELETE /repos/x`.
  Capability pinning denies: distinct parsed operations.
- **MCP scope escalation.** Container forwarded Linear's `list_issues`
  calls `create_issue`, or guesses a tool name absent from its list.
  Every `tools/call` resolves against current policy — the same resolver
  that filtered the list — so the call is rejected and logged; an
  unclassified tool that slips into the allowlist still queues as a
  write. Exfiltration through an approved MCP write hits the same
  secret scan as any other outbound content, and the OAuth token cannot
  leak because no container byte ever carried it.
- **GraphQL smuggling.** A mutation hides in an innocuous-looking query.
  Operation type is explicit post-parse; mutations are rejected on the
  wire.
- **Identity spoofing.** A container claims another's identity.
  Per-container proxy credentials and spoof-proof source addresses deny
  it; a misplaced fake token alerts.
- **Approval social engineering.** Injected content asks the human to
  approve a push whose description lies. The diff renders from
  broker-parsed pack data; the description has no authority.
- **Doctor false pass.** The OS store trusts the CA but Node ignores it.
  Doctor checks each runtime separately.
- **QUIC or DNS tunnel.** No route on Hyper-V; softnet default-deny on
  tart; DNS only through the broker, which rate-limits and logs.
- **Inbox flooding.** Hundreds of pending requests bury one malicious
  comment. Rate limits back off; batching groups by target; every item
  still renders its diff.
- **Edit-after-review race.** Agent edits a pending request between read
  and approve. Opening locks; approval executes the locked content.
- **Unlock-window swap.** User closes undecided; agent swaps content.
  Re-opening re-locks and binds approval to the new content; the yellow
  fade makes the swap conspicuous.
- **Release hijack via CI.** Injected content steers the agent to
  trigger a release workflow. The dispatch is a write, seen before it
  executes; a ruleset deny removes even the prompt; workflow-file
  changes hit the default gates.
- **Phishing the human.** "Paste the real deploy token and I'll finish
  tonight." Answers are scanned for secret-shaped text before delivery.
  "Reply yes to approve" gains nothing: answers are never interpreted.
- **Reviewer impersonation.** A PR review from a login resembling a
  maintainer's instructs the reviewing agent to apply changes (observed
  on cline/cline #13261; the review was later deleted upstream). The
  edit-distance warning fires on the lookalike login with an unknown
  numeric ID, and the author line shows no commits and first-seen today.
  The container is tainted, so any resulting write needs individual
  review with the warning beside it; the quarantined copy survives the
  upstream deletion.
- **Injection despite screening.** Instructions the text heuristics
  miss steer the agent. Its writes still gate: capability pins bound
  the damage, the diff shows what would change, and denial-with-note
  redirects the agent. Screening failing is the expected case, not the
  broken one.

## 6. Deferred

- SSH brokering (terminate at the broker, parse the exec command, relay
  upstream). HTTPS covers all git operations; port 22 stays closed.
- MCP forwarding beyond tools: resources, prompts, sampling, and
  elicitation across the boundary; stdio-launched host servers and
  legacy SSE transports; per-argument tool scoping (future capability
  pins); importing server URLs from host clients' MCP configs.
- GraphQL mutations on the wire and their argument-level scoping. Writes
  buffer through the inbox instead.
- GitHub App short-lived tokens, when the org constraint lifts.
- Git LFS, release assets, ghcr.io.
- Other code hosts: GitLab, Bitbucket, Azure DevOps.
- Linux hosts; cloud containers likely arrive first.
- Remote monitoring (Android, web).
- Risk scoring, until the quarantine corpus can train and evaluate one.
- Graceful broker restart. Connections drop, clients retry; pending
  requests persist.
- Single guest-facing port: multiplex the proxy (CONNECT/absolute-form
  requests) and bootstrap (origin-form GET/POST) on one listener by
  request shape. One firewall rule instead of two; needs care that
  bootstrap routes can never be reached through the proxying path.
