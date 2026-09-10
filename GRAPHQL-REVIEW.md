# GraphQL review and future capability pins

## Implemented now

The host broker parses GitHub `/graphql` request bodies when constructing
the immutable one-shot review snapshot. `GET /api/requests/{id}` includes
`graphql: {status: "parsed", analysis: {...}}`, or
`graphql: {status: "unavailable", message: "..."}` on a parsing/limit error.
Other requests have `graphql: null`. Parsed bodies are not put in the SSE
snapshot, notification text, persistent settings or logs.

The browser renders the broker's structured snapshot; it does not parse
GraphQL independently. Approval still fingerprints and forwards the
**original method, URL, headers and body**, through the existing
authorization/escrow path. Formatting does not change what executes.
GitHub queries on the supported transport now flow automatically; general
mutations still require one-shot review. The explicit comment permission
below remains the only automatic write exception. Parse failures
remain reviewable as raw text under the existing manual policy; they must
never qualify for a future automatic grant.

The parser implements a bounded executable-document grammar using existing
Rust/Serde dependencies, based on the
[September 2025 GraphQL language specification](https://spec.graphql.org/September2025/#sec-Language):

- Query, mutation and subscription operations, including shorthand queries.
- Exact `operationName` selection; no guessing when multiple operations exist.
- Aliases, nested fields, arguments, named/inline fragments and directives.
- Variable references, declared types, defaults, supplied values, explicit
  nulls and a distinct missing-variable marker.
- Strings, block-string normalization, Unicode escapes/surrogate pairs,
  enums, numbers, booleans, nulls, objects and lists.
- Formatted full document with all operations/fragments; selected-operation
  expansion with every conditional branch retained and labeled.
- Duplicate operation/fragment/variable/argument/input-object names,
  duplicate JSON keys, undefined selected-operation variables, undefined
  fragments, and fragment cycles reported as unavailable, not silently merged.

Supported envelopes are `application/json` with `query` (required string),
`operationName` (optional string/null), `variables` (optional object/null),
or a raw `application/graphql` document. Batches, persisted-query/extensions
envelopes, URL query parameters, other media types, type-system definitions
and unsupported language extensions fall back to a visible raw-review
diagnostic. Unknown JSON envelope fields are not silently discarded.

Parser limits: 64 KiB request body, 8,192 lexical tokens and 32 nesting
levels. Display limits: 256 expanded fields, 1,024 selection visits and a
256 KiB expansion budget. Over-limit displays yield no partial analysis,
but a successfully classified query still flows when only display expansion
fails. Formatting normalizes whitespace/string escapes and omits comments;
the raw body is retained for queued requests.

**This is not schema validation.** The broker does not know all GitHub
types, validate field merges, coerce custom inputs or evaluate directives.
Fields may be invalid for their declared type. Enum literals and supplied
JSON strings stay distinct in the tagged value representation. Lists are
not implicitly coerced; omitted values are not conflated with null.

**Isolation limitation:** the parser receives only body text/content type
and performs no network, settings or credential access, but currently runs
in the broker process. The separate secret-free parser process described
as a design goal in `DECISIONS.md` is not implemented. Query admission uses
the bounded executable grammar and GitHub's Query-root contract; target/action
display hints are not the security boundary for automatic write authorization.

## Read-only GraphQL queries

The same envelope parser and AST operation selection feed read admission and
the UI. The operation type must be `query` (including the shorthand `{ ... }`),
not `mutation` or `subscription`. Names/aliases and words in comments or
strings cannot change that type. For multiple operations, the request must
select an existing, unique query with `operationName`; an unselected mutation
does not run. No field or argument allowlist is applied to queries, so
repository reads, search, fragments, variables and introspection all work.
This relies on [GitHub's read/query contract](https://docs.github.com/en/graphql/guides/forming-calls-with-graphql),
not an assertion that every arbitrary GraphQL service honors read semantics.
GitHub still validates schema/variables and may return errors for invalid
fields or missing values; those errors do not turn a query into a mutation.

Automatic read transport is POST to HTTPS `api.github.com`, port 443 (implicit
or explicit), path `/graphql`, with no URL query parameters or conflicting
Host header. JSON and raw GraphQL content types are supported, with optional
UTF-8 charset. Duplicate headers, encoding/upgrade/method-override semantics,
unknown headers and unknown directive extensions do not auto-pass. Allowed
headers are Authorization, Content-Type, Content-Length, Transfer-Encoding,
Host, User-Agent, Accept, Accept-Encoding, Connection (`close`/`keep-alive`),
X-GitHub-Next-Global-ID, X-GitHub-Api-Version, Time-Zone and Cache-Control.
Standard `@skip`/`@include` on selections are supported; their Boolean/variable
conditions cannot convert a query into a mutation. Other directives stay
manual until supported. Batches, duplicate JSON keys, persisted queries,
ambiguous selection, malformed syntax and invalid fragment graphs never
qualify as reads. Existing size/encoding limits may reject rather than queue.

Read requests still pass identity/approval/IP/kill/management-port and escrow
checks. The final epoch/IP/kill check is shared with manual approvals and
occurs after body buffering; prior revocation cannot slip through as a read.
The original query bytes are forwarded, with normal escrow substitution.
No target lookup, saved grant, pending item or browser notification is created.
Log rows identify `read-only GitHub GraphQL query; automatically allowed`.

## PR creation and review operations: manual approval

`createPullRequest`, `addPullRequestReview`, `addPullRequestReviewThread`,
`addPullRequestReviewThreadReply`, `submitPullRequestReview`, and the legacy
`addPullRequestReviewComment` are manually approvable through the ordinary
Inbox. This does not require a saved comment permission. The original
request waits for **Approve once** / **Deny** and is forwarded unchanged on
approval. No blanket PR/review grant is created. Legacy operations may be
rejected by GitHub if no longer supported; Friendzone does not rewrite them.
REST JSON PR creation and review-comment writes use the same one-shot gate.

Cards show an action label and `mutation_inputs` (path/label/value) for every
supplied input: repository IDs, head/base branches, title/body, draft and
maintainer options, commit, file/line/side, threads/comments and review event.
Unknown inputs remain explicitly visible. `APPROVE` and `REQUEST_CHANGES`
are consequential review submissions, not merely comment text. Target hints
identify opaque Repository/PR/Review/Thread IDs, not verified PR numbers;
when both PR and review/reply IDs are supplied no single target is guessed.
General PR/review target lookup is not added to the narrow comment resolver.
Binary git push remains blocked; PR creation requires the head branch to
already exist on GitHub. Token scopes must permit the approved operation.

## Structured model (version 1)

`analysis` includes selected operation type/name/count, formatted full
document, pretty supplied variables, effective variables with their source
(`supplied`, `default`, `missing`), ordered fields, and warnings.

Each field contains:

- `field`: actual GraphQL field name, independent of the alias.
- `response_name`, `path`: client-selected response alias/path for display.
- `parent`: index of the parent field, or null for a root field. Fragments
  do not manufacture parents; their expanded root fields remain roots.
- `arguments`: typed, resolved values; `arguments_text`: readable rendering.
- `conditions`: typed inherited directives (name + resolved argument map),
  inline type conditions and fragment conditions, explicitly not evaluated;
  `conditions_text` provides the corresponding display strings.
- `action`, `target`: optional broker-recognized action and primary target hint.
- `comment_body`: literal `addComment.input.body`, separate from its target.
- `mutation_inputs`: labeled exact resolved inputs for PR creation/review
  operations; extra fields remain visible and do not imply a broader grant.

Value tags preserve strings, enums, integer/float literals, lists, objects,
null, booleans and missing variables. Field order and duplicate occurrences
are retained; no field merging or request-wide action hash is performed.

### Initial GitHub target extractors

These are explicit schema paths, not a recursive search for a field named
`id` or a `#123` string:

| Context | Primary target |
|---|---|
| Root mutation `addComment` | `input.subjectId`: opaque Issue-or-PullRequest node ID |
| Root mutation `updateIssue` | `input.id`: opaque Issue node ID |
| Root mutation `closeIssue`, `reopenIssue` | `input.issueId`: opaque Issue node ID |
| Root mutation `addPullRequestReview`, `updatePullRequest` | `input.pullRequestId`: opaque PullRequest node ID |
| Root mutation `createPullRequest` | `input.repositoryId`: opaque Repository node ID |
| Root mutation `addPullRequestReviewThread`, legacy `addPullRequestReviewComment`, `submitPullRequestReview` | sole provided PR/review/reply ID; ambiguous combinations have no primary hint |
| Root mutation `addPullRequestReviewThreadReply` | `input.pullRequestReviewThreadId`: opaque thread node ID |
| Root query `node` | `id`: opaque node ID, type unknown |
| Root query `repository(owner, name)` → `issue(number)` | owner + repository + issue number |
| Same → `pullRequest(number)` | owner + repository + PR number |
| Same → `issueOrPullRequest(number)` | owner + repository + issue-or-PR number |

Unknown operations, nested lookalikes, missing/non-string node IDs and
missing/invalid repository numbers do not acquire a target. All arguments
remain available, including ones not recognized by the target extractor.
See GitHub's [issues](https://docs.github.com/en/graphql/reference/issues),
[pulls](https://docs.github.com/en/graphql/reference/pulls) and
[repos](https://docs.github.com/en/graphql/reference/repos) schema references.

## Verified per-guest comment permissions

For an eligible pending `addComment` request, the review pane offers:

1. **Resolve GitHub target**: a broker-owned query to `https://api.github.com/graphql`
   reads the node type, canonical node ID, repository ID/name, issue/PR number,
   title and URL using the request's configured escrow credential. Inspect
   those values; title text is untrusted content even though it came from GitHub.
2. **Allow future comments here**: explicitly grants this guest permission to
   comment on that verified target with varying comment text. The target is
   checked again when saving. No capability is granted merely by resolving.
3. **Approve once** or **Deny** the existing request separately. Saving a
   permission does not release already-waiting requests or replay anything.

**Saved comment permissions** in Inbox lists these grants with Revoke.
They are saved atomically alongside guest policy in `containers.json` (at
most 32 per guest). Removing a guest removes its grants. Kill/IP/approval
changes remain enforced. Grant/revoke events appear in the memory-only log
but do not change last-observed guest traffic.

### Automatic path is a closed command, not arbitrary GraphQL forwarding

The strict extractor accepts one mutation, one root `addComment`, input
`subjectId` and `body` strings plus optional string/null `clientMutationId`.
Variables/defaults and aliases work. Extra operations, extra input fields,
unused variables, fragments, directives, or unsupported result selections
fall back to Inbox. Result selections are restricted to `clientMutationId`,
`subject { id }`, `commentEdge { node { id url body } }`, and `__typename`;
aliases are preserved. This is intentionally narrower than GitHub's schema.

Transport must be POST to exactly `https://api.github.com/graphql`, with a
supported JSON/GraphQL content type and exactly one recognized fake Bearer
credential from escrow. No passthrough real tokens or custom semantic
headers/cookies are accepted under a grant. Extra headers can therefore
make a CLI request fall back to manual review. A fixed allowlist permits
ordinary Host, User-Agent, Accept, Accept-Encoding, Connection and HTTP
body framing headers; automatic forwarding rebuilds clean headers.

Every candidate automatic comment does a **fresh fixed target read** (no
redirects, eight-second timeout, bounded response, four concurrent reads).
The canonical node ID, repository ID/name, type, number and URL must match
the saved target. Legacy node IDs can resolve to the canonical ID; a moved
issue or renamed repository fails the saved match and needs a new grant.
Lookup errors/rate limits/busy state fail back to manual review, not allow.

On admission the broker builds its own `FriendzoneComment` mutation using
the validated values and canonical node ID. **It does not forward the guest's
GraphQL text under an automatic grant.** The selected permitted response
shape is retained. Manual **Approve once** still forwards the original bytes.
The request log distinguishes automatic reconstruction from manual approval.

Grants bind to the escrow entry/fake/header/prefix and a digest of its real
credential, kept out of UI/SSE output. Changing that binding makes the grant
inactive; resolve a new request to grant the new credential. Restoring the
exact old binding makes an unrevoked grant eligible again; use Revoke for
permanent removal. The UI labels inactive credentials on state refresh.
Concurrent grants/revocations use a revision check: an old review cannot
restore a revoked permission without a fresh resolve/confirmation.

Guest policy and grant existence are rechecked atomically at admission.
The credential used for target verification is frozen for that admitted
command. Later revocation/rotation cannot undo admitted upstream work.
GitHub state can change between the read and mutation; the mutation uses
the verified canonical node ID, not a possibly reused issue number.

No user-configurable lookup URL/query, guest-grant API, REST comment pinning,
automatic PR/review mutation grants, MCP write policy, separate parser
process, or full schema validator is added. All preexisting network
containment limitations still apply. A comment permission permits arbitrary
comment content (including links/mentions); it is not content moderation or
an anti-spam quota. Client retries may post duplicate comments: inspect
upstream state after a lost response before retrying.

## Future broader capability rules

For “this agent may comment on cline/cline#482, with arbitrary comment text”:

1. The host chooses the repository and issue/PR. A broker-owned, fixed read
   obtains the canonical repository/node IDs and verifies their association.
   Do not trust a guest's claimed mapping or decode opaque node IDs; GitHub
   explicitly [requires treating node IDs as opaque](https://docs.github.com/en/graphql/guides/migrating-graphql-global-node-ids).
2. Store a guest-scoped capability with the verified subject ID and allowed
   action (`addComment`), not the operation name/alias or whole-body hash.
3. Match the **selected operation's complete behavior**. Every root field,
   argument, fragment and directive must be covered; unrecognized or
   unvalidated behavior falls back to manual review/denial. Matching just one
   allowed field or primary target is insufficient.
4. For `addComment`, constrain allowed input fields and the subject ID while
   treating `body` as variable content. For other mutations, account for
   additional effects (e.g. a duplicate-issue reference, changing a PR base
   branch, or a review `event: APPROVE`). Posting a review is not merely
   posting a comment.
5. Recheck the capability at the same admission boundary as guest
   approval/IP/kill checks, with auditable revocation. Address node-ID
   canonicalization, repository changes and credential changes explicitly.

The current permission implements only the narrow comment case above. A
broader rule system must not promote the advisory target summaries directly
into grants or treat a shared primary target as equivalent behavior.