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
Queries and general mutations still require one-shot review. The explicit
comment permission below is the only automatic exception. Parse failures
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

Work limits: 64 KiB request body, 8,192 lexical tokens, 32 nesting levels,
256 expanded fields, 1,024 selection visits and a 256 KiB expansion budget.
Over-limit documents yield no partial analysis. Formatting normalizes
whitespace/string escapes and omits comments; the raw body is retained.

**This is not schema validation.** The broker does not know all GitHub
types, validate field merges, coerce custom inputs or evaluate directives.
Fields may be invalid for their declared type. Enum literals and supplied
JSON strings stay distinct in the tagged value representation. Lists are
not implicitly coerced; omitted values are not conflated with null.

**Isolation limitation:** the parser receives only body text/content type
and performs no network, settings or credential access, but currently runs
in the broker process. The separate secret-free parser process described
as a design goal in `DECISIONS.md` is not implemented. Do not treat this
advisory parser as the security boundary for automatic authorization.

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

No user-configurable lookup URL/query, guest-grant API, general query
auto-allowing, REST comment pinning, MCP write policy, separate parser
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