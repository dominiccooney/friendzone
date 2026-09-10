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
Queries and mutations both still require one-shot review. Parse failures
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

## Next step: verified issue/PR pinning (not implemented)

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

No persistent capability, node lookup/cache, auto-allow-query rule, broader
GraphQL transport allowance or MCP write policy is introduced by this UI work.