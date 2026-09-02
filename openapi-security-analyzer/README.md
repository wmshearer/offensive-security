# OpenAPI security analyzer

Static security analysis of OpenAPI specifications, and a version-to-version
diff that reads removals as an inventory question.

Written in TypeScript. Sends no requests to anything. It reads files.

## What it does that other tools do not

Very little of the single-document rule set is new, and saying otherwise would
be the first claim a reviewer checks. Spectral's OWASP ruleset already covers
this ground. Counting the live source, it has **29 rules**, spread unevenly:
API4 has 9, API2 has 8, while API5 and API7 have one weak heuristic each, and
API6 and API10 have none at all.

The part that is different is `diff`, and the honest framing of it matters:

- **Wrong claim:** nobody frames spec-diff as security analysis.
- **True claim:** nobody does it without live traffic as an input.

Wallarm, Cerberus and 42Crunch all sell shadow and zombie API detection, and
they do it well. Every one of them compares a spec against traffic observed at
a gateway or agent. That is a heavier deployment answering a related question.

Spectral sits at the other end: it lints one document and has no concept of a
second. An open feature request asking for exactly that confirms it.

This tool takes the middle: two documents, no runtime data, no agent, no
gateway. It runs in CI on a pull request.

## The limit that governs everything here

A specification is documentation. Removing a path from documentation does not
remove the route from the server.

That is precisely why a removed path is worth flagging, and precisely why this
tool can never close the finding. Every diff result is a question for a human.

Findings are labelled `PROVES` or `SUGGESTS`, and every one carries a
`cannot establish` line that ships with it rather than living in a footnote.

## Usage

```
node dist/cli.js analyze <spec.json>
node dist/cli.js diff <previous-spec.json> <current-spec.json>
```

Argument order for `diff` matters. Reversed, it produces a clean-looking report
rather than an error, because a removal reads as an addition. There is a test
pinning that behaviour and the CLI names the arguments.

## Result against a real API

Two published versions of Stripe's OpenAPI specification, v1300 and v2430, both
MIT licensed:

```
previous: 559 operations
current:  589 operations

  34 operations added
   4 operations removed
   0 operations lost a declared security requirement
```

The four removals are:

- `GET /v1/invoices/upcoming`
- `GET /v1/invoices/upcoming/lines`
- `GET /v1/subscription_items/{subscription_item}/usage_record_summaries`
- `POST /v1/subscription_items/{subscription_item}/usage_records`

None was marked `deprecated: true` in the earlier spec before disappearing from
the later one. Stripe's documentation page for the first returns 404, and a
search of the public changelog did not surface a removal note for any of them.

What that establishes: four operations left the documented contract without a
deprecation flag. What it does not establish: whether any of those routes still
answer. Stripe is a mature API vendor with a public versioning policy, and the
most likely explanation is an orderly retirement recorded somewhere this tool
cannot see. The finding is an inventory question, not a vulnerability.

## The bug worth knowing about

The first run against Stripe produced four **HIGH** findings, each stating the
removed endpoint was "reachable without credentials".

That was false. Stripe declares `[{basicAuth}, {bearerAuth}]` at the document
level, and operations with no `security` key inherit it. Only an explicit empty
array opts out. The original check looked at the operation level alone, so every
inheriting operation read as unauthenticated.

A wrong claim on the highest-severity line is the worst kind to ship, because it
is the line a reader acts on first. Both the rules and the diff engine now call
one shared `requiresAuth`, and six tests pin the behaviour. Reintroducing the
old logic fails three of them, which was checked rather than assumed.

## Tests

```
npx vitest run
```

20 tests. The interesting ones are in the inheritance group.

## Specs used

- `stripe/openapi` — MIT, licence text read directly
- Both versions fetched from published tags

## What this cannot do

- Confirm any endpoint is live. It makes no requests.
- Find shadow endpoints, meaning routes that were never documented at all. A
  document cannot describe what was never written into it. Only the zombie half
  is addressable, and only partially.
- Establish runtime authentication, rate limiting, or TLS behaviour. Gateways
  routinely enforce all three without any of it appearing in the specification.
