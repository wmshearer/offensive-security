# Findings: what zizmor and OpenSSF Scorecard actually detect in GitHub Actions workflows

## Thesis, up front

Two scanners were pointed at a corpus of five known GitHub Actions
vulnerabilities with a machine-readable answer key
(`ground-truth.yml`). This project found two structural blindnesses, not
two weak tools: **zizmor cannot detect the OIDC misconfiguration class at
all**, because the vulnerable artifact is a cloud provider's identity trust
policy, a file zizmor never reads, and **OpenSSF Scorecard's
`Dangerous-Workflow` check only covers two of the five classes**, by its
own documentation. A third finding sits underneath both scanner results:
**zizmor's own `self-hosted-runner` rule is opt-in, not part of its default
output**, and switching it on with `--persona=auditor` is the only thing
that changes between the two zizmor runs in this project. Every number
below traces to a raw file kept in `evidence/`.

## What "detected" means here, and why there is no single score

Never a single blended number. zizmor reports an exact rule name, file, and
line for every finding, so it is scored **per class, true positive versus
false negative, at line level**, against `ground-truth.yml`. Scorecard's
`Dangerous-Workflow` check reports a file and line too, but its own
documentation describes it as a repo-posture check for the presence of a
small number of named dangerous patterns, not a dataflow engine with a
rule per vulnerability class. Scorecard is scored as a coarser **file-level
binary**: did it flag the workflow file containing the planted case at all.
Forcing both tools onto the same line-level table would overstate what
Scorecard's coarser check actually claims to do.

## The five planted classes, one line each

1. **`pull_request_target` secret exfiltration** - `.github/workflows/pr-target-exfil.yml`, line 29-30 (trigger) and 44-47 (untrusted checkout).
2. **Script injection via `github.event`** - `.github/workflows/script-injection.yml`, lines 43-46.
3. **Actions cache poisoning** - `.github/workflows/cache-poison-write.yml` line 61 (writer) paired with `.github/workflows/cache-poison-restore.yml` lines 26-59 (restorer).
4. **Self-hosted runner with no isolation, planted, never executed** - `.github/workflows/self-hosted-runner-pattern.yml`, line 64.
5. **OIDC wildcard `sub` trust-policy misconfiguration, analytical only** - `docs/oidc-trust-policy-analysis.md`, no workflow line, by design.

Full rationale, CWE mapping, and detection hypothesis for each case is in
`ground-truth.yml`.

## Per-class results, zizmor, default persona versus `--persona=auditor`

zizmor 1.30.0 (MIT, PyPI, `github.com/zizmorcore/zizmor`), run twice against
the exact same six workflow files: once with its default settings (the
"Regular" persona) and once with `--persona=auditor`. Raw output:
`evidence/zizmor-default.json`, `evidence/zizmor-auditor.json`. Scored
result: `evidence/scoring-results.json`.

| Class | Rule expected | Default persona | `--persona=auditor` |
|---|---|---|---|
| 1: pull_request_target exfil | `dangerous-triggers` | TRUE POSITIVE (line 29) | TRUE POSITIVE (line 29) |
| 2: script injection | `template-injection` | TRUE POSITIVE (line 43) | TRUE POSITIVE (line 43) |
| 3: cache poisoning | `cache-poisoning` | TRUE POSITIVE (line 28) | TRUE POSITIVE (line 28) |
| 4: self-hosted runner | `self-hosted-runner` | **FALSE NEGATIVE** | TRUE POSITIVE (line 64) |
| 5: OIDC wildcard | none exists | STRUCTURALLY CANNOT DETECT | STRUCTURALLY CANNOT DETECT |

Zero false positives on any of the four rules mapped to a planted class, in
either run (`zizmor_default_false_positives_on_mapped_rules` and
`zizmor_auditor_false_positives_on_mapped_rules` in
`evidence/scoring-results.json` are both empty lists).

**The one and only difference between the two runs is class 4.** This is
the headline mechanism finding of this project, not a side note. zizmor's
own module doc for this rule, read directly from
`crates/zizmor/src/audit/self_hosted_runner.rs`, states the reason in one
sentence: "this audit is 'auditor' only, since zizmor can't detect whether
self-hosted runners are ephemeral or not." A default `zizmor` run against
this exact corpus, containing a bare `runs-on: self-hosted` label with no
environment gate, **reports nothing for it**. Anyone running `zizmor .` out
of the box, without knowing to add `--persona=auditor`, would conclude this
workflow is clean. The finding is real, confirmed High confidence and
Medium severity when it does fire (`evidence/zizmor-auditor.json`), and the
tool chooses, by design, not to surface it by default because it cannot
tell an ephemeral self-hosted runner from a persistent one from the YAML
alone. That is a considered design decision on zizmor's part, documented in
its own source, not a bug, but it means the practical default-mode coverage
of class 4 is zero.

### A scoping detail about the cache-poisoning rule, found while building the corpus

The first version of the class 3 "restorer" workflow in this project
triggered on `push: branches: [main]`, an ordinary push to the default
branch. zizmor did not flag it, in either persona. Reading
`crates/zizmor/src/audit/cache_poisoning.rs` directly explained why: the
rule only inspects a cache-aware step inside a job it recognizes as a
**release workflow**, specifically one triggered by a tag push, a `release`
event, a branch name containing the word "release", or the use of a
well-known publisher action such as `softprops/action-gh-release`. A plain
push to `main` matches none of those heuristics. The restorer workflow was
rewritten to trigger on a tag push (`push: tags: ["v*"]`), which does match
the rule's release-workflow definition, and the rule fired immediately at
Medium confidence. This is recorded here because it is itself a finding
about the tool: zizmor's cache-poisoning coverage is scoped to what it
considers a release pipeline, not to every workflow that reads a cache and
executes what it finds.

### Unmapped zizmor findings, recorded, not forced into the count

Both runs produced real findings that do not correspond to any of the five
planted classes. Per this project's own scoring rule, these are recorded as
unmapped, never forced into a true positive or false positive for a class
they were not testing:

- **Default run:** `artipacked` (missing `persist-credentials: false` on
  `actions/checkout`) and `unpinned-uses` (actions referenced by tag,
  e.g. `@v4`, instead of a pinned commit hash). Both are real, valid
  findings about this corpus's supply-chain hygiene; neither is one of the
  five classes this project measures.
- **`--persona=auditor` run, additionally:** `anonymous-definition`,
  `concurrency-limits`, `excessive-permissions`, `secrets-outside-env`,
  `undocumented-permissions`. All are legitimate Auditor-tier findings
  about this corpus, none map to classes 1 through 5.

Full lists: `zizmor_default_unmapped_idents` and
`zizmor_auditor_unmapped_idents` in `evidence/scoring-results.json`.

## Per-class results, OpenSSF Scorecard

OpenSSF Scorecard v5.5.0 (Apache-2.0,
`github.com/ossf/scorecard`), run against the same corpus with
`scorecard --local=. --checks=Dangerous-Workflow --show-details`. Raw
output: `evidence/scorecard-dangerous-workflow.json`.

| Class | Verdict | Detail |
|---|---|---|
| 1: pull_request_target exfil | FLAGGED, file level | `Warn: untrusted code checkout '${{ github.event.pull_request.head.sha }}': .github/workflows/pr-target-exfil.yml:44` |
| 2: script injection | FLAGGED, file level | `Warn: script injection with untrusted input ' github.event.issue.title ': .github/workflows/script-injection.yml:44` |
| 3: cache poisoning | NOT COVERED | `Dangerous-Workflow`'s own documentation names no cache-related sub-check |
| 4: self-hosted runner | NOT COVERED | `Dangerous-Workflow`'s own documentation names no self-hosted-runner sub-check |
| 5: OIDC wildcard | NOT COVERED | No documented check anywhere in Scorecard covers a cloud-side trust policy |

Scorecard's overall `Dangerous-Workflow` score for this repository was
**0 out of 10**, its lowest possible score, driven entirely by classes 1
and 2. Nothing in its raw output mentions caching, self-hosted runners, or
OIDC in any form; `evidence/scorecard-dangerous-workflow.json`'s three
`details` lines are the complete list of what the check reported.

As a secondary comparison, `scorecard --checks=Token-Permissions` was also
run (`evidence/scorecard-token-permissions.json`) and scored this corpus
10 out of 10, correctly noting every workflow scopes `contents: read` at
the top level with no job-level write permissions. This is expected and
not a finding about any of the five classes: none of the five planted
vulnerabilities involves excessive `GITHUB_TOKEN` permissions, so a clean
Token-Permissions score is a true negative, not a missed detection.

## The two structural blindnesses, confirmed empirically

### zizmor cannot detect class 5, and it is not a gap a new rule could close

Confirmed by running zizmor, in both personas, against the full corpus
including `.github/workflows/oidc-debug.yml`: no rule name in either run's
output contains "oidc" or references a subject claim
(`test_zizmor_no_rule_named_oidc_or_sub_claim` in
`tests/test_scanner_evidence.py` checks this directly against the raw
JSON). This is not a weakness in zizmor's rule catalog that a 42nd rule
could patch. zizmor parses GitHub Actions workflow YAML. The vulnerable
artifact for class 5, a wildcard `sub` condition in an AWS, Azure, or GCP
identity trust policy, is not a GitHub Actions YAML file. It lives in a
completely separate system that zizmor has no reason to, and currently has
no mechanism to, ever open. Closing this gap would require zizmor to
ingest a second artifact type from an external cloud API, a materially
different feature than adding a rule.

### Scorecard's Dangerous-Workflow documentation covers exactly two of the five classes

Confirmed by reading Scorecard's own `docs/checks.md` before building this
corpus, then confirmed again empirically: running the check against
workflows for all five classes produced findings naming only class 1
(untrusted checkout) and class 2 (script injection). Scorecard has other,
separately named checks, for example `Token-Permissions`, which was also
run here and correctly found nothing wrong, since none of the five classes
involves that specific concern. But no check in Scorecard's published
documentation claims to look for cache poisoning, self-hosted runner
exposure, or OIDC trust-policy scope. This is Scorecard functioning exactly
as documented, not an implementation bug: it is designed as a small set of
named, high-confidence repo-posture signals, not a general-purpose
vulnerability scanner, and its own documentation never claimed coverage of
the other three classes.

### The default-versus-auditor difference: what a tool declines to report, versus what it cannot see

Class 5 and class 4 look similar from a distance, both are misses in a
zizmor default run, but they are misses for opposite reasons, and that
distinction is the most interesting result in this project. Class 5 is
invisible to zizmor because the vulnerable artifact is outside the file
format zizmor parses; no configuration flag could ever change that, short
of zizmor growing an entirely new capability to read cloud IAM policy.
Class 4 is visible to zizmor, in full, at High confidence, the moment
`--persona=auditor` is added; the rule exists, runs, and fires correctly
against the exact YAML in this corpus, but its own author tagged it
Auditor-persona and left it out of the default output because zizmor
cannot tell, from YAML alone, whether a given self-hosted runner is
ephemeral (and therefore lower-risk) or persistent (and therefore exactly
this class of exposure). One of these is a scanner that cannot see the
bug. The other is a scanner that can see the bug, chooses not to report it
by default, and says exactly why in its own source code.

## Every miss and match, narrated

- **Class 1, both zizmor runs and Scorecard: matched.** All three runs
  independently confirm this is the class both tools were built to catch
  first; GitHub's own secure-use documentation calls out this exact
  pattern by name.
- **Class 2, both zizmor runs and Scorecard: matched.** Same story as
  class 1; both tools implement dedicated logic for untrusted
  template-expression interpolation into shell commands.
- **Class 3, both zizmor runs: matched, with a scoping caveat.** The rule
  only fires when the consuming workflow is shaped like a release
  pipeline (see "A scoping detail," above). A cache-poisoning attack
  against a workflow that does not look like a release, for example a
  plain `push: main` deploy step, would not be caught by this rule as
  currently written, even though the underlying vulnerability (attacker
  writes a cache key, trusted job restores and executes it) is identical.
  **Scorecard: not covered, matches its own documentation exactly.**
- **Class 4, zizmor default: false negative. zizmor auditor: matched.**
  Explained in full above; not a bug, a documented persona choice.
  **Scorecard: not covered, matches its own documentation exactly.**
- **Class 5, both zizmor runs and Scorecard: structurally cannot detect.**
  Explained in full above. This is stated with confidence, not apology:
  the absence of a finding here is the correct, expected behavior of both
  tools given what each one actually parses.

No unmapped scanner finding in this project was force-fit to any of the
five classes. `artipacked` and `unpinned-uses` (zizmor, both runs) and the
additional Auditor-tier findings in the auditor run are real, correctly
scoped findings about this corpus's own supply-chain hygiene, unrelated to
the five planted vulnerability classes, and are recorded as unmapped in
`evidence/scoring-results.json` rather than counted toward or against
either tool's score on this project's actual question.

## Where the numbers come from

| Claim | Evidence file |
|---|---|
| zizmor version 1.30.0 | `evidence/zizmor-version.txt` |
| Scorecard version v5.5.0 | `evidence/scorecard-version.txt` |
| zizmor default-persona raw findings | `evidence/zizmor-default.json`, `evidence/zizmor-default.plain.txt` |
| zizmor auditor-persona raw findings | `evidence/zizmor-auditor.json`, `evidence/zizmor-auditor.plain.txt` |
| Scorecard Dangerous-Workflow raw output | `evidence/scorecard-dangerous-workflow.json` |
| Scorecard Token-Permissions raw output (secondary comparison) | `evidence/scorecard-token-permissions.json` |
| Per-class scored verdicts | `evidence/scoring-results.json`, produced by `scripts/03_score.py` |
| Ground truth (file, line, CWE, rationale per case) | `ground-truth.yml` |
| zizmor cache-poisoning rule's release-workflow scoping | `evidence/cache_poisoning_rule_source.rs` (fetched directly from `zizmorcore/zizmor`) |

## What could not be verified live, and what was judged

- **Class 5's captured OIDC token claims are pending the lab repository's
  first workflow run.** `docs/oidc-trust-policy-analysis.md` documents the
  expected claim shape from GitHub's own published `sub` format and shows
  the wildcard-versus-scoped trust-policy comparison against that expected
  shape. The section will be updated with the real, redacted claims once
  `.github/workflows/oidc-debug.yml` has actually run on GitHub; this
  local-only phase of the project could not trigger it, since the
  workflow requires a real GitHub Actions run to mint a real OIDC token.
  No zizmor or Scorecard result depends on this: both tools were run
  against the workflow YAML as written, which is sufficient to confirm
  neither one has any rule that references OIDC or a subject claim.
- **The CWE mapping for class 4 (CWE-668) is stated as a moderate fit, not
  a strong one**, per the research this project's ground truth cites: CWE
  has no entry specific to a compute resource that is shared across
  untrusted job executions without being truly ephemeral, which is the
  precise mechanism that makes a self-hosted runner risky here.
- **No CWE mapping is claimed for class 5.** Four candidates
  (CWE-1357, CWE-501, CWE-296, CWE-285) were checked directly against
  MITRE's own definitions and rejected or downgraded to "closest weak
  candidate" (CWE-285) rather than reported as a fit. See `ground-truth.yml`
  for the full reasoning per candidate.
- **This project measures detection on a clean, single-vulnerability-per-file
  corpus.** It does not measure how either tool performs against a large,
  messy, real-world workflow file containing many unrelated patterns at
  once, the way `c-static-analysis-rules` measured custom C rules against
  real open-source codebases and found precision collapsing outside a
  synthetic benchmark. That is a legitimate follow-up question this
  project does not answer.
