# Class 5 analysis: OIDC wildcard `sub` trust-policy misconfiguration

This document is analytical only. No cloud account exists for this project,
no IAM role was created, and no cloud role was ever assumed. Nothing in this
file causes any live authorization decision. It exists to show, as a static
comparison, what a wildcard trust-policy condition would match against a
real OpenID Connect (OIDC) token's claims, once those claims are captured.

## Background: what OIDC and the `sub` claim are, for a non-expert reader

OIDC (OpenID Connect) lets a GitHub Actions workflow request a short-lived,
cryptographically signed identity token from GitHub, without storing any
long-lived cloud credential in the repo. A cloud provider (AWS, Azure, GCP)
can be configured to trust GitHub's OIDC issuer and grant access based on
claims inside that token, most importantly the `sub` (subject) claim.
GitHub's documented default format for `sub` is:

```
repo:<ORG>/<REPO>:ref:refs/heads/<BRANCH>
```

(or an equivalent form for other trigger types, e.g. pull requests use
`repo:<ORG>/<REPO>:pull_request`). A cloud-side trust policy is supposed to
match this string exactly (or with a narrow, intentional pattern) so that
only workflows running in the intended repository and branch can assume the
role. Source:
https://docs.github.com/en/actions/reference/openid-connect-reference

## The misconfiguration this class demonstrates

A trust policy that uses a wildcard match on `sub`, for example an AWS IAM
trust policy condition using `StringLike` with a value like
`repo:wmshearer/*:*`, trusts every repository and every ref/event type under
that account, not just the one workflow that is supposed to be allowed to
assume the role. Any workflow in any repository under that wildcard scope,
including one on an attacker-controlled fork or branch if the account ever
hosts one, can present a token whose `sub` claim matches the wildcard and
assume the role.

The correctly scoped alternative uses `StringEquals` with the exact `sub`
value for one specific repository and branch (or the pull_request form),
so a token from any other repository or branch is rejected outright.

## Capturing a real token's claims

`.github/workflows/oidc-debug.yml` runs GitHub's own official
`github/actions-oidc-debugger` action
(https://github.com/github/actions-oidc-debugger), which requests a real
OIDC token from GitHub's provider and prints its decoded claims to the job
log. No cloud provider is contacted. This is the only live action taken for
class 5; everything after this point is static comparison against the
printed claims.

**Status: pending first workflow run.** This section will be filled in with
the real, redacted claims once the lab repository exists on GitHub and the
`oidc-debug.yml` workflow has been run once via `workflow_dispatch`. Per the
project's own rule (see README.md), any real token signature value is
redacted before being committed; only the claims structure (`sub`, `aud`,
`repository`, `ref`, `event_name`) is preserved, because the claims
structure is the interesting part for this analysis, not the signature.

Expected shape, based on GitHub's documented default `sub` format for a
`workflow_dispatch` run on the repository's default branch:

```
sub: repo:wmshearer/actions-security-lab:ref:refs/heads/main
aud: https://github.com/wmshearer
repository: wmshearer/actions-security-lab
repository_owner: wmshearer
event_name: workflow_dispatch
ref: refs/heads/main
```

## Static comparison: wildcard versus scoped trust policy

Given a captured `sub` claim of the form above, here is a sample (never
applied, never assumed) AWS IAM trust policy fragment showing the
misconfigured wildcard version next to the correctly scoped version.

### Misconfigured: wildcard `sub` match (illustration only, never created)

```json
{
  "Effect": "Allow",
  "Principal": { "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": { "token.actions.githubusercontent.com:aud": "https://github.com/wmshearer" },
    "StringLike": { "token.actions.githubusercontent.com:sub": "repo:wmshearer/*:*" }
  }
}
```

This condition matches the captured `sub` claim
(`repo:wmshearer/actions-security-lab:ref:refs/heads/main`) because
`repo:wmshearer/*:*` is a wildcard over every repository owned by
`wmshearer` and every ref/event suffix. It would equally match a token
minted by any other repository in the same account, or by any branch or
pull request event in this repository, not just the one intended workflow.

### Correctly scoped: exact `sub` match

```json
{
  "Effect": "Allow",
  "Principal": { "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "https://github.com/wmshearer",
      "token.actions.githubusercontent.com:sub": "repo:wmshearer/actions-security-lab:ref:refs/heads/main"
    }
  }
}
```

This condition matches only a token whose `sub` claim is exactly this
string: this specific repository, on this specific branch. A token from any
other repository, branch, or event type is rejected.

## What this analysis does and does not prove

It proves: a real OIDC token's claims, captured from this lab's own
workflow run, would satisfy the wildcard condition above, as a matter of
string matching. It does not prove: that any cloud role was assumed, that
any IAM role exists, or that this account has ever had cloud access of any
kind. No `aws-actions/configure-aws-credentials` step, or equivalent for
any other cloud provider, appears anywhere in this repository.

## Why neither scanner in this project's scope can detect this class

Both zizmor and OpenSSF Scorecard operate by reading GitHub Actions workflow
YAML files. The misconfiguration described in this document lives entirely
in a cloud provider's IAM trust policy, a resource that does not exist in
this repository (or in most repositories) as a file zizmor or Scorecard
would ever parse. This is not a coverage gap that a new rule could close
inside either tool's current design; it would require the tool to ingest a
second artifact type from a completely different system (an AWS/Azure/GCP
API or exported policy document), which is outside what either tool does
today. See FINDINGS.md for the empirical confirmation.
