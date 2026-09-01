# Class 5 analysis: OIDC wildcard `sub` trust-policy misconfiguration

This document is analytical only. No cloud account exists for this project,
no IAM role was created, and no cloud role was ever assumed. Nothing in this
file causes any live authorization decision. It shows, as a static
comparison, what a wildcard trust-policy condition would match against the
claims of a real OpenID Connect (OIDC) token captured from this repository's
own GitHub Actions run.

## Background: what OIDC, a claim, `sub`, a trust policy, and a wildcard are

OIDC (OpenID Connect) lets a GitHub Actions workflow request a short-lived,
cryptographically signed identity token from GitHub, without storing any
long-lived cloud credential in the repo. That token is a JSON Web Token
(JWT) made of a header, a payload, and a signature. The payload contains
**claims**: individual pieces of information about who and what requested
the token, such as which repository and branch ran the workflow. A cloud
provider (AWS, Azure, GCP) can be configured to trust GitHub's OIDC issuer
and grant access based on those claims, most importantly the **`sub`**
(subject) claim, which identifies the workflow run that requested the
token. The cloud-side configuration that decides which `sub` values (and
other claims) are allowed to obtain access is called a **trust policy**. A
**wildcard** is a pattern character, typically `*`, that matches any
sequence of characters in that position, so a trust policy condition
written with a wildcard matches every value that fits the pattern, not
just one specific value.

## The real captured token

`.github/workflows/oidc-debug.yml` ran on GitHub Actions (run
`33453971610`) and requested a real OIDC token directly from GitHub's
provider using `curl` against the `ACTIONS_ID_TOKEN_REQUEST_URL`, then
decoded and printed the token's payload to the job log. No cloud provider
was contacted at any point. The decoded payload is committed at
`evidence/oidc/claims_raw.json`. That file contains no signature, only the
decoded claims payload, so nothing in it is a usable, replayable
credential; the token itself also expired shortly after the run (its `exp`
claim is a five-minute window past `iat`). The fields relevant to this
analysis, quoted exactly from that file:

```
sub:                     repo:wmshearer@241811240/cicd-actions-lab@1352963523:ref:refs/heads/master
iss:                     https://token.actions.githubusercontent.com
aud:                     https://github.com/wmshearer
repository:              wmshearer/cicd-actions-lab
repository_id:           1352963523
repository_owner:        wmshearer
repository_owner_id:     241811240
repository_visibility:   public
job_workflow_ref:        wmshearer/cicd-actions-lab/.github/workflows/oidc-debug.yml@refs/heads/master
ref:                     refs/heads/master
ref_protected:           false
ref_type:                branch
runner_environment:      github-hosted
```

## The `sub` format includes numeric IDs, not just names, and here is why

wmshearer's captured `sub` is:

```
repo:wmshearer@241811240/cicd-actions-lab@1352963523:ref:refs/heads/master
```

This is not the plain `repo:<owner>/<repo>:ref:refs/heads/<branch>` form
that most existing documentation and blog posts show. It embeds two
numeric IDs: `241811240` (wmshearer's account ID) after the owner name, and
`1352963523` (the repository ID) after the repository name, joined with
`@`.

This was verified directly against GitHub's own current OpenID Connect
reference documentation
(`https://docs.github.com/en/actions/reference/security/oidc`, fetched
2026-08-31), which confirms this is neither an accident nor a
repository-level customization someone configured. GitHub shipped this as
a new default, called **immutable subject claims**, announced in an
April 2026 changelog post
(`https://github.blog/changelog/2026-04-23-immutable-subject-claims-for-github-actions-oidc-tokens/`)
and rolled out starting July 15, 2026. Quoting the reference doc directly:

> Previous format example: `repo:octo-org/octo-repo:ref:refs/heads/main`
> Immutable format example: `repo:octo-org@123456/octo-repo@456789:ref:refs/heads/main`
>
> The `@` separator is used between names and IDs because `@` cannot
> appear in GitHub usernames or repository names.
>
> Repositories created before July 15, 2026 keep the previous format
> unless you opt in to immutable subject claims. Repository renames and
> transfers after July 15, 2026 also move to the immutable subject format.

This repository (`wmshearer/cicd-actions-lab`) was created 2026-08-31,
after the July 15, 2026 cutover, which is why its captured `sub` shows the
new immutable format automatically, with no opt-in action taken by
wmshearer. GitHub's stated motivation, per the same changelog, is exactly
the security property this analysis cares about: a plain name-based `sub`
is vulnerable to **namespace reuse**. If wmshearer's account or this
repository were ever deleted and its name later claimed by someone else,
a trust policy matching on the name alone would trust the new owner's
workflows as if they were wmshearer's, because the name is identical even
though the underlying account and repository are not. The numeric IDs
(`241811240`, `1352963523`) are permanent identifiers GitHub never
reassigns, so a trust policy matching on the ID-embedded form cannot be
satisfied by a same-named impostor. This is a real security improvement in
GitHub's default, confirmed against GitHub's own documentation, not an
inference drawn from the token alone.

The rest of this analysis works from wmshearer's real captured `sub`,
in the immutable format, since that is what was actually issued. Everything
below still applies to the older plain-name format too, wherever a
repository has not yet moved to the immutable format; the wildcard
problem described here is orthogonal to which `sub` format is in use.

## Correctly-pinned trust policy: matches this repository and ref, nothing else

Using wmshearer's real captured claims, a correctly scoped AWS IAM trust
policy condition looks like this (illustration only; never created, never
applied):

```json
{
  "Effect": "Allow",
  "Principal": { "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "https://github.com/wmshearer",
      "token.actions.githubusercontent.com:sub": "repo:wmshearer@241811240/cicd-actions-lab@1352963523:ref:refs/heads/master"
    }
  }
}
```

`StringEquals` requires an exact match. A token from any other repository,
any other branch, or any other owner is rejected outright, and because
this condition uses the immutable, ID-embedded form, it also survives a
future rename of either the account or the repository.

The condition key names above, `token.actions.githubusercontent.com:sub`
and `token.actions.githubusercontent.com:aud`, were verified directly
against GitHub's own AWS OIDC configuration guide
(`https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services`,
fetched 2026-08-31), which uses both exact key names in its worked
`StringEquals` example, and against AWS's own IAM condition-key
reference for identity federation.

## Wildcard conditions that are too broad, from most to least dangerous

Each variant below is illustration only, never created, never applied. All
are evaluated against wmshearer's one real captured `sub`,
`repo:wmshearer@241811240/cicd-actions-lab@1352963523:ref:refs/heads/master`,
to show concretely what each additionally matches beyond the intended case.

### 1. Wildcard on the entire subject

```json
"StringLike": { "token.actions.githubusercontent.com:sub": "repo:*" }
```

This matches wmshearer's `sub`, and it also matches every `sub` any
GitHub Actions OIDC token can ever produce, for any account, any
repository, any branch, tag, environment, or pull request, anywhere on
GitHub, as long as the token's issuer (`iss`) and audience are also
accepted. This is the most dangerous variant: it removes claim-based
identity checking entirely and relies on nothing but the fact that a
token came from GitHub's OIDC issuer at all.

### 2. Wildcard on the owner

```json
"StringLike": { "token.actions.githubusercontent.com:sub": "repo:wmshearer@241811240/*" }
```

This matches wmshearer's `sub`, and it also matches a token minted by
any other repository under wmshearer's account, on any branch, tag,
environment, or event type. If wmshearer's account ever hosts more than
one repository, every workflow in every one of them, including a
throwaway test repository or a fork wmshearer forgot about, can assume
this role.

### 3. Wildcard on the ref

```json
"StringLike": { "token.actions.githubusercontent.com:sub": "repo:wmshearer@241811240/cicd-actions-lab@1352963523:ref:*" }
```

This matches wmshearer's `sub` (`ref:refs/heads/master`), and it also
matches every branch and every tag in this one repository. That includes
a branch an outside contributor creates by opening a pull request, since
opening a PR from a fork causes GitHub to run workflows against a ref
tied to the contributor's own branch in many trigger configurations, and
it includes any short-lived branch a compromised or careless collaborator
pushes. Pinning the repository correctly still leaves the ref wide open,
so anyone who can create a branch or tag in, or a PR against, this
repository can potentially mint a token that satisfies this condition.

### 4. Matching `repository` without pinning `ref`

Some trust-policy designs use a custom claim mapping or a job that checks
`repository` (`wmshearer/cicd-actions-lab`) but leaves `ref` unconstrained,
either because the policy author only matched part of `sub` or configured
a custom claims condition against `repository` alone. This has the same
effect as case 3 above: the repository is pinned correctly, but nothing
distinguishes the protected `master` branch from a branch anyone with
write or PR access can create. A trust policy is only as strong as its
least-constrained claim; pinning `repository` while leaving `ref`
unconstrained is functionally a ref-wildcard, worded differently.

## The `aud` claim's role

wmshearer's real captured `aud` is `https://github.com/wmshearer`. `aud`
(audience) states who the token is intended for, that is, which specific
cloud identity provider configuration is meant to accept it. A trust
policy is supposed to validate `aud` alongside `sub`, confirming the token
was issued for this specific integration and not for some other consumer
of GitHub's OIDC tokens.

If a trust policy omits the `aud` check entirely, or uses a wildcard on
it, a token that GitHub issued for a completely different purpose (for
example, a different cloud integration configured with a different
custom audience string on the same GitHub account) could be replayed
against this trust policy, provided the attacker also controlled a `sub`
value the policy would accept. Requiring an exact `aud` match closes that
door regardless of what `sub` says, so `aud` and `sub` are meant to be
checked together, not as substitutes for each other. Neither claim alone
is a sufficient trust-policy condition.

## `ref_protected: "false"`: why a pinned ref is weaker than it looks

wmshearer's real captured claims include `"ref_protected": "false"`,
meaning `refs/heads/master` in this repository has no branch protection
rule configured (no required reviews, no restriction on who can push).
`ref_protected` is itself one of the claims GitHub includes in the token,
precisely so a trust policy or its administrator can account for this.

A trust policy pinned exactly to `ref:refs/heads/master`, using
`StringEquals` as shown in the correctly-pinned example above, is
correctly scoped as a string match. But if that ref is not protected, the
match being narrow does not mean the population of people who can produce
a token satisfying it is narrow. Anyone with push access to this
repository can push a commit directly to `master` and trigger a workflow
run there, producing a token with exactly this `sub`. On a public
repository (wmshearer's is `repository_visibility: public`), depending on
the workflow's trigger configuration, this can extend further: a
workflow triggered on events tied to a pull request, run against an
unprotected branch, can be influenced by a wider set of people than the
repository's own collaborators. A `ref` pin is a necessary control, not a
sufficient one; it is only as strong as the protection on the branch or
tag it names.

## Applies beyond AWS

AWS IAM trust-policy syntax is used above because it is the most common
target for this integration, and because its condition-key names could be
verified directly against AWS's own documentation. Azure (federated
credential subject identifier matching) and GCP (Workload Identity
Federation attribute-condition expressions written in CEL, for example
`assertion.sub=='repo:...'`) both implement the identical class of issue
with different configuration syntax: whatever expression matches the
`sub` claim can be written too broadly, and whatever claim carries
audience information can be left unchecked, in either provider's syntax
just as easily as in AWS's.

## What this analysis does and does not prove

It proves: wmshearer's real OIDC token, captured from this repository's
own workflow run, has the exact claim values quoted above, and each
wildcard and omission pattern shown here would, as a matter of string
matching, accept a token carrying those values or a broader set of
values than the correctly-pinned policy would. It does not prove that any
cloud role was assumed, that any IAM role exists, or that this account has
ever had cloud access of any kind. No `aws-actions/configure-aws-credentials`
step, or equivalent for any other cloud provider, appears anywhere in this
repository.

## Why neither scanner in this project's scope can detect this class

Both zizmor and OpenSSF Scorecard operate by reading GitHub Actions
workflow YAML files. The misconfiguration described in this document lives
entirely in a cloud provider's IAM trust policy, a resource that does not
exist in this repository, or in most repositories, as a file zizmor or
Scorecard would ever parse. This is not a coverage gap a new rule could
close inside either tool's current design; it would require the tool to
ingest a second artifact type from a completely different system (an
AWS, Azure, or GCP API or exported policy document), which is outside
what either tool does today. The claim values in this document are now
the real values from an actual run, not a hypothetical example, which
shows exactly what that blind spot means in practice. See FINDINGS.md for
the empirical confirmation that neither tool's output references OIDC or
a subject claim anywhere.
