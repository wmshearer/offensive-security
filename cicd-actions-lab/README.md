# cicd-actions-lab

A small, purpose-built corpus of five known GitHub Actions vulnerabilities,
built to answer one question: what do two real security scanners,
**zizmor** and **OpenSSF Scorecard**, actually detect when pointed at code
with a known answer key?

## Scope, stated up front

This is a purpose-built lab in a **private** repository, not a production
codebase and not a public challenge. Every vulnerability here is planted on
purpose, documented in `ground-truth.yml`, and safe by construction:

- Classes 1, 2, and 3 (defined below) are real, working GitHub Actions
  workflows that can be triggered and observed.
- Class 4 (self-hosted runner) is planted as YAML only and **has never been
  executed**. No self-hosted runner has been or will be registered on any
  machine for this project.
- Class 5 (OIDC misconfiguration) is **analytical only**. No cloud account
  exists for this project and no cloud role is ever assumed. A real OpenID
  Connect token's claims are captured and compared, on paper, against a
  sample trust-policy string.

## The five vulnerability classes

Each term is defined here on first use, for a reader who has not worked
with GitHub Actions security before.

1. **`pull_request_target` secret exfiltration.** `pull_request_target` is a
   workflow trigger that runs with the permissions and secrets of the
   repository's default branch, even when the workflow was triggered by a
   pull request from a different, less-trusted branch. If that workflow
   also checks out the pull request's own code, the untrusted code runs
   with privileged access, including to repository secrets.
   `.github/workflows/pr-target-exfil.yml`.

2. **Script injection via `github.event`.** GitHub Actions lets a workflow
   read fields from the event that triggered it, for example an issue's
   title (`github.event.issue.title`). If that field is pasted directly
   into a shell command instead of passed through an environment variable
   first, an attacker who controls the field's contents (anyone who can
   open an issue) can inject arbitrary shell commands into that step.
   `.github/workflows/script-injection.yml`.

3. **Actions cache poisoning.** GitHub Actions lets a workflow save and
   restore a cache of files between runs, keyed by a string the workflow
   author chooses. If a low-privilege, easily triggered workflow can write
   to a cache key that a later, higher-privilege release workflow trusts
   and restores without checking, an attacker can plant content in the
   cache that the release workflow later executes.
   `.github/workflows/cache-poison-write.yml` and
   `.github/workflows/cache-poison-restore.yml`.

4. **Self-hosted runner with no isolation.** A GitHub Actions "runner" is
   the machine that executes a workflow's jobs. GitHub provides free,
   disposable, cloud-hosted runners by default; a "self-hosted" runner is a
   machine the repository owner supplies instead, which is not disposable
   between jobs the same way. If a workflow that uses a self-hosted runner
   can be triggered by an untrusted pull request, and nothing gates the job
   behind manual approval, anyone who can open that pull request can run
   code on that machine. `.github/workflows/self-hosted-runner-pattern.yml`
   plants exactly this pattern and never runs it. See "Safety and scope"
   below for why.

5. **OIDC wildcard `sub` trust-policy misconfiguration.** OIDC (OpenID
   Connect) lets a GitHub Actions workflow request a short-lived, signed
   identity token from GitHub, so a cloud provider (AWS, Azure, GCP) can
   grant access without a long-lived credential stored in the repo. The
   token's `sub` (subject) claim identifies which repository and branch
   requested it. If the cloud-side trust policy matches `sub` with a
   wildcard instead of an exact value, any workflow in the wildcard's scope
   can assume the role, not just the one intended. This class is analyzed
   in `docs/oidc-trust-policy-analysis.md`, using a real token's claims
   captured by `.github/workflows/oidc-debug.yml`, with no cloud account
   involved at any point.

## Safety and scope

- **No data leaves GitHub.** The class 1 "exfiltration" sink is a GitHub
  Actions artifact, not a third-party server. Nothing is posted to any
  external endpoint anywhere in this repository.
- **Every secret is a dummy.** The one secret this lab uses is named
  `DUMMY_API_KEY_DO_NOT_USE`, an inert placeholder string, never a real
  credential.
- **Class 4 is planted, not executed.** GitHub's own security guidance
  states that a self-hosted runner reachable by a pull request can be
  compromised by anyone who can open that pull request, and this applies to
  private repositories too, not only public ones. Registering a real
  self-hosted runner to demonstrate this class would mean an
  internet-reachable process on a real machine could execute
  attacker-influenced code. That risk is categorically different from
  classes 1, 2, 3, and 5, which execute only inside GitHub-hosted,
  disposable virtual machines. This lab plants the vulnerable YAML pattern
  and never triggers it. Both scanners under test read workflow files
  statically, they do not execute a workflow to produce a finding, so this
  choice does not weaken the measurement.
- **Class 5 never touches a cloud account.** No AWS, Azure, or GCP account
  exists for this project. `docs/oidc-trust-policy-analysis.md` states this
  explicitly and shows the misconfiguration as a static string comparison
  only.
- **This repository is private.** A public repository containing working
  `pull_request_target` and script-injection workflows could be forked and
  probed by strangers; keeping the lab private removes that risk entirely.

## Prior art considered and why this lab was built fresh

`step-security/github-actions-goat` (Apache-2.0,
https://github.com/step-security/github-actions-goat) is an existing,
actively maintained GitHub Actions security training repository. Its own
`docs/Vulnerabilities/` directory contains exactly three documents:
`ExfiltratingCICDSecrets.md`, `OverprivilegedGITHUB_TOKEN.md`, and
`TamperingDuringBuild.md`. None of them is a dedicated, named scenario for
cache poisoning, self-hosted runner compromise, or OIDC trust-policy
misconfiguration, and neither `pull_request_target` nor `github.event`
script injection is named as its own scenario either; they are at best
implicit inside the broader secret-exfiltration document. This lab was
built fresh specifically to cover classes 3, 4, and 5, which Goat's own
documentation index does not address, and to pair each of the five classes
with a machine-readable ground-truth manifest built for exact scoring,
which Goat's walkthrough-style content was not built for.

## Repository layout

```
.github/workflows/        the six workflow files (five classes, class 3 has two files)
docs/oidc-trust-policy-analysis.md    class 5 static analysis
ground-truth.yml          machine-readable manifest: every planted case, file, line, CWE, rationale
scripts/01_run_zizmor.sh  runs zizmor, default and --persona=auditor, writes evidence/
scripts/02_run_scorecard.sh   runs OpenSSF Scorecard --local, writes evidence/
scripts/03_score.py       computes per-class results from ground truth + raw evidence
evidence/                 raw tool output; every number in FINDINGS.md traces to a file here
tests/                    pytest suite, 60 tests
FINDINGS.md               the results and what they mean
```

## Reproducing the scan

```
pipx install zizmor            # installs zizmor 1.30.0 (MIT license)
go install github.com/ossf/scorecard/v5@v5.5.0   # OpenSSF Scorecard (Apache-2.0)

./scripts/01_run_zizmor.sh
./scripts/02_run_scorecard.sh
python3 scripts/03_score.py

python3 -m pytest tests/ -v
```

All three scan/score steps run entirely offline against the YAML files on
disk. No GitHub Actions minutes are consumed by running the scanners
themselves; minutes are only consumed if the workflows in
`.github/workflows/` are actually triggered on GitHub (see FINDINGS.md for
which classes were run live).

## See also

`FINDINGS.md` for what the scanners actually found, per class, per tool,
including the default-versus-`--persona=auditor` zizmor comparison and the
two structural blindnesses this project set out to confirm.
