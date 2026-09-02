# Findings

The product-security question is not "does this component have a CVE." It is "are
we exposed, where, and how fast can we tell." This works that question end to end
against a service image, using a bug I found and reported upstream so the answer
can be checked rather than argued.

## The short version

A scanner found **160 vulnerabilities** in the image, 7 of them Critical.

It found **zero** in `gguf 0.19.0`, the one component in that image I can
demonstrate is exploitable, because I found the bug myself and reported it as
[llama.cpp PR #28131](https://github.com/ggml-org/llama.cpp/pull/28131).

Sending the malicious input to the running container occupies the parser for
**19.7 seconds** on a 5 MB upload. After the fix, the same input is rejected in
**0.00 seconds**.

So the scan result and the exposure are close to unrelated. A team that triaged
this image by severity would have spent its week on the 7 Criticals and shipped
the one thing an attacker can actually reach.

## The image

An ordinary model-inference service: Python 3.11, FastAPI, uvicorn, requests,
numpy, and `gguf`, the library that reads GGUF model files. One endpoint accepts an
uploaded model and returns what its header says.

That endpoint is the whole exposure story. It parses a file that came from outside,
which is what turns a parser bug into a product-security question rather than a
library curiosity.

## Step 1: what is actually in the image

```
syft inference-service:1.0 -o json
142 packages
gguf 0.19.0 python
```

The SBOM is the part most teams already have. It answers "where is this component"
across a fleet, which is the first question asked when a vulnerability lands.

## Step 2: what the scanner thinks

```
grype inference-service:1.0
160 findings

  Critical    7
  High       28
  Medium     61
  Low        11
  Negligible 45
  Unknown     8

findings for gguf 0.19.0:  0
```

Nothing for `gguf`. That is not the scanner being broken. It is the scanner being
honest: no CVE has been assigned, no advisory has been published, so there is
nothing in the database to match. A scanner reports known vulnerabilities in known
components, and it cannot tell you about a bug that has been reported upstream but
not yet catalogued.

**The absence of a finding is not evidence of safety.** It is evidence of absent
data, and those are different things that look identical in a dashboard.

## Step 3: send the input and watch

The only way to settle it is to exercise the code path. The input is the one from
PR #28131: a GGUF file declaring an array of 5,000,000 `FLOAT64` elements it cannot
possibly hold.

```
file size:         5,200,057 bytes
declared elements: 5,000,000 FLOAT64
bytes they need:   40,000,000
bytes available:   5,200,008

parse result:      parsed with no error
time taken:        19.68s
```

Run inside the shipped container, not against a local checkout. The parser accepts
a file whose declared contents need 40 MB when only 5 MB exist, and loops once per
declared element rather than once per byte present.

## Step 4: how bad, in numbers a team can act on

"It is slow" is not actionable. What matters is whether the attacker pays
proportionally for the damage, and here they do not.

| Upload size | Declared elements | Parse time | Cost to the server |
|---|---|---|---|
| 260,057 | 250,000 | 0.96s | 3.87 s/MB |
| 1,040,057 | 1,000,000 | 3.82s | 3.85 s/MB |
| 2,600,057 | 2,500,000 | 9.68s | 3.90 s/MB |
| 5,200,057 | 5,000,000 | 19.69s | 3.97 s/MB |

The ratio holds at roughly **3.9 seconds of server CPU per megabyte uploaded**, and
it is stable across two orders of magnitude, so it extrapolates. A single client on
a 10 Mbit connection can generate work faster than one worker process can retire
it. This does not need a botnet.

That number is the one worth carrying to an engineering team. It converts "a
parser is slow" into "one client saturates a worker", which is a scheduling and
capacity argument rather than a code-style argument.

## Step 5: prove the fix works in the artifact

The patch note is not the evidence. Building the fixed image and re-running the
input is.

| | Shipped image | Patched image |
|---|---|---|
| Result | parsed with no error | `ValueError` |
| Time | 20.04s | 0.00s |

And the other direction, which matters more than the first: a fix that stops the
attack and also rejects real models is an outage, not a fix.

```
valid files tested:  55
wrongly rejected:    0
```

Every scalar array type at lengths 0, 1, 5, 64 and 5,000 parses unchanged.

## What this says about triage

The image has 7 Critical findings from the scanner. Every one of them is real, and
every one is in a base-image package that is not reachable from the service's only
endpoint. The one bug that *is* reachable, that takes untrusted input on the
request path, and that has a working exploit, has no severity rating at all
because nobody has assigned it one.

Severity is a property of a vulnerability. Exposure is a property of your
deployment. Ranking work by the first and calling it risk management is how a team
ends up patching a library it never calls while shipping the parser on its upload
endpoint.

The useful question is the reachability one: which of these components does
untrusted input actually touch? That question needs the SBOM, the scanner, and
somebody who has read the service. The tools answer two thirds of it.

## Deliberately not claimed

- **This is not a CVE and should not be called one.** It is a reported upstream
  bug with an open pull request. As of writing, PR #28131 has had one round of
  maintainer review, the first version of the patch was rejected as incorrect, and
  a revised version is under review.
- **The service is mine.** It was written for this exercise to have a realistic
  place to put the component. No third-party product was tested.
- **The 3.9 s/MB figure is from one machine**, single-threaded, with no
  concurrency. Real capacity depends on worker count, request timeouts, and
  whatever sits in front of the service. An upload size cap or a request timeout
  would blunt this considerably, and a real assessment would say so to the team.
- **160 findings is not a criticism of grype.** It reported what is in its
  database, correctly. The gap is structural: a bug reported upstream last week
  cannot be in any scanner's data, and that is a permanent property of the model
  rather than a bug to be fixed.
- **No third-party image or registry was scanned**, and no vulnerability was
  reported to anyone as a result of this work.
