# Ransomware readiness rubric

A scored self-assessment. The categories come from published government guidance.
The scoring model does not, and that is stated here rather than implied away.

## Where the structure comes from

**Categories** follow CISA's Cross-Sector Cybersecurity Performance Goals v2.0
(December 2025), which restructured around the six CSF 2.0 Functions: Govern,
Identify, Protect, Detect, Respond, Recover.

**Control content** draws on the #StopRansomware Guide v3.0 (October 2023),
published jointly by CISA, FBI, NSA and MS-ISAC. It organises prevention by
initial access vector and response as a sequential checklist.

**Risk framing** follows NIST IR 8374 Revision 1, "Ransomware Risk Management: A
Cybersecurity Framework 2.0 Community Profile", finalised June 2026. It
supersedes the February 2022 original, which was written against CSF 1.1.

## Two things worth knowing before using this

**The scoring model is invented.** No CISA or NIST document publishes a numeric
ransomware maturity score. The #StopRansomware Guide is a checklist with no
weighting or tiers. CISA's Ransomware Readiness Assessment inside CSET does
produce a tiered result, but CSET is a desktop application rather than a
published rubric, so its question bank could not be cited from a primary source.

So the weights below are mine. They are defensible and they are not authoritative,
and anyone using this should adjust them to their own environment rather than
treat the number as a standard.

**The Guide's own cross-references are stale.** #StopRansomware v3.0 cites CPGs
using the version 1 numbering (`[CPG 2.R]`, `[CPG 1.A]`). CPG v2.0 renumbered
around the six Functions. The Guide has not been updated to match, so those
citations are re-mapped here rather than copied across.

## The rubric

Each control scores 0, 1 or 2.

- **0** — not in place
- **1** — partially in place, or in place without verification
- **2** — in place and verified within the last 12 months

The verification requirement in the top score is deliberate. Backups that have
never been restored from are the single most common finding in ransomware
post-incident reviews, and an unverified control is a plan rather than a defence.

### Govern (weight 1.0)

| # | Control |
|---|---|
| G1 | A named owner is accountable for ransomware readiness |
| G2 | An incident response plan exists and names decision authority for paying or refusing a ransom |
| G3 | Legal, communications and law enforcement contacts are established before an incident |
| G4 | Cyber insurance coverage and its notification requirements are understood |

### Identify (weight 1.0)

| # | Control |
|---|---|
| I1 | An asset inventory exists and is current |
| I2 | Crown-jewel systems and data are identified and prioritised for recovery |
| I3 | External attack surface is enumerated and reviewed on a schedule |
| I4 | Third-party and managed service provider access is inventoried |

### Protect (weight 1.5)

Weighted highest because prevention removes the incident rather than managing it.

| # | Control |
|---|---|
| P1 | Multi-factor authentication is enforced on all remote access and privileged accounts |
| P2 | Internet-facing services are patched on a defined schedule with emergency provision |
| P3 | Backups exist, are offline or immutable, and are segmented from production credentials |
| P4 | **Restoration from backup has been tested end to end within 12 months** |
| P5 | Network segmentation limits lateral movement from a single compromised host |
| P6 | Privileged accounts are separated from daily-use accounts |
| P7 | Macro execution from internet-sourced documents is blocked by policy |

### Detect (weight 1.25)

| # | Control |
|---|---|
| D1 | Endpoint telemetry is collected centrally and retained for at least 90 days |
| D2 | Detection content covers the techniques ransomware families actually use |
| D3 | Alerts reach a human who is resourced to act on them |
| D4 | Detection coverage is measured rather than assumed |

D2 and D4 are what the measurement half of this project addresses.

### Respond (weight 1.0)

| # | Control |
|---|---|
| R1 | Isolation procedures can be executed without the network being available |
| R2 | An out-of-band communication channel exists for use when systems are down |
| R3 | Response roles are assigned and exercised |
| R4 | Evidence preservation is defined before systems are rebuilt |

### Recover (weight 1.25)

| # | Control |
|---|---|
| C1 | Recovery time objectives are defined per system and known to be achievable |
| C2 | Rebuild procedures exist for critical systems |
| C3 | A post-incident review process exists and produces changes |

## Scoring

```
category score = sum(control scores) / (2 * control count)
overall       = sum(category score * weight) / sum(weights)
```

Reported as a percentage per category and overall. The per-category figures
matter more than the total: an organisation at 90% overall with a 40% Recover
score has a specific problem that the total hides.

That is the same failure mode the abuse-program-metrics project documented, where
a pooled score of 0.014 concealed one stratum at 0.695 and another at -0.693.

## What this cannot tell you

It is a self-assessment. Every answer is the assessor's own, and the difference
between "we have backups" and "we have restored from them" is exactly the
difference this rubric tries to force and cannot enforce.

It does not model a specific threat actor, sector, or regulatory obligation.

A high score is not a prediction. Organisations with mature controls are
ransomed, and the controls change how far the incident gets rather than whether
it starts.
