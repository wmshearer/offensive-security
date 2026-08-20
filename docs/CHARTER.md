# Red Team Program Charter

**Organization:** Meridian Defense Systems
**Document owner:** Chief Information Security Officer
**Classification of this document:** Internal, Controlled Unclassified Information
**Version:** 1.0
**Review cycle:** Annual, or on any material change to scope or authority

> This is a sample charter written to demonstrate how a red team program is designed and
> governed. Meridian Defense Systems is fictional. The frameworks, controls, and standards
> it cites are real, and each citation was checked against its primary source.

---

## 1. Purpose, Mission, and Mandate

Meridian Defense Systems runs classified programs for federal customers. A control that is
never tested is a control that is only assumed to work. The red team program exists to test
that assumption by emulating a real adversary against Meridian's own defenses, and to measure
whether the organization can detect and respond to that adversary before it reaches a
protected asset.

The program does not exist to find as many vulnerabilities as possible. It exists to answer
one question: could a capable adversary reach a crown-jewel asset without Meridian noticing
and responding in time? That question is about the Detect and Respond functions of the
organization, not about the count of open findings.

The mandate is set under NIST SP 800-53 Rev 5, control **CA-8 (Penetration Testing)** and its
enhancement **CA-8(2) (Red Team Exercises)**, which requires the organization to "employ ...
red-team exercises to simulate attempts by adversaries to compromise organizational systems
in accordance with applicable rules of engagement." The rules of engagement in Section 5 are
therefore not optional paperwork. They are how the program satisfies the control.

## 2. Authority and Executive Sponsorship

The program is chartered by the Chief Information Security Officer with the endorsement of the
Chief Executive Officer, who holds legal authority over the systems in scope. That authority
is what separates an authorized exercise from a crime. No engagement begins without a written
authorization signed by a sponsor whose authority covers every system named in scope.

The sponsor approves this charter before any work begins, approves the scope of each
engagement, and is the only party who can expand or restrict that scope mid-cycle. The
authorization for each engagement, described in Section 5, carries the sponsor's signature and
a defined start and end date.

## 3. Program Type

Meridian runs three related but distinct assurance activities. The charter states which one
this program is, because confusing them leads to the wrong scope and the wrong measure of
success.

- **Vulnerability assessment** is broad and mostly automated. It answers "what is exposed?"
- **Penetration testing** is goal-directed exploitation within an agreed scope. It answers
  "what is exploitable, and what is the real impact?"
- **Red teaming** is objective-focused adversary emulation that also tests whether the
  defenders notice. It answers "could an adversary reach the objective without us stopping
  them?"

This is a **red team program**. The authoritative distinction it rests on is in NIST SP
800-53, which treats general penetration testing (CA-8) and red team exercises (CA-8(2)) as
related but separate controls. Vulnerability scanning is covered by a different control (RA-5)
and does not satisfy either.

## 4. Scope and Boundaries

Each engagement defines its own scope in its authorization. The charter sets the standing
boundaries that hold across every engagement.

**In scope, when named in an engagement authorization:** Meridian's enterprise network,
identity systems, endpoints, the classified program enclaves, physical facilities, and staff
(for social engineering), subject to the rules of engagement.

**Out of scope in all cases, unless separately and explicitly authorized in writing:**

- Any system Meridian does not own or operate, including customer and partner networks.
- Any action expected to degrade or deny a production service (denial-of-service testing).
- Any change to, or destruction of, live mission data.
- Medical, safety, or life-support systems.

The boundary between in and out of scope is enumerated system by system in each authorization.
Anything not named as in scope is out of scope. This mirrors the pre-engagement discipline in
the Penetration Testing Execution Standard, whose stated purpose is to agree scope up front and
prevent scope creep.

## 5. Rules of Engagement

Every engagement runs under a written rules-of-engagement document, signed before work begins.
A full worked example is in [ROE-OPERATION-IRON-THRESHOLD.md](ROE-OPERATION-IRON-THRESHOLD.md).
At minimum the rules of engagement specify:

1. **Authorization.** A signed statement from a sponsor with authority over the in-scope
   systems, naming the authorized activity and the exact window. Operators carry this during
   any physical or social-engineering activity.
2. **Scope.** The in-scope and out-of-scope systems, address ranges, domains, and facilities,
   named individually.
3. **Permitted and prohibited techniques.** For example, credential access is permitted;
   denial of service is prohibited unless separately approved.
4. **Timing.** Testing hours and any blackout windows where activity must stop.
5. **Data handling.** What may be accessed to prove impact, whether data is exfiltrated for
   real or only demonstrated, and how any captured data is stored and destroyed.
6. **Emergency stop and deconfliction.** The trusted-agent contact chain and the procedure to
   halt the engagement immediately if needed.
7. **Evidence handling.** How findings are recorded and how chain of custody is kept.

The authorization must be explicit in scope, signed by a party with authority, and in writing.
Under the U.S. Computer Fraud and Abuse Act (18 U.S.C. section 1030), access without
authorization is an offense, and good intent is not a defense. The signed rules of engagement
are what make the activity lawful.

## 6. Engagement Lifecycle

Each engagement moves through a defined set of stages, adapted from the four-stage penetration
testing methodology in NIST SP 800-115 (Planning, Discovery, Attack, Reporting) and extended
with the adversary-emulation steps a red team adds:

1. **Planning.** Set the objective, agree scope, sign the rules of engagement, and stand up
   the cells in Section 7.
2. **Threat intelligence.** The threat-intel analyst builds a profile of the adversary the
   engagement will emulate, so the emulation copies real behavior rather than a generic script.
3. **Discovery.** Reconnaissance and mapping of the in-scope environment.
4. **Attack.** Execution of the adversary emulation toward the objective, mapped to MITRE
   ATT&CK techniques so each action is recorded by its technique identifier.
5. **Reporting.** The attack narrative, the detection-gap analysis, the metrics in Section 9,
   and prioritized remediation, delivered to the sponsor and the blue team.

## 7. Deconfliction and Coordination

A red team action and a real intrusion can look identical to the defenders. The program uses a
three-cell structure so the two can be told apart in real time.

- **Red cell.** The operators executing the emulation.
- **Blue cell.** The defenders and the security operations center being tested. Depending on
  the engagement type, the blue cell may not be told an engagement is underway, which is what
  keeps the detection measurement real.
- **White cell, also called the control cell.** The neutral oversight function that holds the
  rules of engagement, keeps the operations log, and runs deconfliction if the blue cell
  escalates a red team action as a suspected real incident.

Deconfliction is the moment the white cell confirms to a small set of trusted agents that a
suspicious event was in fact the red team, so the organization does not spend a real incident
response on a test. The white cell keeps an operations log of every red cell action, which is
what makes deconfliction possible at the moment it is needed.

At the department level, this coordination is formalized for federal cyber red teams by DoD
Instruction 8585.01, "DoD Cyber Red Teams" (effective January 11, 2024), which assigns
governance, prioritization, operations, deconfliction, and reporting responsibilities for DoD
red team activity. Meridian's program follows the same separation of duties.

## 8. Framework Alignment

Every engagement maps its actions to a shared adversary-behavior taxonomy so that findings are
comparable across engagements and technique coverage can be tracked over time.

- **MITRE ATT&CK (Enterprise)** is the primary taxonomy. Each red cell action is recorded by
  its ATT&CK technique identifier, which is what lets the coverage measurement in Section 9
  mean something across engagements.
- **MITRE ATLAS** is used for any engagement that touches an AI or machine-learning system,
  since ATT&CK does not cover threats like data poisoning or prompt injection. ATLAS is updated
  roughly monthly; as of version 2026.07 it defines 16 tactics and 101 techniques. Engagements
  cite the ATLAS version in effect at the time.

Meridian also aligns the program to the **NIST Cybersecurity Framework 2.0** (February 2024)
and its six Functions: Govern, Identify, Protect, Detect, Respond, and Recover. The red team
program is the organization's primary means of validating the Detect and Respond Functions
against realistic adversary behavior.

## 9. Reporting, Metrics, and Continuous Improvement

Each engagement produces a report structured for two audiences: an executive summary framed in
business-risk terms with no jargon, and a technical body with the attack narrative mapped to
ATT&CK technique identifiers, the detection-gap analysis, and prioritized remediation.

The program measures itself across engagements, not only within a single report. Standing
metrics are:

- **Detection rate.** Techniques that generated an alert, divided by techniques executed.
- **Dwell time.** Time from initial access to the first true detection. If no detection ever
  occurs, the full engagement counts as dwell time, which flags a persistent blind spot.
- **Response rate.** Of the techniques detected, how many led to an actual containment action.
  A high detection rate with a low response rate is a specific and common finding.
- **Technique coverage over time.** The share of relevant ATT&CK techniques for which the
  organization has a tested, working detection, tracked over successive engagements to show a
  trend rather than a single score.
- **Remediation velocity.** How many prior findings were fixed before the next engagement,
  which ties the program to real risk reduction rather than report volume.

No single federal standard prescribes a fixed metric set, so these are program-defined and
anchored to the ATT&CK technique structure so they stay comparable over time.

## 10. Ethics, Legal, and Data Handling

- **Authorization.** No activity occurs without the signed authorization in Section 5. This is
  both an ethical line and a legal one, given the Computer Fraud and Abuse Act.
- **Scope discipline.** Any change to scope mid-engagement requires written approval from the
  sponsor through a formal change-control step. Operators do not expand scope on their own
  judgment.
- **Data handling.** Where proving impact requires touching sensitive data, the engagement
  prefers demonstrated access (a screenshot of reaching the asset) over real exfiltration.
  Any data captured is stored under the same controls as the data it came from and is
  destroyed on a defined schedule after the report is delivered.
- **Disclosure.** Findings go to the sponsor and the defenders. They are not disclosed outside
  Meridian without the sponsor's approval.

## 11. Team Structure, Roles, and Qualifications

- **Red team lead.** Owns the engagement, reports to the sponsor, and is accountable for
  conduct within the rules of engagement.
- **Operators.** Execute the adversary emulation.
- **Threat-intelligence analyst.** Builds the adversary profile the emulation copies.
- **White cell lead.** Holds the rules of engagement, keeps the operations log, and runs
  deconfliction. This role is independent of the red cell.

Practitioner qualification is evidenced by recognized industry certification. For red team
roles, the relevant credentials include the CREST Certified Red Team Specialist (CCRTS) and
the CREST Certified Simulated Attack Manager (CCSAM), which are the practitioner certifications
used in intelligence-led red teaming frameworks such as the Bank of England's CBEST.

## 12. Governance, Review, and Charter Maintenance

This charter is reviewed at least annually and on any material change to the program's
authority or scope. The sponsor approves each revision. Engagement cadence is set so that every
crown-jewel system is exercised on a defined cycle; as a benchmark, the EU's DORA regulation
sets a maximum three-year cycle for threat-led penetration testing of significant financial
entities, which is a reasonable outer bound for how long a critical system should go between
red team exercises.

---

## Sources

Every framework and control cited above was checked against its primary source.

- NIST SP 800-53 Rev 5, CA-8 (Penetration Testing) and CA-8(2) (Red Team Exercises):
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
- NIST SP 800-115, Technical Guide to Information Security Testing and Assessment
  (four-stage penetration testing methodology, Figure 5-1):
  https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-115.pdf
- NIST Cybersecurity Framework 2.0 (February 2024), six Functions:
  https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf
- MITRE ATT&CK: https://attack.mitre.org/
- MITRE ATLAS (version 2026.07 as of this writing):
  https://atlas.mitre.org/ and https://github.com/mitre-atlas/atlas-data
- DoD Instruction 8585.01, DoD Cyber Red Teams (effective January 11, 2024), on the DoD
  Issuances site (esd.whs.mil).
- CREST red teaming certifications (CCRTS, CCSAM):
  https://www.crest-approved.org/cyber-service-categories/red-teaming/
- Computer Fraud and Abuse Act, 18 U.S.C. section 1030.
