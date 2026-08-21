# Threat Intelligence Requirements Framework

This document is about the layer above threat analysis. A threat intel team can write
excellent reports and still fail as a function if nobody decided what to collect, nobody
graded whether a source could be trusted, and nobody checked whether a finished product
changed a decision. This framework covers that management layer: setting requirements,
planning collection against them, grading sources and confidence, choosing language that
doesn't overstate what's known, and closing the loop on whether any of it mattered.

It draws on two primary sources read directly for this document (US DoD's Joint
Publication 2-0 and the CIA's 1999 monograph on analytic method), and several
secondary-sourced frameworks that could not be verified against their original text in
this pass. Every claim below is marked. Where the marking says secondary, treat the
substance as probably right and the sourcing as not yet checked against the original
document. `docs/SOURCES.md` has the full list with what to do about each gap.

## Contents

1. [Priority Intelligence Requirements](#1-priority-intelligence-requirements)
2. [Collection planning](#2-collection-planning)
3. [Processing, analysis, and production](#3-processing-analysis-and-production)
4. [Source and information grading](#4-source-and-information-grading)
5. [Analytic confidence and estimative language](#5-analytic-confidence-and-estimative-language)
6. [Dissemination](#6-dissemination)
7. [Evaluation and feedback](#7-evaluation-and-feedback)
8. [The intelligence cycle, and why the phase count keeps changing](#8-the-intelligence-cycle-and-why-the-phase-count-keeps-changing)
9. [Worked example: one PIR end to end](#9-worked-example-one-pir-end-to-end)

---

## 1. Priority Intelligence Requirements

A **Priority Intelligence Requirement (PIR)** is a question a decision-maker needs
answered in order to make a decision. It is not a topic, not a beat, not a standing
interest area. "Ransomware trends" is a topic. "Should we change our incident response
retainer terms before Q3, given who is currently targeting companies our size" is a PIR.

The term comes from military doctrine. Joint Publication 2-0 (JP 2-0), the US Department
of Defense's doctrine for joint intelligence, treats PIRs as the output of the first
category of the intelligence process, "planning and direction": the stage where a
commander's information needs get translated into things intelligence staff can actually
go collect against. In that context a PIR is tied to a specific decision point in a
campaign: does the commander commit reserves, does a unit move at dawn or dusk, does an
operation proceed given a specific threat. The PIR exists because the commander is about
to decide something and the decision forks depending on the answer.

Commercial CTI (cyber threat intelligence) borrows the term but the discipline
attaching it to a real decision is frequently lost in practice. A team that maintains a
"PIR list" that reads like a syllabus, "nation-state activity," "ransomware trends,"
"emerging malware", has a reading list, not a requirements program. Nobody can tell you
what changes if the answer to "ransomware trends" comes back one way versus another,
because no decision was ever attached to the question. That gap between military PIR
doctrine (tightly bound to a commander's decision) and how the term is often used in CTI
(a standing topic list) is a known tension in the field. It is worth naming explicitly
rather than pretending the borrowed term still carries its original discipline by default.

### What makes something a PIR, not a topic

A real PIR has three things:

1. **A question with a knowable answer**, not an open-ended interest area.
2. **A named decision-maker** who owns a decision that depends on the answer.
3. **A decision that actually forks** depending on what comes back. If the org does the
   same thing regardless of the answer, it wasn't a requirement, it was curiosity.

### Template

```
PIR-<id>: <question, phrased so it can be answered>
Decision supported: <the specific choice this informs, and who makes it>
Decision-maker: <role, named>
Answered by: <what would count as an answer: a probability judgment, a yes/no,
              a ranked list, etc.>
Time sensitivity: <when the answer stops being useful because the decision
                    will be made with or without it>
Owner: <who on the intel team is accountable for tracking this>
```

### Four worked PIRs, for a platform trust-and-safety / security org

**PIR-1: Are any of the threat actors currently using generative AI to bypass our
content-moderation classifiers doing so at a scale that would justify re-architecting
detection around adversarial-AI assumptions rather than tuning the existing pipeline?**

- Decision supported: whether the detection engineering roadmap for next quarter is a
  point release (tune existing classifiers) or a re-architecture (build for an
  adversarial-AI threat model from the start).
- Decision-maker: Head of Detection Engineering, with sign-off from the VP of Trust and
  Safety on budget.
- Answered by: a probability judgment (ICD 203 band, see Section 5) on whether AI-driven
  bypass is happening at production-relevant scale, plus named case evidence.
- Time sensitivity: needed before the quarterly roadmap is locked, roughly six weeks out.
- Owner: CTI analyst assigned to the abuse-and-AI beat.

**PIR-2: Is the actor cluster behind the last two coordinated inauthentic behavior (CIB)
takedowns the same group, and if so, what infrastructure or account-creation pattern
would let us pre-empt the next wave instead of reacting to it?**

- Decision supported: whether to fund a dedicated pre-emptive detection signature (new
  engineering work) versus continuing to rely on post-hoc investigation triggered by
  external reports.
- Decision-maker: Director of Integrity Operations.
- Answered by: an attribution judgment with confidence level, plus a specific,
  actionable pattern (registration timing, hosting overlap, naming convention) if the
  clusters are linked.
- Time sensitivity: before the next platform transparency report cycle, since a
  confirmed pattern changes what gets disclosed.
- Owner: CTI analyst partnered with the CIB detection team.

**PIR-3: Which currently active ransomware groups have shown any prior interest in, or
capability against, our specific industry vertical, and does that change our incident
response retainer staffing for the next contract renewal?**

- Decision supported: retainer size and specialty mix for the incident response
  contract up for renewal.
- Decision-maker: CISO, budget approval from Finance.
- Answered by: a ranked list of groups with named evidence for each (leak-site
  listings in the vertical, TTP overlap with prior incidents in the sector), not a
  general "ransomware is up" trend line.
- Time sensitivity: before the contract renewal deadline.
- Owner: CTI analyst, cross-checked against the incident response team's own case
  history.

**PIR-4: If we disclose a specific abuse campaign publicly (a blog post naming an
actor or technique), does the available evidence meet the confidence bar our legal and
comms teams require for public attribution, or should the disclosure describe the
technique without naming an actor?**

- Decision supported: go/no-go and wording on a specific public disclosure, including
  whether to name an actor.
- Decision-maker: VP of Trust and Safety, with Legal and Comms as required approvers.
- Answered by: an explicit confidence level (high/moderate/low, per Section 5) attached
  to the attribution claim, not just the underlying finding.
- Time sensitivity: tied to the disclosure's planned publication date.
- Owner: CTI analyst who ran the investigation, with a second analyst as reviewer.

Each of these forks a real decision. If PIR-1 comes back "no evidence of AI-driven
bypass at scale," the roadmap stays a point release. If it comes back "yes, moderate
confidence," the roadmap changes. That's what distinguishes it from "how are threat
actors using AI," which is interesting but doesn't by itself tell anyone what to do
differently.

---

## 2. Collection planning

Collection planning is mapping each PIR to named sources that could actually answer it,
and stating plainly which PIRs currently have no good source. This is the
unglamorous middle of the process and it's the part most teams skip, because writing a
PIR feels like progress and admitting "we have no way to answer this yet" does not.

### Mapping a PIR to sources

For each PIR, list:

- **Direct sources**: feeds, telemetry, or reporting that could plausibly answer the
  question outright.
- **Partial sources**: sources that answer an adjacent question and require inference to
  bridge the gap.
- **Gaps**: the parts of the PIR nothing currently available can answer.

Take PIR-1 above (AI-driven bypass of moderation classifiers). Direct sources might
include internal classifier logs and appeal-rate data. Partial sources include public
vendor threat reports on AI misuse. This portfolio's own `ai-threat-intel-analysis`
project is exactly this kind of partial source: it normalizes documented AI-misuse cases
from OpenAI, Microsoft, Google, and Anthropic reporting and finds a real inflection point
(models used as a productivity aid through the first half of 2025, then called at
runtime inside malware, then one campaign run mostly by an agent, in the second half).
That's useful evidence for PIR-1, but it's about other platforms' disclosed incidents,
not a direct measurement of what's hitting your own classifiers. Using it requires the
analyst to say plainly: this tells us the industry-wide trend line, not our own exposure,
and treating it as if it answered the internal question would be a mistake worth
flagging in the product itself.

### When no source can answer the PIR

This is the common case, not the exception, and it's the part nobody writes down. When
collection planning turns up no source, three options exist, and the analyst's job is to
name which one applies rather than let the PIR sit silently unanswered:

1. **Stand up new collection.** Sometimes this is legitimate: instrument something that
   isn't currently logged, add a new feed subscription, start tracking a specific actor.
   This has a cost and a lead time, and both should be stated, not implied.
2. **Answer a narrower, adjacent question instead**, and say explicitly that this is what
   happened. If PIR-1 can't be answered directly, the team might report "no confirmed
   case of AI-driven bypass against our specific classifiers, but three documented
   industry cases show the technique is viable", that's a fair partial answer, not
   the PIR as originally posed.
3. **Report the gap as the answer.** Sometimes the correct output of collection planning
   is "we cannot currently answer this, here is what it would take to be able to." That
   is a legitimate deliverable. A PIR that goes unanswered without anyone saying so is a
   silent failure; a PIR that gets reported as currently unanswerable, with the reason
   why stated, is the collection function doing its job.

### Understanding how a source collected before reading it

Collection planning also means understanding a source's collection method well enough to
know what it can and cannot tell you, before treating its absence of a signal as
evidence. The `ransomware-ecosystem` project in this portfolio is a clean example: of
16,072 leak-site listings, 614 fall on a single date, 2021-09-09, about 40 times the
daily average. That is almost certainly a collection artifact (very likely when the
tracking tool's own monitoring began or was backfilled in bulk), not a real spike in
ransomware activity on that day. An analyst who didn't know how the feed was built could
easily misread that date as a coordinated event. The general rule: before a feed's
silence or its spikes get used as evidence for or against a PIR, know how the feed was
collected.

The same portfolio project shows the flip side, in `threat-intel-datamart`: across 8,591
indicators from 8 separate published campaign reports, cross-campaign indicator overlap
is zero (8,587 distinct values of 8,591). That's not because the campaigns shared no
infrastructure. It's because curated feeds are deduplicated before publication: each
report is written to stand alone. So "no overlap in this feed" answers "did this
publisher report the same indicator twice," not "did these campaigns share
infrastructure." What the same data does show is that 63 of 151 distinct top-level
domains show up in more than one campaign, and .com appears in all eight. That means exact
indicators rotate, but registration habits are stickier and visible if you group by the
right attribute instead of looking for exact matches. Collection planning has to know
which question a given source can actually answer, not just whether it returns a result.

---

## 3. Processing, analysis, and production

Processing and exploitation turns raw collected material into something an analyst can
work with (extracting text from a PDF, normalizing timestamps, deduplicating). Analysis
and production is where an analyst reasons over that processed material and writes it
up. Analysis of Competing Hypotheses (ACH) belongs here.

### Analysis of Competing Hypotheses (ACH)

ACH comes from Richards J. Heuer Jr.'s 1999 CIA Center for the Study of Intelligence
monograph, *Psychology of Intelligence Analysis* (a primary source, fetched and confirmed
directly for this document). Heuer developed ACH as a structured counter to a specific
failure mode: analysts naturally look for evidence that confirms the hypothesis they
already favor, rather than actively trying to disprove each candidate hypothesis. ACH's
distinguishing feature versus ordinary analysis is that it's built around falsification,
trying to knock hypotheses down, rather than confirmation.

The eight-step procedure, from the primary text:

1. Identify the possible hypotheses to be considered (brainstorm with analysts of
   different perspectives).
2. List significant evidence and arguments for and against each hypothesis.
3. Prepare a matrix with hypotheses across the top and evidence down the side; assess the
   diagnosticity of each piece of evidence.
4. Refine the matrix: reconsider the hypotheses, delete evidence that isn't
   diagnostic.
5. Draw tentative conclusions about the relative likelihood of each hypothesis, trying to
   disprove hypotheses rather than prove them.
6. Analyze how sensitive the conclusion is to a few critical items of evidence.
7. Report conclusions, discussing the relative likelihood of all the hypotheses, not just
   the one judged most likely.
8. Identify milestones for future observation that would indicate events are diverging
   from the expected course.

### When ACH is worth the cost

ACH is a heavy technique. Building a matrix, scoring diagnosticity across every
hypothesis-evidence pair, and writing up all surviving hypotheses (not just the winner)
takes real analyst time. It's worth that cost when:

- The question has genuinely competing explanations that matter differently to the
  decision-maker (attribution calls, "is this a rebrand or two separate groups").
- The stakes are high enough that being wrong in a way ACH would have caught (anchoring
  on the first plausible story) is expensive: a public attribution, a legal filing, an
  executive brief that will drive spending.
- There's enough evidence to fill a matrix. ACH doesn't manufacture evidence; a thin
  evidence base still produces a thin matrix.

It is not worth the cost for routine, low-stakes judgments, or for questions with only
one plausible hypothesis on the table. Forcing ACH onto every write-up turns a
falsification discipline into a paperwork exercise, which defeats the point.

The `ransomware-ecosystem` project's rebrand-candidate question is a good example of
where ACH earns its keep and where the project stopped short of it on purpose. It found
568 candidate pairs where one ransomware group's last listing and another's first
listing fall within 30 days of each other, and named at least three competing
explanations for a shared-victim-hash pattern: double extortion by two separate crews,
an affiliate reusing a target list across two ransomware-as-a-service programs, or a
rebrand that kept its old backlog. The project explicitly declines to pick one, stating
plainly that "none of this rises to attribution" and that it is "a list of pairs worth a
human looking at the malware and infrastructure, not a list of confirmed rebrands." That
is the right call for a dataset-level finding meant to hand off to a human analyst. If an
analyst later picks up one specific high-value pair and needs to actually decide between
those competing explanations for a report going to a decision-maker, that's exactly the
point where the ACH matrix becomes worth building.

---

## 4. Source and information grading

Sources need to be graded on two separate things: how reliable the source has been
historically, and how credible this specific piece of information is. Conflating the two
is one of the most common mistakes an intel program can make, and the Admiralty Code
exists specifically to prevent it.

### The Admiralty Code (NATO)

The Admiralty Code, associated with NATO intelligence doctrine, is reported here from
secondary sourcing (see `docs/SOURCES.md` for exactly what could and could not be
verified). It uses two independent scales:

**Source reliability (A–F):**

| Grade | Meaning |
|---|---|
| A | Completely reliable |
| B | Usually reliable |
| C | Fairly reliable |
| D | Not usually reliable |
| E | Unreliable |
| F | Reliability cannot be judged |

**Information credibility (1–6):**

| Grade | Meaning |
|---|---|
| 1 | Confirmed by other sources |
| 2 | Probably true |
| 3 | Possibly true |
| 4 | Doubtful |
| 5 | Improbable |
| 6 | Truth cannot be judged |

The design principle, per the secondary sourcing reviewed for this document: reliability
and credibility are scored independently because an unreliable source can occasionally
deliver true information, and a reliable source can occasionally be wrong. A grading of
"B2" means a usually-reliable source reporting something probably true. It does not mean
"medium confidence" as a single blended idea. It means two separate judgments happened
to land near each other this time, and they might not next time.

### Worked example: a low-reliability source delivering high-credibility information

Take a source graded **E1**: unreliable (history of invalid information) but the
specific claim is confirmed by other sources this time. This is not a contradiction, and
it's exactly the case the two-axis design exists to capture. An anonymous forum poster
with a track record of exaggerated or fabricated claims (E, unreliable) might post a
leaked ransom note that independently checks out against known TTPs and gets confirmed
by a second, unrelated source (1, confirmed by other sources). If the scheme forced a
single blended score, an analyst would have to average "unreliable" and "confirmed" into
something like "medium," which throws away the actually useful fact: this specific claim
checked out, even though this specific source usually doesn't. The reverse also happens:
a normally reliable government advisory (A or B) can, on one specific detail, turn out
to be wrong or unconfirmable (5 or 6), and a single blended score would wrongly launder
that instance's uncertainty through the source's general good reputation.

### Corroboration is not corroboration when it's circular

Grading gets harder when "two sources agree" doesn't mean what it sounds like. The
`actor-name-crosswalk` project in this portfolio found exactly this problem while
reconciling MITRE ATT&CK's 176 threat-actor groups against the MISP threat-actor galaxy's
1,041 entries: 87 of MISP's 1,403 synonym strings (about 6%) are themselves shaped like
ATT&CK group IDs (`G0006`, `G0013`, and so on). Those aren't independently sourced
vendor names. They're MISP citing ATT&CK's own catalog number. So when an analyst sees
"ATT&CK and MISP both list this actor under this name," part of that agreement is really
one source quoting the other, not two independent lines of reporting converging on the
same answer. Treating a both-sources match as automatically stronger evidence, without
checking whether one source is actually citing the other, overstates confidence. This is
the strongest single argument in this whole framework for checking upstream citations
before counting corroborating sources: it isn't a hypothetical failure mode, it's a
measured one, in a real dataset in this portfolio. `src/grade_source.py`'s
`check_corroboration` function is built directly on this finding.

---

## 5. Analytic confidence and estimative language

This section covers two things that get confused constantly: how likely something is,
and how much an analyst trusts the basis for saying so. They are different axes and
should never be fused into one phrase.

### ICD 203's seven bands

Intelligence Community Directive 203 ("Analytic Standards"), published by the US Office
of the Director of National Intelligence (ODNI), is reported here from secondary
sourcing. ODNI's own site blocked automated fetching of the primary PDF in the research
supporting this document, so the bands below rest on two independent secondary
reproductions that agree with each other exactly, not on a primary read. See
`docs/SOURCES.md` for what verifying this properly would require.

| Term | Probability range |
|---|---|
| Almost no chance | 01–05% |
| Very unlikely | 05–20% |
| Unlikely | 20–45% |
| Roughly even chance | 45–55% |
| Likely | 55–80% |
| Very likely | 80–95% |
| Almost certain | 95–99% |

Reported guidance alongside the table: analysts are strongly encouraged not to mix terms
from different rows within one product. Using "unlikely" in one paragraph and "very
likely" in the next, describing related judgments in the same product, without
explaining why the confidence differs that much, muddies the read for the reader who is
expecting a consistent scale.

### The single most useful rule here

**Likelihood language and analytic-confidence language are separate axes and should not
be combined into one phrase.** "Likely, with high confidence" is not one rating. It's two
separate judgments that happen to be reported together: how probable the event is
(likely, 55–80%) and how much the analyst trusts the sourcing and reasoning behind that
probability call (high confidence). A phrase like "likely with high confidence" invites
the reader to treat it as a single compound score, when actually the two components can
move independently. You can have high confidence in a roughly-even-chance judgment
(meaning: the analyst is very sure the true probability really is close to 50/50, not
that the analyst is unsure), and you can have low confidence in an "almost certain"
judgment (meaning: the analyst suspects the event is very likely, but the sourcing behind
that suspicion is thin). Reporting them as two separate, clearly labeled fields, a
probability band and a confidence level (High/Moderate/Low), forces the write-up to state
plainly which axis is doing the talking. This is also not a universal standard:
ICD 203's bands are one specific US intelligence-community scale. The IPCC uses different
percentage bands for similar-sounding words in climate reporting, and the UK's
Professional Head of Intelligence Assessment (PHIA) has its own "probability yardstick."
A CTI shop borrowing "likely/unlikely" language from ICD 203 should say so, because a
reader trained on a different scale will attach different numbers to the same word.

### Worked example: how confidence hardens as it travels

The `doppelganger-case-study` project in this portfolio is the cleanest illustration of
what ICD 203's confidence discipline exists to prevent. The attribution chain for the
Doppelganger/RRN influence operation ran through several stages, each with a different
level of hedging, and by the time it reached the public record the hedges had quietly
disappeared:

- EU DisinfoLab, the organization that discovered the operation (September 2022), would
  not attribute it: "Our investigation does not lead to a formal attribution to a
  specific actor... we cannot entirely exclude the possibility of a false flag
  operation."
- VIGINUM, the French government agency for foreign digital interference, built a
  technical case (July 2023) through domain registrations, WHOIS records, and
  phone-number correlation, and still wrote in explicitly hedged terms: "probably," "very
  likely."
- The EU sanctioned seven individuals and five entities (July 2023). The US sanctioned a
  subset of that same list (March 2024). The DOJ indicted two named individuals and
  seized 32 domains (September 2024).

By the time the story reaches sanctions and an indictment, the original discoverer's
explicit refusal to rule out a false flag is not carried forward or cited by the later,
more confident sources. That's not necessarily wrong, later stages had more evidence
than the first discoverer did, but it's exactly the failure mode ICD 203 exists to
guard against: hedged, probabilistic language hardening into apparent certainty as a
claim travels, without anyone re-stating the confidence level at each hop. A product that
cites the sanctions and the indictment as its evidence, without also carrying forward
that the chain started at "cannot exclude a false flag," is quietly upgrading the
claim's confidence by omission.

---

## 6. Dissemination

Dissemination is choosing the right product for the consumer and handling the sharing
restrictions correctly. A ten-page technical report is the wrong product for an
executive with two minutes; a one-page brief is the wrong product for an engineer who
needs the actual indicators to write a detection rule. `gtg1002-exec-brief` in this
portfolio is an example of the executive-audience end of that spectrum: it takes an
already-verified technical investigation and reframes it as a one-page brief (Bottom
Line Up Front, then Key Judgments, then supporting detail), while keeping the ICD 203
separation intact: probability and confidence reported as separate tagged fields on
each judgment, and the one disputed figure in the case (the claim that AI ran 80-90% of
an operation) kept at moderate confidence with the dissent stated on the line beneath it,
rather than either burying the dispute or letting it dominate the brief.

### TLP: Traffic Light Protocol

TLP marks how a piece of intelligence can be shared onward. It has four labels in its
current version: RED (not for sharing beyond the specific individuals in the room),
AMBER or AMBER+STRICT (limited sharing within an organization, or specifically named
parties), GREEN (community sharing, not for public posting), and CLEAR (no restriction
on further sharing).

**TLP 2.0, published by FIRST in August 2022, renamed the old WHITE label to CLEAR.**
This isn't a minor cosmetic change for a portfolio piece to skip past. It broke real
data in this portfolio. The `threat-intel-datamart` project loaded eight MISP campaign
exports from a single publisher, Infoblox, and found what looked like two different
sharing policies for the same organization: some events tagged `tlp:white`, others
`tlp:clear`. There weren't two policies. There was one organization whose feed straddled
the vocabulary change: events from 2022-11-09 through 2024-05-15 used the old `white`
tag, and events from 2024-07-29 onward used the new `clear` tag. Splitting Infoblox into
two source rows because of that would have been wrong, and modeling it as a Type 2
slowly-changing dimension (as if the sharing policy itself changed on a date) would have
been actively misleading: it would tell an analyst Infoblox tightened or loosened its
sharing on a specific date, when nothing about Infoblox's actual policy changed at all.
The fix the project used was a crosswalk: keep the raw label as published, and hold a
separate canonical column that maps `white` to `clear`. That is the general lesson for
handling any vocabulary rename in dissemination tooling: don't discard the original
label, and don't quietly assume an old label from an unrelated era means what today's
version of that label means, without checking whether the standard's own text agrees.
Worth noting: the TLP 2.0 standard document itself never mentions WHITE by name; the "WHITE
became CLEAR" statement lives in FIRST's own announcement and CISA's user guide, and even
MISP's own taxonomy hedges the equivalence as "most probably compatible" rather than
asserting it outright. That hedge is itself worth carrying into how confidently a
dissemination pipeline treats the mapping.

---

## 7. Evaluation and feedback

This is the stage everyone skips, and it's the stage JP 2-0 lists last for a reason:
it's what tells you whether any of the preceding five categories were worth doing.

### What to measure

- **Did the product get read by the named decision-maker before the decision was made?**
  This is checkable: did the PIR-2 brief land on the Director of Integrity Operations's
  desk before or after the roadmap was actually locked.
- **Did the decision go the way the intelligence pointed, or a different way, and if
  different, was that because the intelligence was wrong or because other factors
  outweighed it?** These are different failure modes and worth distinguishing.
  Intelligence that was correct but got overridden by budget reality is not a failure of
  the intel function.
  - **Did a follow-up PIR ever get raised because the first answer wasn't good enough?**
  That's a proxy for whether the consumer trusted the product enough to keep asking, or
  quietly stopped relying on the team.
  - **Time from PIR being raised to being answered**, tracked per PIR, so a team can tell
  whether its own collection-to-production pipeline is getting faster or slower over
  time, and whether the time sensitivity stated on each PIR was actually met.

### What can't be measured, and shouldn't be pretended otherwise

- **Whether a disclosed attribution was actually correct**, in the deep sense, is often
  unknowable to the team that made it. The `doppelganger-case-study` chain above shows
  why: even government agencies with far more resources than a commercial CTI team
  hedged their confidence for over a year before sanctions and an indictment followed.
  A commercial team should not claim it can verify its own attribution calls against
  ground truth it will likely never see.
- **Counterfactual impact**, what would have happened without the product, is
  fundamentally unmeasurable in a single case. You cannot rerun the quarter without the
  PIR-1 brief and see if the roadmap decision differed. The best a team can do is track
  whether the decision-maker cites the product as a factor, which is a weaker but
  defensible substitute for a counterfactual nobody can run.
- **Whether "reading the report" produced "understanding the report."** A read receipt
  or a meeting attendance log measures exposure, not comprehension. Don't conflate the
  two when reporting feedback metrics upward.

Being explicit about what can't be measured is itself part of the deliverable. A
feedback process that claims full attribution of business outcomes to specific
intelligence products is asserting something a plainly-done evaluation and feedback
process cannot actually support.

---

## 8. The intelligence cycle, and why the phase count keeps changing

Most commercial CTI material draws "the intelligence cycle" as a clean, six-stage
circular diagram and moves on. The actual doctrine is messier than that, on two counts,
and both are worth stating rather than picking a favorite silently.

### JP 2-0's six categories, and its own disclaimer

Joint Publication 2-0, the current US DoD doctrine for joint intelligence, is a primary
source for this document, fetched and confirmed verbatim. It states the intelligence
process "consists of six interrelated categories of intelligence operations": planning
and direction; collection; processing and exploitation; analysis and production;
dissemination and integration; and evaluation and feedback.

What most secondhand summaries leave out: **JP 2-0 explicitly disclaims strict
linearity**, even while listing the six categories in order. The source text notes that
these categories often run concurrently: a request for imagery may need planning and
direction but no new collection at all, and information can be disseminated during
processing, before formal analysis is even complete. That nuance matters. The tidy
circular-diagram version of the intelligence cycle that shows up in most public material
is a simplification the primary doctrine itself rejects. A framework that draws a clean
loop and stops there is quietly less accurate than the source it's citing.

### CIA's public rendering: five stages or six, depending on the version

CIA's own public-facing material on the intelligence cycle is reported here from
secondary sourcing (not independently fetched for this document; see
`docs/SOURCES.md`). Different CIA-adjacent public materials render it as either five or
six stages, depending mainly on whether "Feedback" is folded into "Dissemination" or kept
as its own stage. This isn't a mistake in any one version; it's consistent with the
broader intelligence-cycle literature's well-documented instability in how many phases
get named. For a commercial CTI team, the six-category JP 2-0 structure is the better fit
here specifically because it keeps evaluation and feedback as its own explicit category
rather than letting it quietly disappear into dissemination, which is exactly the stage
most teams already skip in practice (Section 7). Folding it into dissemination makes that
skip easier to not notice.

---

## 9. Worked example: one PIR end to end

**PIR-2 from Section 1**, run through all six JP 2-0 categories, using this portfolio's
own work as the collection and production evidence.

**Question:** Is the actor cluster behind the last two coordinated inauthentic behavior
(CIB) takedowns the same group, and if so, what pattern would let the team pre-empt the
next wave?

**1. Planning and direction.** The Director of Integrity Operations raises the PIR after
the second takedown, because the decision (fund a pre-emptive detection signature versus
keep relying on reactive investigation) needs an answer before the next transparency
report cycle. The analyst assigned confirms the question is answerable in principle (it's
about comparing two specific, already-observed clusters) and sets the time sensitivity.

**2. Collection.** The `cib-detection` work in this portfolio found that shared hashtags
separate coordinated accounts from ordinary ones at AUC 0.888 on Twitter's 2020 takedown
data, a real, working detection signal, but built and validated against one specific
operation's tradecraft. Collection planning here means checking whether that signal
would even apply to the current cluster before leaning on it.

**3. Processing and exploitation.** This is where the `doppelganger-case-study` project's
finding becomes directly relevant, not as a topic match but as a method warning: it found
that the shared-hashtag detector would not have caught the Doppelganger/RRN operation,
because DOJ affidavit evidence showed the operation's own tradecraft instructed accounts
to ride existing public trends in individually varied language rather than coordinate on
shared tags, producing tag overlap with the general public, not with each other. The
processing step here is reading the current cluster's actual observed behavior closely
enough to know whether it looks like the 2020 hashtag-coordination pattern or the
2022-era trend-riding pattern, before assuming last time's detection method transfers.

**4. Analysis and production.** If the two clusters' tradecraft looks meaningfully
different (one hashtag-coordinated, one trend-riding), that's itself evidence they may
not be the same group, or that the group's tradecraft evolved between takedowns. That is
a case where ACH (Section 3) is worth the cost, because there are genuinely competing
hypotheses (same group, evolved method / different groups, convergent method / same
group, no meaningful method) and the stakes (a funding decision, a public transparency
report) justify the analyst time. The write-up reports the relative likelihood of each
hypothesis, not just the winner, per ACH step 7.

**5. Dissemination and integration.** The finished judgment goes to the Director of
Integrity Operations as a short brief: the PIR's question restated, a probability band
(Section 5) on whether it's the same actor, a confidence level reported as a separate
field, and the specific pattern (if any) that would let engineering build a pre-emptive
signature. TLP marking depends on whether it's staying internal (AMBER) or going into a
public transparency report later (eventually CLEAR, once cleared for release).

**6. Evaluation and feedback.** Track whether the Director's funding decision cites this
brief, whether engineering actually builds against the named pattern, and whether the
next takedown (if one happens) validates or contradicts the judgment. If the pattern
turns out wrong, that's not a failure to hide. It's the next PIR.

---

Sourcing for every claim in this document, including exactly what's primary, what's
secondary, and what remains a gap, is in `docs/SOURCES.md`.
