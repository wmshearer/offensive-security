# Sources

Every framework cited in `docs/FRAMEWORK.md`, with publisher, exact title, URL, and its
verification status carried across from the research brief that supports this document
(`/home/kali/director/.research/incoming/wave4-program-frameworks.md`, Area 3). Status
legend, same as the brief:

- **PRIMARY**: the source document was fetched and read directly; quotations are
  verbatim from the extracted text.
- **SECONDARY**: the primary document could not be fetched directly; the claim rests on
  reputable secondary reproductions that agree with each other, but was not independently
  checked against the original text.
- **GAP**: something the research could not verify at all in the time available, flagged
  as an open item rather than guessed at.

---

## 1. Joint Publication 2-0, "Joint Intelligence": PRIMARY

Publisher: US Department of Defense, Joint Chiefs of Staff.
Edition fetched: 2007 (mirrored at bits.de).
URL used: https://www.bits.de/NRANEU/others/jp-doctrine/jp2_0(2007).pdf

The six-category intelligence process (planning and direction; collection; processing
and exploitation; analysis and production; dissemination and integration; evaluation and
feedback) and the document's own disclaimer of strict linearity are both quoted or
paraphrased directly from this fetched text.

**Gap**: a fuller 2013 revision (22 October 2013) of JP 2-0 exists and is referenced in
search results as the more current full doctrine document. This document's research did
not fetch the 2013 edition directly; it relies on a search-summary claim that the 2013
edition uses the same six-category structure. Someone verifying this properly should
locate and fetch the 2013 edition directly and confirm the six categories and the
non-linearity language are unchanged.

## 2. CIA's public intelligence cycle: SECONDARY / GAP

Publisher: CIA (public affairs materials).
Referenced but not fetched: https://www.cia.gov/spy-kids/static/59d238b4b5f69e0497325e49f0769acf/Briefing-intelligence-cycle.pdf

The claim that CIA-adjacent public material renders the cycle as either 5 or 6 stages,
depending on whether "Feedback" is folded into "Dissemination," comes from a
search-engine synthesis, not a direct read of CIA's own PDF text. Treated in
`FRAMEWORK.md` as illustrating the intelligence-cycle literature's known instability in
phase count, not as an authoritative structure in its own right.

**To verify properly**: fetch the CIA PDF directly (a browser session may succeed where
automated fetch attempts did not) and confirm the exact stage count and names used.

## 3. Admiralty Code (NATO): SECONDARY

Commonly cited as the "Admiralty Code" or "Admiralty System"; formal codification
referenced in secondary material as AJP-2.1 under STANAG 2511. No freely mirrorable
primary NATO document was found and fetched in the research supporting this document.

The reliability scale (A "Completely reliable" through F "Reliability cannot be judged")
and the credibility scale (1 "Confirmed by other sources" through 6 "Truth cannot be
judged") reported in `FRAMEWORK.md` rest on multiple independent secondary sources
(Wikipedia, Blockint, SRM, a ResearchGate paper abstract) that agree with each other
closely. This is not a primary-source read. The scale content is treated as
high-confidence because of that cross-agreement, but it has not been checked against an
actual NATO-published STANAG or AJP text.

**To verify properly**: obtain AJP-2.1 (NATO Standardization Office publications are not
all freely public; this may require an institutional or defense-sector channel) and
confirm the scale definitions verbatim.

## 4. ICD 203, "Analytic Standards": SECONDARY

Publisher: Office of the Director of National Intelligence (ODNI).
Originally issued 2007; per secondary sources, most recently amended January 21, 2022.
Canonical URL per multiple secondary references: https://www.dni.gov/files/documents/ICD/ICD-203.pdf

**ODNI's site blocked automated fetching of this document.** Multiple direct-fetch
attempts against dni.gov and odni.gov, and against FAS.org mirrors, either redirected to
an HTML/JavaScript interstitial or returned empty/blocked responses. The seven-band
estimative-probability table reported in `FRAMEWORK.md` (Almost no chance 01-05% through
Almost certain 95-99%) rests on two independent secondary reproductions, a GitHub repo
transcription by a third party and multiple consistent search-engine summaries, which
agree with each other exactly. That agreement is why the table is treated as
high-confidence in this document. It is explicitly **not** primary-verified.

The guidance that analysts should not mix terms from different rows, and that
probability and confidence language are separate axes, is reported the same way:
secondary-sourced, not read from the ODNI PDF directly.

**To verify properly**: use a real browser session, not an automated curl-style fetch,
against dni.gov, since the blocking behavior appears to target non-browser clients
specifically. If that still fails, check the Federation of American Scientists (FAS.org)
Intelligence Resource Program mirrors, or a university library's government-documents
collection, which sometimes hosts unblocked copies of ODNI directives.

## 5. ICD 206, "Sourcing Requirements for Disseminated Analytic Products": GAP

Publisher: ODNI.
Identified but not fetched or read in any form. Governs mandatory sourcing citations
(Source Reference Citations, Appended Reference Citations, source descriptors) for
analytic products leaving an agency. Not cited substantively in `FRAMEWORK.md` because it
was not verified at all; noted here only so a reader knows it exists and was
intentionally left out rather than overlooked.

**To verify properly**: same approach as ICD 203, a browser session against dni.gov, or
the FAS.org mirror at https://irp.fas.org/dni/icd/icd-206.pdf (existence confirmed by
search, contents not fetched).

## 6. Richards J. Heuer Jr., "Psychology of Intelligence Analysis": PRIMARY

Publisher: CIA Center for the Study of Intelligence (CSI), 1999.
URL: https://www.cia.gov/resources/csi/static/Pyschology-of-Intelligence-Analysis.pdf

Fetched and read directly. Chapter 8, "Analysis of Competing Hypotheses," contains the
original 8-step ACH procedure, quoted in `FRAMEWORK.md` from the extracted primary text.
The document credits Heuer as the procedure's author directly (footnote 85 in the
source). This is the actual origin document, not a later restatement.

**Not verified**: Heuer & Pherson's later book, "Structured Analytic Techniques for
Intelligence Analysis" (CQ Press/SAGE, 2nd edition), which republishes and extends ACH
alongside 54 other techniques. Its table of contents and the full list of 55 techniques
were not confirmed from primary text; this document does not cite specifics from that
later book beyond noting it exists.

## 7. PIR doctrinal origin: GAP (partial)

The claim that PIRs are tied to a commander's specific decision points in original
military doctrine is reported per general military-doctrine understanding in the
research brief, not independently confirmed against primary Army or Joint doctrine text
(e.g., ADP 2-0) in this pass. SANS FOR578 course materials, reportedly the source for how
CTI adapts PIR doctrine (via "Priority TTPs"), were also not fetched; they are paywalled
course content.

**To verify properly**: read ADP 2-0 or FM 2-0 (US Army intelligence doctrine) directly
for the original PIR definition, and, if accessible, SANS FOR578 materials or the SANS
blog post "Bridging Gaps in CTI: A Practical Guide to Threat-Informed Security with PIRs"
(https://www.sans.org/blog/bridging-gaps-cti-practical-guide-threat-informed-security-pirs)
for the commercial CTI adaptation.

## 8. Portfolio projects cited as collection and production evidence

These are this portfolio's own work, not external doctrine, and are cited directly from
their own README/FINDING files in this repository set, not from any external source:

- `actor-name-crosswalk` (`docs/FINDING.md`)
- `threat-intel-datamart` (`docs/FINDING.md`)
- `doppelganger-case-study` (`README.md`, `docs/CASE.md`)
- `ransomware-ecosystem` (`docs/FINDING.md`)
- `gtg1002-exec-brief` (`README.md`)
- `ai-threat-intel-analysis` (`README.md`)
- `cib-detection` (referenced via `doppelganger-case-study`'s own README, which states
  its AUC 0.888 finding; this document did not re-open `cib-detection`'s own files
  directly, and relies on `doppelganger-case-study`'s citation of it)

## Summary table

| Framework | Publisher | Status |
|---|---|---|
| JP 2-0 six-category intelligence process | US DoD | PRIMARY (2007 edition) |
| JP 2-0 2013 revision | US DoD | GAP (not fetched) |
| CIA public intelligence cycle (5 or 6 stage) | CIA | SECONDARY / GAP |
| Admiralty Code (reliability A-F, credibility 1-6) | NATO | SECONDARY |
| ICD 203 estimative-probability bands | ODNI | SECONDARY (ODNI blocked automated fetch) |
| ICD 206 sourcing requirements | ODNI | GAP (not fetched) |
| ACH 8-step procedure | CIA CSI / Heuer, 1999 | PRIMARY |
| Heuer & Pherson SAT book (55 techniques) | CQ Press/SAGE | GAP (not verified) |
| PIR military doctrinal origin | US Army/Joint doctrine | GAP (not primary-verified) |
| TLP 2.0 WHITE-to-CLEAR rename | FIRST | Reported per FIRST's own announcement and CISA's TLP 2.0 User Guide, both cited in the `threat-intel-datamart` project; the TLP 2.0 standard document itself does not mention WHITE by name |
