# Threat Intelligence Requirements Framework

This is the management layer above threat analysis: how a team decides what to collect,
who decides it, how source quality and analytic confidence get expressed, and how the
team finds out whether the intelligence was any use.

The main deliverable is `docs/FRAMEWORK.md`. It covers Priority Intelligence Requirements
(what one actually is, with worked examples tied to named decisions), collection planning
against those requirements, where Analysis of Competing Hypotheses fits and when it's
worth the cost, source and information grading with the Admiralty Code, ICD 203's
estimative-probability bands, dissemination and TLP, and evaluation and feedback, the
stage most teams skip. It closes with one PIR run end to end through all six stages.

`docs/SOURCES.md` lists every framework cited, its publisher, and whether it was
verified against the primary document or rests on secondary sourcing. Two things in this
document were not independently verified: the Admiralty Code and ICD 203's probability
bands. Both rest on secondary sourcing because the primary publishers (NATO, and ODNI for
ICD 203) either don't freely mirror the source or blocked automated fetching. That's
stated plainly rather than papered over.

## The headline point

Likelihood and analytic confidence are different axes. "Likely, with high confidence" is
not one rating, it's two separate judgments that happen to be reported together. A team
that fuses them into a single compound phrase is asserting a precision it doesn't have.
The `doppelganger-case-study` project in this portfolio shows what happens when that
discipline slips across a chain of sources: a discoverer who explicitly refused to
attribute, an agency that hedged with "probably" and "very likely," and then sanctions
and an indictment that carry no trace of the original doubt.

## The tool

`src/grade_source.py` is a small, dependency-free Python tool for grading a claim's
sourcing. It:

- takes an Admiralty reliability letter (A-F) and credibility number (1-6), validates
  both, and refuses to collapse them into one blended score
- maps an estimative-probability phrase to its ICD 203 band, and rejects any phrase
  that isn't one of the seven
- flags a product that mixes terms from different ICD 203 rows, or fuses a confidence
  word into a probability phrase
- given a list of sources for one claim, flags when apparent independence is actually
  circular (one source citing another in the same list), modeled on a real finding from
  the `actor-name-crosswalk` project: 87 of MISP's 1,403 threat-actor synonym strings are
  themselves ATT&CK group IDs, meaning MISP is, for those entries, citing ATT&CK rather
  than reporting independently

Run it:

```bash
python3 src/grade_source.py
```

Run the tests:

```bash
python3 -m pytest tests/ -q
```

26 tests, standard library only (`pytest` for the test runner).
