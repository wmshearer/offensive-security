# Validation methodology

How I confirm a vulnerability is real and reachable before acting on it.

This project is a synthesis, not a new investigation. Across twelve penetration-testing
walkthroughs I wrote, the same handful of checks keep appearing: prove the primitive by
hand before reaching for a module, get an out-of-band callback when there is no visible
output, confirm the precondition before spending time on the exploit. None of that was
ever named as a practice. It was just what the work required at the time.

Job postings name it. "Vulnerability triage and validation" appears in the requirements
of every posting I have read for this kind of role. So this page pulls the practice out
of the walkthroughs and states it plainly, with the original moments as the evidence.

## What is here

- `docs/` — the methodology itself, and the evidence table behind it
- `src/` — the extraction script that pulls validation moments from the source pages
- `tests/` — checks that every claim in the methodology traces to a real citation

## What this is not

This is not a claim to have run these engagements against live client targets. Every
walkthrough it draws on is a documented reconstruction of a retired HackTheBox machine,
built from the official published solution. The validation reasoning is real and the
citations are exact. The engagements were lab work.

## Sources

Every row in the evidence table cites a file and line in the published case studies at
the project site. Nothing here is recalled from memory or restated from a framework.
