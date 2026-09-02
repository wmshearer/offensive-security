"""Pin the evidence table's shape and its agreement with the methodology.

Two failures these catch:

1. A row losing its citation or gaining a duplicate id. The research pass that
   produced this table shipped one duplicate row filed under the wrong
   walkthrough, so duplicates are a real failure mode here, not a theoretical one.

2. The practice labels drifting out of step with METHODOLOGY.md. The site's own
   CLAUDE.md drifted from its code the same way: the doc kept describing a
   superseded design long after the code changed, and a later reader following
   the doc would have reintroduced the bug it warned about.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs" / "evidence.json"
METHODOLOGY = ROOT / "docs" / "METHODOLOGY.md"

# The eight practices METHODOLOGY.md documents under "The eight checks".
PRACTICES = {
    "prove-by-hand-first",
    "out-of-band-confirmation",
    "precondition-check",
    "scanner-false-positive",
    "confirm-change-took-effect",
    "two-method-confirmation",
    "baseline-first",
    "rule-out-simple-case-first",
}


@pytest.fixture(scope="module")
def rows() -> list[dict]:
    return json.loads(EVIDENCE.read_text(encoding="utf-8"))


def test_every_row_has_a_citation(rows):
    for r in rows:
        assert r["line_start"] > 0
        assert r["line_end"] >= r["line_start"]
        assert r["step_title"].strip()


def test_ids_are_unique(rows):
    ids = [r["id"] for r in rows]
    assert len(ids) == len(set(ids)), "duplicate row id"


def test_no_duplicate_citations(rows):
    """A slug plus a step title should appear once. The research pass filed the
    same Ghostlink step under Nexus as well, which is what this catches."""
    seen = [(r["slug"], r["step_title"]) for r in rows]
    assert len(seen) == len(set(seen)), "the same step cited twice"


def test_types_are_the_documented_practices(rows):
    used = {r["type"] for r in rows}
    assert used <= PRACTICES, f"undocumented practice: {used - PRACTICES}"


def test_methodology_documents_every_practice_in_use(rows):
    """Each practice with evidence behind it must appear in the write-up."""
    text = METHODOLOGY.read_text(encoding="utf-8").lower()
    for practice in {r["type"] for r in rows}:
        words = [w for w in practice.split("-") if len(w) > 3]
        assert any(w in text for w in words), f"{practice} has evidence but no prose"


def test_the_stated_gap_is_still_stated(rows):
    """The write-up claims no corrective validation moment exists. If a row ever
    adds one, the gap paragraph is wrong and has to change with it."""
    text = METHODOLOGY.read_text(encoding="utf-8")
    assert "None of them is corrective." in text
    assert not any("corrective" in r["type"] for r in rows)
