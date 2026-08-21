"""Tests for the ransomware coverage analysis.

The load-bearing test here is `test_t1486_rules_exist_and_stayed_silent`.

The headline finding is that T1486, Data Encrypted for Impact, used by all 14
families and the single most defining ransomware behaviour, is not covered by any
rule that fired. Read carelessly that says "nobody writes rules for encryption",
which is false. Ten rules for it exist in the corpus.

They stayed silent because the events contain no ransomware. Both readings
produce the same number and mean opposite things, so the distinction is pinned
here rather than left to prose.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from analyse import CORE_THRESHOLD, build  # noqa: E402
from scoring import expand, load_run, parent_of  # noqa: E402
from techniques import load_families, technique_provenance  # noqa: E402

SIGMA = Path(
    "/home/kali/director/projects/cloud-detection-coverage/data/sigma/rules"
)
EVENTS = Path(
    "/home/kali/director/projects/detection-rule-lab/data/events/malicious.jsonl"
)


@pytest.fixture(scope="module")
def data() -> dict:
    return build()


def test_sibling_run_is_the_expected_measurement(data):
    run = data["run"]
    assert run.rules_loaded == 2691
    assert run.rules_fired == 135
    assert run.malicious_events == 834226


def test_families_resolve_from_attack(data):
    assert len(data["families"]) == 14
    names = {f.name for f in data["families"]}
    assert "LockBit 3.0" in names
    assert "Conti" in names


def test_t1486_is_used_by_every_family(data):
    """Encrypting files for impact is what ransomware is. If this ever stops
    being universal, the family list is wrong."""
    provenance = technique_provenance(data["families"])
    assert len(provenance["T1486"]) == len(data["families"])


def test_core_set_uses_a_stated_threshold(data):
    assert CORE_THRESHOLD == 4
    provenance = technique_provenance(data["families"])
    for tid in data["core"]:
        assert len(provenance[tid]) >= CORE_THRESHOLD


def test_headline_coverage(data):
    summary = data["core_cov"].summary()
    assert summary["techniques_total"] == 17
    assert summary["techniques_covered"] == 8


def test_t1486_is_not_covered_by_a_rule_that_fired(data):
    assert "T1486" in data["core_cov"].uncovered_techniques


def test_t1486_rules_exist_and_stayed_silent():
    """The correction to the headline. Rules for encryption-for-impact are
    written and present in the corpus. They did not fire."""
    matching = [
        p for p in SIGMA.rglob("*.yml")
        if "attack.t1486" in p.read_text(encoding="utf-8", errors="replace").lower()
    ]
    assert len(matching) >= 10, "T1486 rules should exist in the Sigma corpus"

    run = load_run()
    fired = set()
    for rule in run.results:
        fired |= expand(set(rule.techniques))
    assert "T1486" not in fired, "T1486 fired; the finding needs rewriting"


def test_the_corpus_has_the_telemetry_those_rules_need():
    """Two of the T1486 rules key on image_load, which is Sysmon EventID 7. If
    that event type were absent, the silence would mean 'wrong telemetry' rather
    than 'no ransomware in the data', which is a different finding."""
    seen = set()
    with EVENTS.open(encoding="utf-8", errors="replace") as handle:
        for i, line in enumerate(handle):
            if i >= 50_000:
                break
            try:
                seen.add(json.loads(line).get("EventID"))
            except json.JSONDecodeError:
                continue
    assert 7 in seen, "no image_load events, so the silence is inconclusive"


def test_subtechnique_credits_parent():
    assert parent_of("T1059.003") == "T1059"
    assert "T1059" in expand({"T1059.003"})


def test_single_family_techniques_are_excluded_from_core(data):
    provenance = technique_provenance(data["families"])
    singles = {t for t, f in provenance.items() if len(f) == 1}
    assert singles, "expected some single-family techniques"
    assert not (singles & data["core"])


def test_matching_rules_are_mostly_malicious_only(data):
    """A rule that also fires on benign events is a cost. Reporting coverage
    without that split would hide it."""
    summary = data["core_cov"].summary()
    assert summary["rules_matching"] > 0
    assert summary["rules_malicious_only"] <= summary["rules_matching"]


# --- rubric ---------------------------------------------------------------

from rubric import (  # noqa: E402
    NOT_IN_PLACE,
    PARTIAL,
    RUBRIC,
    VERIFIED,
    Assessment,
    worked_example,
)


def test_a_perfect_assessment_scores_one():
    perfect = Assessment({c.id: VERIFIED for cat in RUBRIC for c in cat.controls})
    assert perfect.overall() == pytest.approx(1.0)


def test_an_empty_assessment_scores_zero():
    """Missing controls count as not in place, so a partial assessment cannot
    flatter itself by leaving questions out."""
    assert Assessment().overall() == 0.0


def test_protect_carries_the_most_weight():
    weights = {c.name: c.weight for c in RUBRIC}
    assert weights["Protect"] == max(weights.values())


def test_the_total_hides_the_weakest_category():
    """The reason per-category output is the headline. This assessment reads
    acceptable overall while one category is failing."""
    example = worked_example()
    assert 0.55 < example.overall() < 0.70
    assert example.category_score(example.weakest()) < 0.40


def test_unverified_controls_are_listed_separately():
    example = worked_example()
    unverified = {c.id for c in example.unverified()}
    assert "P4" in unverified, "backup restoration is the control that matters most"


def test_every_control_id_is_unique():
    ids = [c.id for cat in RUBRIC for c in cat.controls]
    assert len(ids) == len(set(ids))


def test_rubric_doc_states_the_scoring_is_invented():
    """No CISA or NIST document publishes a numeric ransomware maturity score.
    If that disclosure ever disappears from the doc, this fails."""
    doc = (ROOT / "docs" / "RUBRIC.md").read_text(encoding="utf-8")
    assert "The scoring model is invented." in doc
    assert "stale" in doc, "the CPG v1 numbering caveat should stay"
