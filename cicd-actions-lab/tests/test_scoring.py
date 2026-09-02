"""Tests on scoring-results.json, the scorer's output. These check the
scorer's conclusions match the raw evidence, per class, and that the
project's two headline structural-blindness claims hold empirically rather
than being asserted."""


def test_scoring_covers_all_four_line_level_classes(scoring_results):
    for run in ("zizmor_default", "zizmor_auditor"):
        classes = {r["class"] for r in scoring_results[run].values()}
        assert classes == {1, 2, 3, 4}


def test_scorecard_scoring_covers_all_four_line_level_classes(scoring_results):
    classes = {r["class"] for r in scoring_results["scorecard"].values()}
    assert classes == {1, 2, 3, 4}


def test_zizmor_default_true_positive_classes_1_2_3(scoring_results):
    results = scoring_results["zizmor_default"]
    tp_classes = {r["class"] for r in results.values() if r["verdict"] == "TRUE_POSITIVE"}
    assert tp_classes == {1, 2, 3}


def test_zizmor_default_misses_class_4(scoring_results):
    results = scoring_results["zizmor_default"]
    class4 = next(r for r in results.values() if r["class"] == 4)
    assert class4["verdict"] == "FALSE_NEGATIVE"


def test_zizmor_auditor_catches_all_four_detectable_classes(scoring_results):
    """This is the default-vs-auditor comparison the project is built to
    demonstrate: switching personas changes class 4 from a miss to a hit,
    with classes 1-3 unaffected."""
    results = scoring_results["zizmor_auditor"]
    tp_classes = {r["class"] for r in results.values() if r["verdict"] == "TRUE_POSITIVE"}
    assert tp_classes == {1, 2, 3, 4}


def test_zizmor_default_vs_auditor_differ_only_on_class_4(scoring_results):
    default_verdicts = {r["class"]: r["verdict"] for r in scoring_results["zizmor_default"].values()}
    auditor_verdicts = {r["class"]: r["verdict"] for r in scoring_results["zizmor_auditor"].values()}
    diffs = {cls for cls in default_verdicts if default_verdicts[cls] != auditor_verdicts[cls]}
    assert diffs == {4}


def test_zizmor_zero_false_positives_on_class_mapped_rules(scoring_results):
    """A clean corpus (one planted vulnerability per class, no decoys) is
    expected to produce zero false positives on the rules mapped to our
    five classes. This is checked explicitly, not assumed."""
    assert scoring_results["zizmor_default_false_positives_on_mapped_rules"] == []
    assert scoring_results["zizmor_auditor_false_positives_on_mapped_rules"] == []


def test_scorecard_catches_classes_1_and_2_only(scoring_results):
    results = scoring_results["scorecard"]
    flagged = {r["class"] for r in results.values() if r["verdict"] == "FLAGGED_FILE_LEVEL"}
    assert flagged == {1, 2}


def test_scorecard_not_covered_for_classes_3_and_4(scoring_results):
    results = scoring_results["scorecard"]
    not_covered = {r["class"] for r in results.values() if r["verdict"] == "NOT_COVERED_BY_CHECK_DOCS"}
    assert not_covered == {3, 4}


def test_scorecard_scored_at_file_level_not_line_level(scoring_results):
    """Every Scorecard verdict must record the coarser file-level
    granularity explicitly, so the writeup never silently treats a
    file-level Scorecard hit as equivalent to zizmor's line-level hit."""
    for r in scoring_results["scorecard"].values():
        assert "granularity" in r
        assert "file-level" in r["granularity"]


def test_no_zizmor_finding_forced_to_map_to_class_5(scoring_results, ground_truth):
    """Class 5 must never appear in the zizmor per-class result dicts,
    because zizmor cannot detect it by design (no line in any workflow file
    corresponds to it)."""
    for run in ("zizmor_default", "zizmor_auditor"):
        classes = {r["class"] for r in scoring_results[run].values()}
        assert 5 not in classes


def test_unmapped_idents_recorded_not_silently_dropped(scoring_results):
    """Real zizmor findings that don't map to one of the 5 planted classes
    (artipacked, unpinned-uses, etc.) must be recorded somewhere, per the
    project's own scoring rule: 'record as unmapped rather than forcing it
    to count.'"""
    assert "zizmor_default_unmapped_idents" in scoring_results
    assert "zizmor_auditor_unmapped_idents" in scoring_results
    assert "unpinned-uses" in scoring_results["zizmor_default_unmapped_idents"]
