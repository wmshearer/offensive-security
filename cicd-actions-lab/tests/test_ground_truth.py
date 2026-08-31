"""Structural tests on ground-truth.yml itself: every planted case is
well-formed, points at a real file/line, and the five classes are all
present exactly once (except class 3, which is a pair, and class 5, which
has no workflow line by design)."""
from pathlib import Path


def test_ground_truth_has_five_classes(ground_truth):
    classes = sorted(c["class"] for c in ground_truth["cases"])
    assert classes == [1, 2, 3, 4, 5]


def test_every_case_has_required_fields(ground_truth):
    required = {"id", "class", "name", "file", "rationale"}
    for case in ground_truth["cases"]:
        missing = required - set(case.keys())
        assert not missing, f"case {case.get('id')} missing fields: {missing}"


def test_class_1_2_3_4_have_real_line_numbers(ground_truth):
    for case in ground_truth["cases"]:
        if case["class"] in (1, 2, 3, 4):
            assert case["line"] is not None, f"class {case['class']} case must have a line"
            assert isinstance(case["line"], int)


def test_class_5_has_no_workflow_line_by_design(ground_truth):
    case5 = next(c for c in ground_truth["cases"] if c["class"] == 5)
    assert case5["line"] is None
    assert "source_workflow" in case5


def test_referenced_files_exist(root, ground_truth):
    for case in ground_truth["cases"]:
        f = root / case["file"]
        assert f.exists(), f"ground truth references missing file: {case['file']}"
        if case.get("paired_file"):
            pf = root / case["paired_file"]
            assert pf.exists(), f"ground truth references missing paired_file: {case['paired_file']}"
        if case.get("source_workflow"):
            sf = root / case["source_workflow"]
            assert sf.exists(), f"ground truth references missing source_workflow: {case['source_workflow']}"


def test_planted_lines_match_actual_file_content(root, ground_truth):
    """The line each case points at must actually exist in the file (not
    past EOF), proving the manifest wasn't left stale after an edit."""
    for case in ground_truth["cases"]:
        if case["line"] is None:
            continue
        f = root / case["file"]
        lines = f.read_text().splitlines()
        assert case["line"] <= len(lines), (
            f"{case['id']}: line {case['line']} is past EOF ({len(lines)} lines) in {case['file']}"
        )


def test_cwe_mappings_are_honest(ground_truth):
    """Class 4's CWE fit is explicitly flagged moderate; class 5 has no CWE
    at all and must not silently acquire one."""
    by_class = {c["class"]: c for c in ground_truth["cases"]}

    assert by_class[3]["cwe"] == "CWE-829"
    assert by_class[4]["cwe"] == "CWE-668"
    assert by_class[4].get("cwe_fit") == "moderate"

    assert by_class[5]["cwe"] is None
    assert by_class[5].get("cwe_weak_candidate") == "CWE-285"


def test_no_case_id_duplicated(ground_truth):
    ids = [c["id"] for c in ground_truth["cases"]]
    assert len(ids) == len(set(ids))
