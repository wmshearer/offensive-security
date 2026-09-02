#!/usr/bin/env python3
"""Score zizmor (default and auditor persona) and OpenSSF Scorecard against
ground-truth.yml, producing per-class results. Never a single blended score.

zizmor is scored at line-level TP/FP/FN because it reports exact file+line
findings. Scorecard is scored as a coarser file-level binary (did it flag the
file at all for the relevant class-shaped pattern, yes/no) because its own
Dangerous-Workflow check reports a file:line but is documented as a
repo-posture check, not a dataflow engine, and does not name a
per-vulnerability-class rule id the way zizmor does.

Reads:
  ground-truth.yml
  evidence/zizmor-default.json
  evidence/zizmor-auditor.json
  evidence/scorecard-dangerous-workflow.json

Writes:
  evidence/scoring-results.json
Prints a human-readable summary table to stdout.
"""
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML is required: pip install --break-system-packages pyyaml", file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).resolve().parent.parent


def load_ground_truth():
    with open(ROOT / "ground-truth.yml") as f:
        return yaml.safe_load(f)


def load_zizmor(path):
    """Returns list of (ident, file, line) tuples, 1-indexed line."""
    with open(path) as f:
        data = json.load(f)
    out = []
    for finding in data:
        ident = finding["ident"]
        for loc in finding.get("locations", []):
            try:
                file_path = loc["symbolic"]["key"]["Local"]["verbatim_path"]
                line = loc["concrete"]["location"]["start_point"]["row"] + 1
            except KeyError:
                continue
            out.append((ident, file_path, line))
    return out


def load_scorecard(path):
    """Returns list of (file, line, detail_text)."""
    with open(path) as f:
        data = json.load(f)
    out = []
    for check in data.get("checks", []):
        if check["name"] != "Dangerous-Workflow":
            continue
        for detail in check.get("details", []):
            # Format: "Warn: <message>: <file>:<line>"
            if ":" not in detail:
                continue
            parts = detail.rsplit(":", 2)
            if len(parts) != 3:
                continue
            message, file_path, line_str = parts
            try:
                line = int(line_str)
            except ValueError:
                continue
            out.append((file_path.strip(), line, message.strip()))
    return out


# Which zizmor rule idents count as a hit for which planted class, per the
# expected_detectors mapping in ground-truth.yml and FINDINGS.md's verified
# rule catalog (not every ident zizmor emits maps to one of our 5 classes;
# unmapped idents like unpinned-uses/artipacked are recorded separately, not
# forced into this table).
ZIZMOR_CLASS_RULES = {
    1: {"dangerous-triggers"},
    2: {"template-injection"},
    3: {"cache-poisoning"},
    4: {"self-hosted-runner"},
    5: set(),  # no rule; zizmor cannot see class 5 at all, by design
}

# zizmor idents that are real findings but do not map to any of our 5
# planted classes. Scored as "unmapped," never forced into a TP.
ZIZMOR_UNMAPPED_IDENTS = {"unpinned-uses", "artipacked", "anonymous-definition",
                          "concurrency-limits", "excessive-permissions",
                          "secrets-outside-env", "undocumented-permissions"}


def score_zizmor(ground_truth, zizmor_findings, run_label):
    cases = [c for c in ground_truth["cases"] if c["line"] is not None]
    results = {}
    all_idents_seen = set(f[0] for f in zizmor_findings)
    matched_findings = set()

    for case in cases:
        cls = case["class"]
        expected_rules = ZIZMOR_CLASS_RULES.get(cls, set())
        case_file = case["file"]
        lo, hi = case.get("line_range", [case["line"], case["line"]])
        file_ranges = [(case_file, lo, hi)]
        if case.get("paired_file"):
            plo, phi = case.get("paired_line_range", [case["paired_line"], case["paired_line"]])
            file_ranges.append((case["paired_file"], plo, phi))

        hit = False
        hit_detail = None
        for (ident, fpath, line) in zizmor_findings:
            if ident not in expected_rules:
                continue
            for (rfile, rlo, rhi) in file_ranges:
                if fpath == rfile and rlo <= line <= rhi:
                    hit = True
                    hit_detail = f"{ident} at {fpath}:{line}"
                    matched_findings.add((ident, fpath, line))
                    break
            if hit:
                break

        if not expected_rules:
            verdict = "STRUCTURALLY_CANNOT_DETECT"
        elif hit:
            verdict = "TRUE_POSITIVE"
        else:
            verdict = "FALSE_NEGATIVE"

        results[case["id"]] = {
            "class": cls,
            "name": case["name"],
            "run": run_label,
            "verdict": verdict,
            "expected_rules": sorted(expected_rules),
            "detail": hit_detail,
        }

    unmapped = sorted(all_idents_seen - set().union(*ZIZMOR_CLASS_RULES.values()))
    return results, unmapped


def score_scorecard(ground_truth, scorecard_findings):
    cases = [c for c in ground_truth["cases"] if c["line"] is not None]
    results = {}
    for case in cases:
        cls = case["class"]
        case_file = case["file"]
        case_lines = {case["line"]} | set(case.get("additional_lines", []))
        if case.get("paired_file"):
            case_file_paired = case["paired_file"]
            case_lines.add(case["paired_line"])
        else:
            case_file_paired = None

        # Scorecard is scored at file-level binary, not exact line, per the
        # documented granularity mismatch (see FINDINGS.md): "did the tool
        # flag this workflow file for a Dangerous-Workflow pattern at all."
        hit = any(f[0] == case_file or (case_file_paired and f[0] == case_file_paired)
                  for f in scorecard_findings)
        detail = None
        for f in scorecard_findings:
            if f[0] == case_file or (case_file_paired and f[0] == case_file_paired):
                detail = f"{f[0]}:{f[1]} - {f[2]}"
                break

        if cls in (3, 4, 5):
            verdict = "NOT_COVERED_BY_CHECK_DOCS"
        elif hit:
            verdict = "FLAGGED_FILE_LEVEL"
        else:
            verdict = "FALSE_NEGATIVE"

        results[case["id"]] = {
            "class": cls,
            "name": case["name"],
            "verdict": verdict,
            "detail": detail,
            "granularity": "file-level binary (Scorecard does not report a per-vulnerability-class rule id)",
        }
    return results


def compute_precision_recall(zizmor_results_by_run):
    """Per-class TP/FP/FN counts for zizmor. FP is computed as: unmapped
    findings within the same file as a planted case are NOT counted as FP
    against that case (scored as unmapped, not forced); a true FP here would
    be a zizmor finding using one of our class-mapped rule idents on a line
    that is NOT a planted case. Checked below and, for this corpus, none
    were found (recorded explicitly either way, not assumed)."""
    summary = {}
    for run_label, results in zizmor_results_by_run.items():
        by_class = {}
        for case_id, r in results.items():
            cls = r["class"]
            by_class.setdefault(cls, []).append(r["verdict"])
        summary[run_label] = by_class
    return summary


def main():
    ground_truth = load_ground_truth()

    zizmor_default = load_zizmor(ROOT / "evidence" / "zizmor-default.json")
    zizmor_auditor = load_zizmor(ROOT / "evidence" / "zizmor-auditor.json")
    scorecard_findings = load_scorecard(ROOT / "evidence" / "scorecard-dangerous-workflow.json")

    zz_default_results, zz_default_unmapped = score_zizmor(ground_truth, zizmor_default, "default")
    zz_auditor_results, zz_auditor_unmapped = score_zizmor(ground_truth, zizmor_auditor, "auditor")
    sc_results = score_scorecard(ground_truth, scorecard_findings)

    # Check for any FALSE POSITIVE: a class-mapped zizmor rule firing on a
    # file/line that is NOT one of our planted ground-truth lines for that
    # class. Scored explicitly, not assumed absent.
    def find_false_positives(zizmor_findings, run_label):
        fps = []
        # ranges_by_rule[rule] = list of (file, lo, hi) windows where a hit
        # on that rule is an expected true positive, not a false positive.
        ranges_by_rule = {}
        for case in ground_truth["cases"]:
            if case["line"] is None:
                continue
            cls = case["class"]
            expected_rules = ZIZMOR_CLASS_RULES.get(cls, set())
            lo, hi = case.get("line_range", [case["line"], case["line"]])
            windows = [(case["file"], lo, hi)]
            if case.get("paired_file"):
                plo, phi = case.get("paired_line_range", [case["paired_line"], case["paired_line"]])
                windows.append((case["paired_file"], plo, phi))
            for rule in expected_rules:
                ranges_by_rule.setdefault(rule, []).extend(windows)

        all_mapped_rules = set().union(*ZIZMOR_CLASS_RULES.values())
        for (ident, fpath, line) in zizmor_findings:
            if ident not in all_mapped_rules:
                continue
            windows = ranges_by_rule.get(ident, [])
            covered = any(fpath == rfile and rlo <= line <= rhi for (rfile, rlo, rhi) in windows)
            if not covered:
                fps.append({"run": run_label, "ident": ident, "file": fpath, "line": line})
        return fps

    zz_default_fps = find_false_positives(zizmor_default, "default")
    zz_auditor_fps = find_false_positives(zizmor_auditor, "auditor")

    output = {
        "zizmor_default": zz_default_results,
        "zizmor_auditor": zz_auditor_results,
        "zizmor_default_unmapped_idents": zz_default_unmapped,
        "zizmor_auditor_unmapped_idents": zz_auditor_unmapped,
        "zizmor_default_false_positives_on_mapped_rules": zz_default_fps,
        "zizmor_auditor_false_positives_on_mapped_rules": zz_auditor_fps,
        "scorecard": sc_results,
    }

    with open(ROOT / "evidence" / "scoring-results.json", "w") as f:
        json.dump(output, f, indent=2)

    # Human-readable summary
    print("=" * 78)
    print("zizmor — default (Regular) persona, per class")
    print("=" * 78)
    for case_id, r in sorted(zz_default_results.items(), key=lambda x: x[1]["class"]):
        print(f"  class {r['class']}  {r['name']:55s} {r['verdict']}")
    print(f"\n  unmapped idents seen (not forced into a class): {zz_default_unmapped}")
    print(f"  false positives on class-mapped rules: {len(zz_default_fps)}")

    print()
    print("=" * 78)
    print("zizmor — --persona=auditor, per class")
    print("=" * 78)
    for case_id, r in sorted(zz_auditor_results.items(), key=lambda x: x[1]["class"]):
        print(f"  class {r['class']}  {r['name']:55s} {r['verdict']}")
    print(f"\n  unmapped idents seen (not forced into a class): {zz_auditor_unmapped}")
    print(f"  false positives on class-mapped rules: {len(zz_auditor_fps)}")

    print()
    print("=" * 78)
    print("OpenSSF Scorecard — Dangerous-Workflow, per class (file-level binary)")
    print("=" * 78)
    for case_id, r in sorted(sc_results.items(), key=lambda x: x[1]["class"]):
        print(f"  class {r['class']}  {r['name']:55s} {r['verdict']}")

    print()
    print("Full machine-readable results written to evidence/scoring-results.json")


if __name__ == "__main__":
    main()
