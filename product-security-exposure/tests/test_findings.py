"""Tests pinning the published findings to the saved tool output.

The images are rebuildable from data/Dockerfile.* but are not in the repo, so these
run against the captured evidence, which is what the writeup quotes.
"""
import json, re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EV = ROOT / "evidence"


def read(n):
    return (EV / n).read_text(errors="replace")


def test_sbom_found_the_component():
    # Reads the committed summary rather than the multi-megabyte raw SBOM, so the
    # suite works from a fresh clone. Regenerate both with scripts/scan.sh.
    sbom = json.loads(read("sbom-summary.json"))
    assert sbom["packages"] == 142
    assert sbom["gguf"]["version"] == "0.19.0"


def test_scanner_found_many_vulns_but_none_in_gguf():
    # The headline. 160 findings, 7 critical, and zero for the one component
    # with a demonstrated exploit.
    g = json.loads(read("grype-summary.json"))
    assert g["total"] == 160
    sev = {b["severity"]: b["count"] for b in g["by_severity"]}
    assert sev["Critical"] == 7
    assert sev["High"] == 28
    assert g["gguf_findings"] == [], g["gguf_findings"]


def test_shipped_image_is_affected():
    before = read("before.txt")
    assert "parsed with no error" in before
    t = float(re.search(r"time taken:\s+([\d.]+)s", before).group(1))
    assert t > 5, f"expected a slow parse, got {t}s"
    assert "AFFECTED" in before


def test_patched_image_rejects_it_immediately():
    after = read("after.txt")
    assert "ValueError" in after
    t = float(re.search(r"time taken:\s+([\d.]+)s", after).group(1))
    assert t < 1, f"expected an immediate rejection, got {t}s"


def test_cost_ratio_is_stable_enough_to_extrapolate():
    # The claim is ~3.9 s/MB holding across two orders of magnitude. If the
    # ratio drifted, the "one client saturates a worker" argument would not hold.
    ratios = [float(m) for m in re.findall(r"([\d.]+) s/MB", read("impact.txt"))]
    assert len(ratios) == 4
    assert max(ratios) - min(ratios) < 0.5, ratios
    assert all(3.5 < r < 4.5 for r in ratios), ratios


def test_the_fix_breaks_no_valid_files():
    reg = read("regression.txt")
    assert "valid files tested:  55" in reg
    assert "wrongly rejected:    0" in reg
