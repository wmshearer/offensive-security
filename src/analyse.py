"""Which ransomware techniques does a real detection run actually catch?

This joins two things:

  1. 95 techniques used by 14 ransomware families, derived from ATT&CK
     relationship objects rather than from anyone's judgement about what counts
     as a ransomware technique.

  2. A scoring run in which 2,691 Sigma rules were fired against 834,226
     malicious and 110,095 benign Windows events, of which 135 rules matched
     something.

The join answers a question the sibling cloud project could not: not what rules
CLAIM to cover, but which ransomware techniques are covered by rules that
demonstrably fire on real attack traffic.

TWO CONFIDENCE TIERS

A technique used by 14 of 14 families is ransomware behaviour by any reading. One
used by a single family might just be that family's habit. So results are
reported at two thresholds, and the stricter one is the headline. Reporting only
the union would let 44 single-family techniques carry the same weight as
encrypting files for impact.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from scoring import RansomwareCoverage, load_run  # noqa: E402
from techniques import (  # noqa: E402
    load_families,
    technique_names,
    technique_provenance,
    technique_union,
)

ROOT = Path(__file__).resolve().parent.parent

#: A technique used by this many families or more is treated as core ransomware
#: behaviour. Four is a judgement call and is stated rather than buried: it is
#: high enough to exclude one family's quirks and low enough to keep techniques
#: that only the better-documented families have recorded.
CORE_THRESHOLD = 4


def build() -> dict:
    families = load_families()
    provenance = technique_provenance(families)
    names = technique_names()
    union = technique_union(families)
    core = {t for t, fams in provenance.items() if len(fams) >= CORE_THRESHOLD}

    run = load_run()

    all_cov = RansomwareCoverage(technique_ids=set(union), fired_rules=run.results)
    core_cov = RansomwareCoverage(technique_ids=set(core), fired_rules=run.results)

    return {
        "families": families,
        "provenance": provenance,
        "names": names,
        "union": union,
        "core": core,
        "run": run,
        "all": all_cov,
        "core_cov": core_cov,
    }


def main() -> None:
    data = build()
    run = data["run"]
    core_cov: RansomwareCoverage = data["core_cov"]
    all_cov: RansomwareCoverage = data["all"]
    names = data["names"]
    provenance = data["provenance"]

    print("Ransomware technique coverage by rules that actually fired\n")
    print(f"  {run.rules_loaded:,} Sigma rules run against "
          f"{run.malicious_events:,} malicious events")
    print(f"  {run.rules_fired} fired, {run.rules_silent:,} stayed silent")
    print(f"  {len(run.techniques_covered)} distinct techniques among the rules "
          "that fired\n")

    print(f"  {len(data['families'])} ransomware families resolved from ATT&CK")
    print(f"  {len(data['union'])} techniques across all of them")
    print(f"  {len(data['core'])} used by {CORE_THRESHOLD}+ families (core set)\n")

    core_summary = core_cov.summary()
    print(f"Core ransomware behaviour ({CORE_THRESHOLD}+ families):")
    print(f"  {core_summary['techniques_covered']} of "
          f"{core_summary['techniques_total']} covered by a rule that fired")
    print(f"  {core_summary['rules_matching']} rules match, of which "
          f"{core_summary['rules_malicious_only']} fired only on malicious events\n")

    print("Covered:")
    for tid in sorted(core_cov.covered_techniques):
        n = len(provenance[tid])
        print(f"  {tid:<12} {names.get(tid, ''):<42} {n} families")

    print("\nNot covered by any rule that fired:")
    for tid in sorted(core_cov.uncovered_techniques,
                      key=lambda t: (-len(provenance[t]), t)):
        n = len(provenance[tid])
        print(f"  {tid:<12} {names.get(tid, ''):<42} {n} families")

    all_summary = all_cov.summary()
    print(f"\nAcross all {len(data['union'])} techniques, including the 44 seen in")
    print(f"only one family: {all_summary['techniques_covered']} covered, "
          f"{all_summary['techniques_uncovered']} not.")

    print("\nWhat this does not say: that these rules would fire in any given")
    print("network. The corpus is Windows endpoint telemetry from a handful of")
    print("hosts, so a rule firing here is evidence about that traffic.")


def as_json() -> dict:
    data = build()
    core_cov: RansomwareCoverage = data["core_cov"]
    all_cov: RansomwareCoverage = data["all"]
    return {
        "families": [
            {"name": f.name, "techniques": len(f.techniques)}
            for f in data["families"]
        ],
        "techniques_all": len(data["union"]),
        "techniques_core": len(data["core"]),
        "core_threshold": CORE_THRESHOLD,
        "core": core_cov.summary(),
        "all": all_cov.summary(),
        "core_covered": sorted(core_cov.covered_techniques),
        "core_uncovered": sorted(core_cov.uncovered_techniques),
    }


if __name__ == "__main__":
    if "--json" in sys.argv:
        out = as_json()
        (ROOT / "data").mkdir(exist_ok=True)
        (ROOT / "data" / "coverage.json").write_text(
            json.dumps(out, indent=1), encoding="utf-8"
        )
        print(json.dumps(out, indent=1))
    else:
        main()
