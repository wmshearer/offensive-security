"""Re-read an existing detection scoring run through a ransomware lens.

WHY THIS REUSES RATHER THAN RERUNS

A sibling project, detection-rule-lab, already ran 2,691 Sigma rules against
834,226 malicious and 110,095 benign Windows events using Zircolite. 135 rules
fired. Every one of those results carries its ATT&CK technique tags alongside
real malicious and benign hit counts.

So the ransomware question does not need a new measurement. It needs the existing
one filtered: of the rules that demonstrably fired on real attack traffic, which
cover techniques that documented ransomware operations actually use?

That is a stronger claim than the cloud coverage sibling could make. That project
could only count what rules CLAIM, because no licensed cloud event corpus existed.
Here the events exist and the rules were already fired against them, so this
counts what WORKED.

WHAT IT STILL CANNOT SAY

The corpus is Windows endpoint telemetry from a handful of hosts. A rule firing
here is evidence it fires on that traffic, not evidence it would fire in any
particular organisation. And the benign side is small enough that hit counts are
reported rather than a false-positive rate, which is the sibling project's
decision and is kept here for the same reason.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SIBLING_RUN = (
    ROOT.parent / "detection-rule-lab" / "reports" / "scoring-run.json"
)


@dataclass(frozen=True)
class FiredRule:
    """A rule that matched at least one event in the sibling project's run."""

    rule_id: str
    title: str
    level: str
    techniques: tuple[str, ...]
    malicious_hits: int
    benign_hits: int

    @property
    def malicious_only(self) -> bool:
        return self.malicious_hits > 0 and self.benign_hits == 0

    @property
    def noisy(self) -> bool:
        """Fired on benign events. Not automatically wrong: a rule can be
        correct and still match ordinary activity. It is a cost, not a verdict.
        """
        return self.benign_hits > 0


@dataclass(frozen=True)
class ScoringRun:
    malicious_events: int
    benign_events: int
    rules_loaded: int
    rules_fired: int
    rules_silent: int
    results: tuple[FiredRule, ...]

    @property
    def techniques_covered(self) -> set[str]:
        out: set[str] = set()
        for rule in self.results:
            out.update(rule.techniques)
        return out


def load_run(path: Path = SIBLING_RUN) -> ScoringRun:
    if not path.exists():
        raise FileNotFoundError(
            f"sibling scoring run not found at {path}. This project reads "
            "detection-rule-lab's published results rather than recomputing them."
        )
    raw = json.loads(path.read_text(encoding="utf-8"))
    summary = raw["summary"]
    results = tuple(
        FiredRule(
            rule_id=r["rule_id"],
            title=r["title"],
            level=r.get("level", ""),
            techniques=tuple(r.get("attack_techniques") or ()),
            malicious_hits=r.get("malicious_hits", 0),
            benign_hits=r.get("benign_hits", 0),
        )
        for r in raw["results"]
    )
    return ScoringRun(
        malicious_events=summary["malicious_events"],
        benign_events=summary["benign_events"],
        rules_loaded=summary["rules_loaded"],
        rules_fired=summary["rules_fired"],
        rules_silent=summary["rules_silent"],
        results=results,
    )


def parent_of(technique: str) -> str:
    """T1486.001 -> T1486. A rule tagged with a sub-technique demonstrates
    coverage of that branch of the parent, so both are credited."""
    return technique.split(".")[0]


def expand(techniques: set[str]) -> set[str]:
    """Add parent ids so sub-technique tags match parent-level lists."""
    return techniques | {parent_of(t) for t in techniques}


@dataclass
class RansomwareCoverage:
    """How much of a ransomware technique set is covered by rules that actually
    fired, as opposed to rules that merely claim the technique."""

    technique_ids: set[str]
    fired_rules: tuple[FiredRule, ...]

    @property
    def matching_rules(self) -> list[FiredRule]:
        wanted = expand(self.technique_ids)
        return [
            rule
            for rule in self.fired_rules
            if expand(set(rule.techniques)) & wanted
        ]

    @property
    def covered_techniques(self) -> set[str]:
        fired = set()
        for rule in self.fired_rules:
            fired |= expand(set(rule.techniques))
        return {t for t in self.technique_ids if t in fired}

    @property
    def uncovered_techniques(self) -> set[str]:
        return self.technique_ids - self.covered_techniques

    def summary(self) -> dict:
        matching = self.matching_rules
        return {
            "techniques_total": len(self.technique_ids),
            "techniques_covered": len(self.covered_techniques),
            "techniques_uncovered": len(self.uncovered_techniques),
            "rules_matching": len(matching),
            "rules_malicious_only": sum(1 for r in matching if r.malicious_only),
            "rules_touching_benign": sum(1 for r in matching if r.noisy),
        }
