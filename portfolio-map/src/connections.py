"""The verified connection graph between projects in this portfolio.

WHY THIS EXISTS

Fifty-six projects rendered as a list look like fifty-six unrelated pieces of
work. Some of them are. But several share data, fork each other's code, or test
one another's findings, and none of that is visible from a grid of cards.

THE RULE THIS FILE FOLLOWS

An edge exists only if something checkable establishes it: an import statement, a
filesystem path to a sibling's data, a vendored file that names its source, or a
project's own text stating the relationship. Two projects being about the same
topic is not a connection. Category membership is already on the site.

That rule matters because the interesting result here is negative. Most of this
portfolio does not connect. Roughly thirty of the fifty-six projects have no
stated relationship to any sibling, and the twelve walkthroughs do not reference
each other at all. A graph that implied otherwise would be the more flattering
picture and the false one.

EDGE KINDS
  data      one project reads or vendors another's dataset
  code      one project imports, forks, or copies another's implementation
  finding   one project acts on, extends, or re-tests another's result
  contrast  one project's result revises or complicates another's
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Kind(str, Enum):
    DATA = "data"
    CODE = "code"
    FINDING = "finding"
    CONTRAST = "contrast"


@dataclass(frozen=True)
class Edge:
    source: str
    target: str
    kind: Kind
    what_passes: str
    #: Where the relationship is established. A file path plus what it contains,
    #: not a paraphrase. Every one of these was opened and read.
    evidence: str


# Edges verified by reading the code or data path that creates them. These are
# dependencies, not descriptions: delete the source project and the target
# breaks.
VERIFIED_BY_CODE = (
    Edge(
        "atlas-coverage-map",
        "signal-stitching",
        Kind.CODE,
        "the ATLAS keyword-mapping rules, copied verbatim",
        "signal-stitching/src/atlas_techniques.py names its source file and "
        "explains that a direct import would resolve against the wrong package",
    ),
    Edge(
        "ai-triage-engine",
        "ai-abuse-triage",
        Kind.CODE,
        "confusion matrix, MCC, and Wilson interval implementations",
        "ai-abuse-triage/src/metrics.py: 'Adapted from the sibling "
        "ai-triage-engine project's eval/metrics.py'",
    ),
    Edge(
        "ai-actor-profile-gtg1002",
        "gtg1002-exec-brief",
        Kind.FINDING,
        "25 sourced claims, restated for a different audience with nothing added",
        "gtg1002-exec-brief/data/brief.py line 26: "
        "'from data.source_profile import ...'",
    ),
    Edge(
        "llm-abuse-detection",
        "sql-vs-python-detection",
        Kind.CODE,
        "seven detection rules, imported rather than reimplemented",
        "sql-vs-python-detection/src/build_db.py line 9 points SRC at "
        "llm-abuse-detection/data",
    ),
    Edge(
        "signal-stitching",
        "threat-intel-datamart",
        Kind.DATA,
        "8 MISP campaign exports, 8,591 indicators, read not copied",
        "threat-intel-datamart/src/build.py line 34 points SOURCE at "
        "signal-stitching/data/campaigns",
    ),
    Edge(
        "ioc-investigation-tool",
        "signal-stitching",
        Kind.DATA,
        "8 MISP campaign events, vendored",
        "signal-stitching/data/campaigns/ holds the vendored copies",
    ),
    Edge(
        "ai-redteam-harness",
        "ai-abuse-ir",
        Kind.FINDING,
        "six recorded attacks against a live target, four successful",
        "ai-abuse-ir/tests/test_sourcing.py reads the harness's "
        "evidence/attack_results.json and fails if the playbooks disagree with it",
    ),
    Edge(
        "detection-rule-lab",
        "ransomware-readiness",
        Kind.DATA,
        "a scoring run of 2,691 rules against 834,226 malicious events",
        "ransomware-readiness/src/scoring.py loads "
        "detection-rule-lab/reports/scoring-run.json",
    ),
)

# Edges a project states in its own text. Weaker than an import, still checkable.
VERIFIED_BY_TEXT = (
    Edge(
        "ai-threat-intel-analysis",
        "atlas-coverage-map",
        Kind.DATA,
        "16 documented cases, mapped to ATLAS techniques",
        "atlas-coverage-map states the cases are walked through the same keyword "
        "mapping ai-threat-intel-analysis uses on its own data",
    ),
    Edge(
        "ai-threat-intel-analysis",
        "ai-abuse-triage",
        Kind.DATA,
        "the same 16 real cases, as a scoring corpus",
        "ai-abuse-triage: 'Corpus: 16 real cases (synthetic=False) pulled from "
        "ai-threat-intel-analysis'",
    ),
    Edge(
        "jailbreak-corpus-analysis",
        "llm-abuse-detection",
        Kind.DATA,
        "1,405 real jailbreak prompts",
        "llm-abuse-detection names the sibling project and the upstream source, "
        "verazuo/jailbreak_llms (MIT)",
    ),
    Edge(
        "llm-abuse-detection",
        "detection-engineering-lifecycle",
        Kind.FINDING,
        "a rule that fires zero times across 2,810 prompts",
        "the lifecycle project traces that rule through every stage as its "
        "worked example",
    ),
    Edge(
        "sql-vs-python-detection",
        "detection-engineering-lifecycle",
        Kind.FINDING,
        "an independent re-implementation finding the same zero fires",
        "the lifecycle project cross-checks the dead rule against the SQL "
        "re-implementation",
    ),
    Edge(
        "actor-name-crosswalk",
        "threat-intel-requirements",
        Kind.FINDING,
        "87 of 1,403 synonyms that are the other catalog's IDs cited back",
        "threat-intel-requirements builds a circular-corroboration check "
        "directly on that finding",
    ),
    Edge(
        "ai-triage-engine",
        "abuse-program-metrics",
        Kind.CONTRAST,
        "a pooled MCC of 0.014 hiding strata at 0.695 and -0.693",
        "abuse-program-metrics back-solves the confusion matrix and states "
        "plainly that its reconstructed pooled figure (0.096) is not the "
        "published one (0.014)",
    ),
    Edge(
        "redteam-program-charter",
        "abuse-program-charter",
        Kind.CODE,
        "the charter structure, re-pointed at a different problem",
        "Authority, Scope, Metrics and Governance carried over; Rules of "
        "Engagement and Deconfliction dropped as not applicable",
    ),
    Edge(
        "cib-detection",
        "sockpuppet-stylometry",
        Kind.CONTRAST,
        "the same four Twitter Election Integrity releases, a weaker signal",
        "stylometry is reported as weaker and more expensive overall, while "
        "beating the hashtag result on the one operation where it works",
    ),
    Edge(
        "cib-detection",
        "doppelganger-case-study",
        Kind.CONTRAST,
        "a hashtag detector that the affidavit evidence contradicts",
        "searching the affidavit for 'hashtag' returns one passage, and it "
        "describes the opposite of what the detector measures",
    ),
    Edge(
        "cib-detection",
        "ransomware-ecosystem",
        Kind.CONTRAST,
        "a co-timing signal that turned out to be a collection artifact",
        "described as the same trap the companion project hit from the "
        "opposite direction",
    ),
    Edge(
        "doppelganger-case-study",
        "narrative-timeline",
        Kind.DATA,
        "the same DOJ affidavit, asked a different question",
        "narrative-timeline names the same source document",
    ),
    Edge(
        "ai-triage-engine",
        "detection-rule-lab",
        Kind.CODE,
        "contamination controls",
        "detection-rule-lab cross-links to the triage engine whose "
        "contamination controls its corpus reuses",
    ),
)

EDGES = VERIFIED_BY_CODE + VERIFIED_BY_TEXT

# Projects that read across a whole family rather than pairing with one sibling.
# Kept separate because calling these twelve separate edges would inflate the
# graph with what is really one relationship.
META = {
    "validation-methodology": (
        "reads all twelve HackTheBox walkthroughs and extracts the validation "
        "checks they have in common. The walkthroughs do not reference each "
        "other; this is the only thing that reads across them."
    ),
    "threat-intel-requirements": (
        "uses sibling projects as the collection and production evidence for one "
        "priority intelligence requirement walked through the JP 2-0 cycle."
    ),
    "abuse-program-charter": (
        "cites four sibling projects' numbers as worked examples, each checked "
        "against that project's own results before being used."
    ),
}


def out_degree() -> dict[str, int]:
    counts: dict[str, int] = {}
    for edge in EDGES:
        counts[edge.source] = counts.get(edge.source, 0) + 1
    return counts


def degree() -> dict[str, int]:
    """Total connections, in or out."""
    counts: dict[str, int] = {}
    for edge in EDGES:
        counts[edge.source] = counts.get(edge.source, 0) + 1
        counts[edge.target] = counts.get(edge.target, 0) + 1
    return counts


def connected_projects() -> set[str]:
    out: set[str] = set()
    for edge in EDGES:
        out.add(edge.source)
        out.add(edge.target)
    return out


def chain(start: str) -> list[list[Edge]]:
    """Every path leading out of a project, depth first.

    Used to find the longest chain rather than asserting one. A hub with many
    one-hop spokes is a weaker structure than a path where data flows through
    several projects in sequence, and only walking it shows which you have.
    """
    paths: list[list[Edge]] = []

    def walk(node: str, path: list[Edge], seen: set[str]) -> None:
        extended = False
        for edge in EDGES:
            if edge.source == node and edge.target not in seen:
                extended = True
                walk(edge.target, [*path, edge], seen | {edge.target})
        if not extended and path:
            paths.append(path)

    walk(start, [], {start})
    return paths


def longest_chain() -> list[Edge]:
    best: list[Edge] = []
    for project in connected_projects():
        for path in chain(project):
            if len(path) > len(best):
                best = path
    return best
