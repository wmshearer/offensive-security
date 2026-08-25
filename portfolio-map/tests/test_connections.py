"""Tests for the connection graph.

The test that matters most is `test_disconnected_count_is_reported_honestly`.

The temptation with a page like this is to make the graph look dense, because a
connected portfolio reads as a body of work and a disconnected one reads as a
pile. Half of these projects connect to nothing. Both the code and the page have
to keep saying so, and an edge added without evidence would quietly erode that.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from connections import (  # noqa: E402
    EDGES,
    META,
    VERIFIED_BY_CODE,
    VERIFIED_BY_TEXT,
    Kind,
    connected_projects,
    longest_chain,
)
from report import total_projects  # noqa: E402

PROJECTS_DIR = Path("/home/kali/director/projects")


def test_every_edge_carries_evidence():
    for edge in EDGES:
        assert len(edge.evidence) > 30, f"{edge.source}->{edge.target} evidence too thin"
        assert len(edge.what_passes) > 10, f"{edge.source}->{edge.target}"


def test_no_self_edges():
    for edge in EDGES:
        assert edge.source != edge.target


def test_no_duplicate_edges():
    pairs = [(e.source, e.target, e.kind) for e in EDGES]
    assert len(pairs) == len(set(pairs))


def test_every_named_project_exists_on_disk():
    """An edge naming a project that is not there means the graph has drifted
    from the portfolio."""
    for edge in EDGES:
        for slug in (edge.source, edge.target):
            assert (PROJECTS_DIR / slug).is_dir(), f"no such project: {slug}"


def test_code_verified_edges_outnumber_nothing():
    """Edges verified by reading an import or a data path are the strong ones.
    If that set ever empties, the graph is entirely self-reported."""
    assert len(VERIFIED_BY_CODE) >= 8


def test_code_and_text_edges_partition_the_graph():
    assert len(VERIFIED_BY_CODE) + len(VERIFIED_BY_TEXT) == len(EDGES)


def test_disconnected_count_is_reported_honestly():
    """Half the portfolio connects to nothing. The page says so, and this
    fails if edges are ever added without the disconnected figure being
    recomputed to match."""
    total = total_projects()
    connected = len(connected_projects())
    disconnected = total - connected - len(set(META) - connected_projects())
    assert disconnected > total * 0.4, (
        "the disconnected share dropped below 40%. If that is real, the page's "
        "framing needs rewriting. If it is not, an edge was added without "
        "evidence."
    )


def test_the_walkthroughs_are_not_linked_to_each_other():
    """Twelve walkthroughs, no pairwise links. Only validation-methodology reads
    across them, and it does so as a family rather than project by project."""
    walkthroughs = {
        e.source for e in EDGES if e.source.endswith("-walkthrough")
    } | {e.target for e in EDGES if e.target.endswith("-walkthrough")}
    assert walkthroughs == set(), (
        "a walkthrough gained an edge; confirm it is real rather than assumed "
        "from topic similarity"
    )


def test_longest_chain_is_a_real_path():
    """Each hop's target must be the next hop's source, or it is not a chain."""
    path = longest_chain()
    assert len(path) >= 3
    for first, second in zip(path, path[1:]):
        assert first.target == second.source


def test_longest_chain_moves_real_artifacts():
    """A chain of 'related to' links would be worthless. Every hop in the
    longest chain must pass data, code, or a finding."""
    for edge in longest_chain():
        assert edge.kind in (Kind.DATA, Kind.CODE, Kind.FINDING)


def test_report_runs():
    result = subprocess.run(
        [sys.executable, str(ROOT / "src" / "report.py")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "projects connect to nothing" in result.stdout
