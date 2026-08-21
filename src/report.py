"""Report the shape of the portfolio's connection graph.

Everything here is computed from connections.py rather than written down, so the
numbers cannot drift from the edge list. If an edge is added or removed, the
counts and the longest chain move with it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from connections import (  # noqa: E402
    EDGES,
    META,
    VERIFIED_BY_CODE,
    VERIFIED_BY_TEXT,
    Kind,
    connected_projects,
    degree,
    longest_chain,
)

PROJECTS_JS = Path(
    "/home/kali/director/projects/wshearer-site/src/projects.js"
)


def total_projects() -> int:
    """Count entries in the site's project list, so the disconnected figure is
    measured against reality rather than a number I remember."""
    text = PROJECTS_JS.read_text(encoding="utf-8")
    return text.count("\n    slug: '")


def main() -> None:
    total = total_projects()
    connected = connected_projects()
    meta_only = set(META) - connected

    print("Connection graph across the portfolio\n")
    print(f"  {total} projects on the site")
    print(f"  {len(EDGES)} verified connections between them")
    print(f"  {len(connected)} projects appear in at least one connection")
    print(f"  {total - len(connected) - len(meta_only)} appear in none\n")

    print("How each connection was verified:")
    print(f"  {len(VERIFIED_BY_CODE):>3}  by reading the code or data path that creates it")
    print(f"  {len(VERIFIED_BY_TEXT):>3}  by the project's own stated description\n")

    by_kind = {k: 0 for k in Kind}
    for edge in EDGES:
        by_kind[edge.kind] += 1
    print("What passes between projects:")
    for kind in Kind:
        print(f"  {by_kind[kind]:>3}  {kind.value}")

    print("\nMost connected:")
    for project, n in sorted(degree().items(), key=lambda kv: (-kv[1], kv[0]))[:6]:
        print(f"  {n:>3}  {project}")

    path = longest_chain()
    print(f"\nLongest chain, {len(path)} hops:")
    if path:
        print(f"  {path[0].source}")
        for edge in path:
            print(f"    -> {edge.target}")
            print(f"       ({edge.kind.value}) {edge.what_passes}")

    print("\nReads across a family rather than pairing with one sibling:")
    for project, note in META.items():
        print(f"  {project}")
        print(f"    {note}")

    print(f"\n{total - len(connected) - len(meta_only)} projects connect to nothing.")
    print("That includes all twelve walkthroughs, which do not reference each")
    print("other, and several standalone tools. A graph that hid that would be")
    print("the more flattering picture and the false one.")


def as_json() -> dict:
    path = longest_chain()
    return {
        "total_projects": total_projects(),
        "edges": len(EDGES),
        "connected": len(connected_projects()),
        "verified_by_code": len(VERIFIED_BY_CODE),
        "verified_by_text": len(VERIFIED_BY_TEXT),
        "longest_chain": [
            {"from": e.source, "to": e.target, "kind": e.kind.value}
            for e in path
        ],
    }


if __name__ == "__main__":
    if "--json" in sys.argv:
        print(json.dumps(as_json(), indent=1))
    else:
        main()
