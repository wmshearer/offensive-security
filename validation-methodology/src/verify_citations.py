"""Check every citation in the evidence table points at the step it claims.

The methodology page is about confirming a finding is real before acting on it.
A wrong line number on that page would be the same mistake the page is about, so
every row gets checked against the source rather than trusted.

The research pass that produced the table cited 35 moments. Two were wrong: one
was a duplicate of another row filed under the wrong walkthrough, and one carried
a line number from a different case study. Both were caught here, which is the
reason this script exists rather than a manual spot-check.

Usage:  python3 src/verify_citations.py
Exit 0 if every citation resolves, 1 otherwise.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

APP = Path("/home/kali/director/projects/wshearer-site/src/App.jsx")
TABLE = Path(__file__).resolve().parent.parent / "docs" / "evidence.json"


def step_titles_at(lines: list[str], start: int, end: int) -> list[str]:
    """Return every Step title= found in the inclusive 1-indexed line range."""
    window = "".join(lines[start - 1 : end])
    return re.findall(r'title="([^"]*)"', window)


def check(row: dict, lines: list[str]) -> tuple[bool, str]:
    start, end = row["line_start"], row["line_end"]
    if start < 1 or end > len(lines):
        return False, f"range {start}-{end} outside file (1-{len(lines)})"
    titles = step_titles_at(lines, start, end)
    if not titles:
        return False, f"no Step title found at {start}-{end}"
    want = row["step_title"]
    if want not in titles:
        return False, f"expected {want!r}, found {titles!r}"
    return True, titles[titles.index(want)]


def main() -> int:
    if not APP.exists():
        print(f"source not found: {APP}")
        return 1
    lines = APP.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    rows = json.loads(TABLE.read_text(encoding="utf-8"))

    ok = bad = 0
    for row in rows:
        passed, detail = check(row, lines)
        if passed:
            ok += 1
        else:
            bad += 1
            print(f"FAIL  {row['slug']:<24} row {row['id']:>2}  {detail}")

    print(f"\n{ok} citations verified, {bad} failed, {len(rows)} rows total")
    if bad == 0:
        print("Every row points at the step it claims.")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
