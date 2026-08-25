"""Find a sibling project without assuming it is one directory up.

This project reads two artifacts produced by other projects: the ATT&CK STIX
bundle from cloud-detection-coverage, and the scoring run from
detection-rule-lab.

The original code reached them with `ROOT.parent / "<project>"`, which assumed
every project sat directly beside this one. Repo consolidation broke that:
detection-rule-lab moved into the detection-methodology repo and this project
moved into security-program-design, so they are no longer siblings on disk.

Searching upward for a directory by name finds them wherever they ended up,
including one level down inside a consolidated repo.
"""

from pathlib import Path


def find_project(name: str, start: Path | None = None) -> Path:
    """Return the path to project `name`, searching upward then one level in.

    Raises FileNotFoundError naming what was searched, rather than returning a
    path that does not exist and failing later somewhere less obvious.
    """
    here = (start or Path(__file__)).resolve()
    searched = []
    for parent in here.parents:
        direct = parent / name
        searched.append(direct)
        if direct.is_dir():
            return direct
        # a consolidated repo holds projects one level down
        for child in sorted(parent.glob("*/" + name)):
            if child.is_dir():
                return child
    raise FileNotFoundError(
        f"project {name!r} not found above {here}; looked in "
        + ", ".join(str(p) for p in searched[:4])
    )
