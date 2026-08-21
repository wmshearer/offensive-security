"""Build a ransomware technique list from ATT&CK, with provenance per family.

THE PROBLEM THIS SOLVES

"Which ATT&CK techniques are ransomware techniques" has no published answer.
MITRE does not ship a Ransomware grouping: there is no campaign object, no label,
and no taxonomy field for it. Checking the bundle directly, zero objects are named
for ransomware as a category.

What does exist is individual families as `malware` objects, each linked to the
techniques it uses by `relationship` objects of type "uses". So the list gets
built by naming families and traversing, and every technique in the result traces
to a MITRE relationship with an id rather than to my judgement.

WHY THE FAMILY LIST IS THE HONEST WEAK POINT

Choosing which families count is a judgement call, and it is the one place this
analysis could be steered. So the choice is made on a stated external rule rather
than on what produces a good number: families that CISA has published a
#StopRansomware advisory about, plus the families MITRE tracks with substantial
technique coverage. The list is small, named, and printed with the results so a
reader can disagree with it specifically.

Cross-checking: where CISA's advisory carries its own technique table, the
STIX-derived list can be diffed against it. AA23-165A does this for LockBit.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Reuse the bundle the cloud coverage project already downloaded rather than
# fetching a second 54MB copy. Same file, same version, one copy on disk.
STIX = (
    ROOT.parent / "cloud-detection-coverage" / "data" / "enterprise-attack.json"
)

# Families selected by a stated rule, not by which produced a better result.
# Each has either a CISA #StopRansomware advisory or substantial MITRE tracking.
# ATT&CK names them inconsistently (versioned entries like "LockBit 3.0", aliases
# like BlackCat/ALPHV), so matching is on a normalised prefix.
FAMILY_PREFIXES = (
    "LockBit",
    "Conti",
    "BlackCat",
    "Royal",
    "Akira",
    "Ryuk",
    "REvil",
    "Sodinokibi",
    "Clop",
    "BlackBasta",
    "Black Basta",
    "Play",
    "Hive",
    "Maze",
    "Ragnar",
    "DarkSide",
)


@dataclass(frozen=True)
class Family:
    stix_id: str
    name: str
    aliases: tuple[str, ...]
    techniques: frozenset[str]


def _external_id(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return str(ref.get("external_id", ""))
    return ""


def load_families(bundle_path: Path = STIX) -> list[Family]:
    """Resolve each named family to its malware object and traverse `uses`."""
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    objects = bundle["objects"]

    by_id = {o["id"]: o for o in objects}

    malware: dict[str, dict] = {}
    for obj in objects:
        if obj.get("type") != "malware" or obj.get("revoked"):
            continue
        if obj.get("x_mitre_deprecated"):
            continue
        name = obj.get("name", "")
        if any(name.startswith(prefix) for prefix in FAMILY_PREFIXES):
            malware[obj["id"]] = obj

    uses: dict[str, set[str]] = defaultdict(set)
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "uses":
            continue
        source = obj.get("source_ref", "")
        target = obj.get("target_ref", "")
        if source in malware and target.startswith("attack-pattern--"):
            technique = by_id.get(target)
            if not technique or technique.get("revoked"):
                continue
            tid = _external_id(technique)
            if tid:
                uses[source].add(tid)

    families = []
    for stix_id, obj in malware.items():
        techniques = uses.get(stix_id, set())
        if not techniques:
            # A family MITRE tracks but has recorded no technique for adds
            # nothing and would pad the family count.
            continue
        families.append(
            Family(
                stix_id=stix_id,
                name=obj.get("name", ""),
                aliases=tuple(obj.get("x_mitre_aliases", ())),
                techniques=frozenset(techniques),
            )
        )
    return sorted(families, key=lambda f: -len(f.techniques))


def technique_union(families: list[Family]) -> set[str]:
    out: set[str] = set()
    for family in families:
        out |= family.techniques
    return out


def technique_provenance(families: list[Family]) -> dict[str, list[str]]:
    """Which families use each technique. A technique used by one family is a
    weaker basis for calling it a ransomware technique than one used by ten."""
    out: dict[str, list[str]] = defaultdict(list)
    for family in families:
        for tid in family.techniques:
            out[tid].append(family.name)
    return {k: sorted(v) for k, v in sorted(out.items())}


def technique_names(bundle_path: Path = STIX) -> dict[str, str]:
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    out = {}
    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern" or obj.get("revoked"):
            continue
        tid = _external_id(obj)
        if tid:
            out[tid] = obj.get("name", "")
    return out


def main() -> None:
    families = load_families()
    union = technique_union(families)
    provenance = technique_provenance(families)
    names = technique_names()

    print(f"{len(families)} ransomware families resolved in ATT&CK\n")
    for family in families:
        print(f"  {len(family.techniques):>3} techniques  {family.name}")

    print(f"\n{len(union)} distinct techniques across all of them\n")

    shared = {t: f for t, f in provenance.items() if len(f) >= 4}
    print(f"{len(shared)} techniques are used by 4 or more families:")
    for tid in sorted(shared, key=lambda t: (-len(provenance[t]), t))[:12]:
        n = len(provenance[tid])
        print(f"  {n:>2} families  {tid:<12} {names.get(tid, '')}")

    singles = [t for t, f in provenance.items() if len(f) == 1]
    print(f"\n{len(singles)} techniques come from a single family, which is a")
    print("weaker basis for calling them ransomware techniques.")


if __name__ == "__main__":
    main()
