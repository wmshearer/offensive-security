"""The readiness rubric, as something you can run.

Categories follow CISA CPG v2.0's six Functions; control content draws on the
#StopRansomware Guide v3.0. The weights and the 0/1/2 scale are mine, and
docs/RUBRIC.md says so plainly, because no CISA or NIST document publishes a
numeric ransomware maturity score.

The per-category score is the output that matters. An overall figure is printed
because people ask for one, and it is printed alongside the category breakdown
so it cannot travel alone. A single number hiding a bad category is the failure
the abuse-program-metrics project documented, where a pooled 0.014 concealed
strata at 0.695 and -0.693.
"""

from __future__ import annotations

from dataclasses import dataclass, field

#: 2 requires verification within 12 months, not just presence. Backups that have
#: never been restored from are the most common finding in ransomware
#: post-incident reviews, and an unverified control is a plan, not a defence.
NOT_IN_PLACE = 0
PARTIAL = 1
VERIFIED = 2


@dataclass(frozen=True)
class Control:
    id: str
    text: str


@dataclass(frozen=True)
class Category:
    name: str
    weight: float
    controls: tuple[Control, ...]


RUBRIC: tuple[Category, ...] = (
    Category("Govern", 1.0, (
        Control("G1", "A named owner is accountable for ransomware readiness"),
        Control("G2", "An incident response plan names decision authority on ransom payment"),
        Control("G3", "Legal, comms and law enforcement contacts exist before an incident"),
        Control("G4", "Insurance coverage and its notification requirements are understood"),
    )),
    Category("Identify", 1.0, (
        Control("I1", "An asset inventory exists and is current"),
        Control("I2", "Crown-jewel systems are identified and prioritised for recovery"),
        Control("I3", "External attack surface is enumerated on a schedule"),
        Control("I4", "Third-party and MSP access is inventoried"),
    )),
    Category("Protect", 1.5, (
        Control("P1", "MFA enforced on all remote access and privileged accounts"),
        Control("P2", "Internet-facing services patched on a defined schedule"),
        Control("P3", "Backups are offline or immutable and credential-segmented"),
        Control("P4", "Restoration from backup tested end to end within 12 months"),
        Control("P5", "Segmentation limits lateral movement from one host"),
        Control("P6", "Privileged accounts separated from daily-use accounts"),
        Control("P7", "Macros from internet-sourced documents blocked by policy"),
    )),
    Category("Detect", 1.25, (
        Control("D1", "Endpoint telemetry collected centrally, retained 90+ days"),
        Control("D2", "Detection content covers techniques ransomware families use"),
        Control("D3", "Alerts reach a human resourced to act on them"),
        Control("D4", "Detection coverage is measured rather than assumed"),
    )),
    Category("Respond", 1.0, (
        Control("R1", "Isolation executable without the network being available"),
        Control("R2", "Out-of-band communications exist for use when systems are down"),
        Control("R3", "Response roles assigned and exercised"),
        Control("R4", "Evidence preservation defined before systems are rebuilt"),
    )),
    Category("Recover", 1.25, (
        Control("C1", "Recovery time objectives defined and known to be achievable"),
        Control("C2", "Rebuild procedures exist for critical systems"),
        Control("C3", "A post-incident review process exists and produces changes"),
    )),
)


@dataclass
class Assessment:
    """Scores keyed by control id. Missing controls count as not in place, so a
    partial assessment cannot flatter itself by omission."""

    scores: dict[str, int] = field(default_factory=dict)

    def category_score(self, category: Category) -> float:
        total = sum(self.scores.get(c.id, NOT_IN_PLACE) for c in category.controls)
        return total / (VERIFIED * len(category.controls))

    def overall(self) -> float:
        weighted = sum(self.category_score(c) * c.weight for c in RUBRIC)
        return weighted / sum(c.weight for c in RUBRIC)

    def weakest(self) -> Category:
        return min(RUBRIC, key=self.category_score)

    def unverified(self) -> list[Control]:
        """Controls claimed as present but not verified. These are the gap
        between a plan and a defence."""
        out = []
        for category in RUBRIC:
            for control in category.controls:
                if self.scores.get(control.id, NOT_IN_PLACE) == PARTIAL:
                    out.append(control)
        return out

    def report(self) -> str:
        lines = ["Ransomware readiness assessment", ""]
        for category in RUBRIC:
            score = self.category_score(category)
            bar = "#" * int(round(score * 20))
            lines.append(
                f"  {category.name:<10} {score:>6.0%}  (weight {category.weight})  {bar}"
            )
        lines.append("")
        lines.append(f"  Overall    {self.overall():>6.0%}")
        lines.append("")

        weakest = self.weakest()
        lines.append(
            f"Weakest category: {weakest.name} at {self.category_score(weakest):.0%}."
        )
        lines.append("Read the categories, not the total. A strong overall score with")
        lines.append("one weak category is a specific problem the total hides.")

        unverified = self.unverified()
        if unverified:
            lines.append("")
            lines.append(f"{len(unverified)} controls are in place but unverified:")
            for control in unverified:
                lines.append(f"  {control.id}  {control.text}")
            lines.append("")
            lines.append("An unverified control is a plan. P4 is the one that matters")
            lines.append("most: untested backups are the most common finding in")
            lines.append("ransomware post-incident reviews.")
        return "\n".join(lines)


def worked_example() -> Assessment:
    """An illustrative organisation, not a real one.

    Shaped to show the pattern the rubric exists to surface: strong on the
    controls that are easy to buy and weak on the ones that need practice. MFA
    and patching are verified; backup restoration and response exercises are
    claimed but untested; recovery objectives were never defined.
    """
    return Assessment({
        "G1": VERIFIED, "G2": PARTIAL, "G3": PARTIAL, "G4": VERIFIED,
        "I1": VERIFIED, "I2": PARTIAL, "I3": VERIFIED, "I4": NOT_IN_PLACE,
        "P1": VERIFIED, "P2": VERIFIED, "P3": VERIFIED, "P4": PARTIAL,
        "P5": PARTIAL, "P6": VERIFIED, "P7": VERIFIED,
        "D1": VERIFIED, "D2": PARTIAL, "D3": VERIFIED, "D4": NOT_IN_PLACE,
        "R1": PARTIAL, "R2": NOT_IN_PLACE, "R3": PARTIAL, "R4": PARTIAL,
        "C1": NOT_IN_PLACE, "C2": PARTIAL, "C3": PARTIAL,
    })


def main() -> None:
    print(worked_example().report())
    print()
    print("Scores above are an illustrative example, not a real organisation.")


if __name__ == "__main__":
    main()
