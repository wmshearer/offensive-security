"""
grade_source.py

A small, dependency-free tool for grading a threat intelligence claim.

Two things it does NOT let you do, on purpose, because both are common mistakes:

1. Collapse source reliability and information credibility into one score.
   The Admiralty Code (NATO) scores these on two independent axes because an
   unreliable source can occasionally deliver true information, and a reliable
   source can occasionally be wrong. A single blended score throws that
   distinction away.

2. Mix estimative-probability language from different ICD 203 bands in one
   product, or fuse a likelihood word with a confidence word into one phrase
   ("likely with high confidence" written as if it were a single rating).
   ICD 203 treats likelihood and analytic confidence as separate axes.

It also flags circular corroboration: when two "independent" sources for the
same claim actually share an upstream citation, agreement between them is not
two sources confirming each other. It is one source citing itself twice. This
is modeled on a real finding from the actor-name-crosswalk project in this
portfolio: 87 of MISP's 1,403 threat-actor synonym strings are themselves
ATT&CK group IDs (e.g. G0006), meaning MISP is in part citing ATT&CK's own
catalog rather than an independent line of reporting.

Standard library only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Admiralty Code: source reliability (A-F) and information credibility (1-6)
# ---------------------------------------------------------------------------

RELIABILITY_SCALE = {
    "A": "Completely reliable",
    "B": "Usually reliable",
    "C": "Fairly reliable",
    "D": "Not usually reliable",
    "E": "Unreliable",
    "F": "Reliability cannot be judged",
}

CREDIBILITY_SCALE = {
    1: "Confirmed by other sources",
    2: "Probably true",
    3: "Possibly true",
    4: "Doubtful",
    5: "Improbable",
    6: "Truth cannot be judged",
}


class GradingError(ValueError):
    """Raised when a claim is graded in a way the scheme does not allow."""


def grade_admiralty(reliability: str, credibility: int) -> dict:
    """
    Validate and describe an Admiralty Code grading.

    reliability: one letter, A-F, describing the SOURCE.
    credibility: one integer, 1-6, describing the INFORMATION.

    These two arguments are required to be passed and read separately. There
    is no function in this module that accepts a single blended
    score, because that is the error the Admiralty Code exists to prevent.
    """
    reliability = reliability.strip().upper()
    if reliability not in RELIABILITY_SCALE:
        raise GradingError(
            f"'{reliability}' is not a valid Admiralty reliability grade. "
            f"Valid grades: {', '.join(sorted(RELIABILITY_SCALE))}. "
            "Reliability grades the SOURCE's track record, not this specific "
            "piece of information."
        )
    if credibility not in CREDIBILITY_SCALE:
        raise GradingError(
            f"'{credibility}' is not a valid Admiralty credibility grade. "
            f"Valid grades: {', '.join(str(k) for k in sorted(CREDIBILITY_SCALE))}. "
            "Credibility grades this specific piece of INFORMATION, not the "
            "source that delivered it."
        )
    return {
        "reliability_grade": reliability,
        "reliability_label": RELIABILITY_SCALE[reliability],
        "credibility_grade": credibility,
        "credibility_label": CREDIBILITY_SCALE[credibility],
        "combined_code": f"{reliability}{credibility}",
        "note": (
            "Reliability and credibility are independent axes. A low-reliability "
            "source (D, E, F) can still deliver high-credibility information "
            "(1, 2) in a given instance, and a high-reliability source (A, B) "
            "can still deliver low-credibility information. Do not average or "
            "collapse the two into a single number."
        ),
    }


def reject_blended_score(value) -> None:
    """
    Explicitly reject the common shortcut of passing one combined score
    instead of a reliability letter and a credibility number.

    Call this from calling code whenever a single scalar arrives where an
    Admiralty grading was expected, so the failure mode has a clear message
    instead of a confusing type error somewhere else.
    """
    raise GradingError(
        "A single blended score was supplied where Admiralty grading needs "
        "two separate values: a reliability letter (A-F, about the source) "
        "and a credibility number (1-6, about the information). Collapsing "
        "them into one score (e.g. treating 'B3' as 'sort of medium') throws "
        "away the reason the two-axis scheme exists: an unreliable source can "
        "occasionally be right, and a reliable source can occasionally be "
        f"wrong. Received: {value!r}"
    )


# ---------------------------------------------------------------------------
# ICD 203 words of estimative probability
# ---------------------------------------------------------------------------

# Ordered low to high probability. Row index doubles as the "row number" used
# to detect mixing of terms from different rows.
ICD203_BANDS = [
    ("almost no chance", 1, 5),
    ("very unlikely", 5, 20),
    ("unlikely", 20, 45),
    ("roughly even chance", 45, 55),
    ("likely", 55, 80),
    ("very likely", 80, 95),
    ("almost certain", 95, 99),
]

# Accept a few verbatim variants seen in practice without adding new bands.
_ICD203_ALIASES = {
    "almost certainly": "almost certain",
}

_PHRASE_TO_ROW = {phrase: i for i, (phrase, _, _) in enumerate(ICD203_BANDS)}

CONFIDENCE_LEVELS = {"high", "moderate", "low"}


def _normalize_phrase(phrase: str) -> str:
    p = phrase.strip().lower()
    return _ICD203_ALIASES.get(p, p)


def grade_probability(phrase: str) -> dict:
    """
    Map an estimative-probability phrase to its ICD 203 band.

    Raises GradingError if the phrase is not one of the seven bands, and
    lists the valid phrases so the caller can fix it rather than guess.
    """
    normalized = _normalize_phrase(phrase)
    if normalized not in _PHRASE_TO_ROW:
        valid = ", ".join(p for p, _, _ in ICD203_BANDS)
        raise GradingError(
            f"'{phrase}' is not one of the seven ICD 203 estimative-probability "
            f"terms. Valid terms: {valid}. Using a word outside this list "
            "(e.g. 'probable', 'doubtful') as if it were a calibrated ICD 203 "
            "band asserts a precision the term does not carry."
        )
    row = _PHRASE_TO_ROW[normalized]
    label, lo, hi = ICD203_BANDS[row]
    return {
        "phrase": label,
        "row": row,
        "percent_low": lo,
        "percent_high": hi,
    }


def check_estimative_language(phrases: list[str], confidence: Optional[str] = None) -> dict:
    """
    Check a set of estimative-probability phrases used in one product.

    Flags:
    - a confidence word (high/moderate/low) fused into the same string as a
      likelihood word, e.g. "likely with high confidence" passed as a single
      phrase, since likelihood and confidence are separate axes and should be
      reported as separate fields, not one compound phrase. This check runs
      before band lookup, because a fused phrase is exactly the malformed
      input that would otherwise just fail ICD 203 lookup with a confusing
      "not a valid term" error, hiding the real problem.
    - any (remaining) phrase not in the ICD 203 list (via grade_probability)
    - phrases drawn from more than one row (mixing bands in one product)
    """
    if confidence is not None and confidence.strip().lower() not in CONFIDENCE_LEVELS:
        raise GradingError(
            f"'{confidence}' is not a recognized analytic-confidence level. "
            f"Valid levels: {', '.join(sorted(CONFIDENCE_LEVELS))}. Confidence "
            "describes how much the analyst trusts the sourcing and analytic "
            "basis. It is reported alongside a probability term, never fused "
            "into it."
        )

    warnings = []
    mixed_confidence_terms = []
    graded = []
    rows_used = set()

    for phrase in phrases:
        lowered = phrase.strip().lower()
        has_confidence_word = any(c in lowered for c in CONFIDENCE_LEVELS)
        has_probability_word = any(p in lowered for p, _, _ in ICD203_BANDS)
        if has_confidence_word and has_probability_word:
            mixed_confidence_terms.append(phrase)
            # Still try to grade the probability component so callers get a
            # band back, by stripping the phrase down to its ICD 203 term.
            matched_term = next(
                (p for p, _, _ in ICD203_BANDS if p in lowered), None
            )
            g = grade_probability(matched_term)
        else:
            g = grade_probability(phrase)
        graded.append(g)
        rows_used.add(g["row"])

    if len(rows_used) > 1:
        rows_sorted = sorted(rows_used)
        used_labels = [ICD203_BANDS[r][0] for r in rows_sorted]
        warnings.append(
            "Mixed rows: this product uses estimative terms from more than one "
            f"ICD 203 band ({', '.join(used_labels)}). Guidance is to not mix "
            "terms from different rows in a single product without a "
            "disclaimer explaining why."
        )
    if mixed_confidence_terms:
        warnings.append(
            "Confidence fused into probability language: "
            f"{mixed_confidence_terms!r}. Likelihood (e.g. 'likely') and "
            "analytic confidence (High/Moderate/Low) are separate axes. "
            "Report them as two fields, not one compound phrase."
        )

    return {
        "graded_phrases": graded,
        "rows_used": sorted(rows_used),
        "confidence": confidence.strip().lower() if confidence else None,
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# Circular corroboration check
# ---------------------------------------------------------------------------

@dataclass
class Source:
    name: str
    reliability: Optional[str] = None
    cites: list[str] = field(default_factory=list)  # names of other sources in the same list this source cites/derives from


def check_corroboration(sources: list[Source]) -> dict:
    """
    Given multiple sources for one claim, flag when apparent independence may
    be circular: when one source's `cites` field names another source in the
    same list.

    Modeled on the actor-name-crosswalk finding: 87 of 1,403 MISP synonym
    strings are themselves ATT&CK group IDs, meaning MISP is, for those
    entries, citing ATT&CK's catalog rather than reporting independently.
    Two catalogs "agreeing" on a name is not corroboration when one is
    quoting the other.
    """
    names = {s.name for s in sources}
    circular_pairs = []
    for s in sources:
        for cited in s.cites:
            if cited in names:
                circular_pairs.append((s.name, cited))

    independent_count = len(sources) - len({p[0] for p in circular_pairs})

    result = {
        "source_count": len(sources),
        "circular_pairs": circular_pairs,
        "apparently_independent_count": len(sources),
        "effectively_independent_count": independent_count,
        "warnings": [],
    }

    if circular_pairs:
        pairs_str = "; ".join(f"{a} cites {b}" for a, b in circular_pairs)
        result["warnings"].append(
            f"Possible circular corroboration: {pairs_str}. "
            f"{len(sources)} sources were supplied but only "
            f"{independent_count} appear to be independent once shared "
            "upstream citations are accounted for. Do not count a citing "
            "source and its citation as two confirmations of the same claim."
        )

    return result


# ---------------------------------------------------------------------------
# Demo / CLI
# ---------------------------------------------------------------------------

def _demo() -> None:
    print("=== Admiralty grading: valid ===")
    print(grade_admiralty("B", 2))

    print("\n=== Admiralty grading: low-reliability source, high-credibility info ===")
    print(grade_admiralty("E", 1))
    print(
        "(An E-rated source, one with a history of unreliable reporting, "
        "delivering a claim independently confirmed by other sources. The "
        "grading captures this without forcing a single blended number.)"
    )

    print("\n=== Admiralty grading: invalid letter ===")
    try:
        grade_admiralty("Z", 2)
    except GradingError as e:
        print(f"GradingError: {e}")

    print("\n=== Rejecting a blended score ===")
    try:
        reject_blended_score("B2 blended to 'medium-high'")
    except GradingError as e:
        print(f"GradingError: {e}")

    print("\n=== ICD 203 probability lookup ===")
    print(grade_probability("very likely"))

    print("\n=== ICD 203: invalid phrase ===")
    try:
        grade_probability("probably")
    except GradingError as e:
        print(f"GradingError: {e}")

    print("\n=== Mixed-row product (flagged) ===")
    result = check_estimative_language(["likely", "almost no chance"], confidence="high")
    for w in result["warnings"]:
        print(f"WARNING: {w}")
    print(result)

    print("\n=== Confidence fused into probability phrase (flagged) ===")
    result = check_estimative_language(["likely with high confidence"])
    for w in result["warnings"]:
        print(f"WARNING: {w}")

    print("\n=== Circular corroboration (actor-name-crosswalk pattern) ===")
    sources = [
        Source(name="ATT&CK", reliability="B"),
        Source(name="MISP galaxy", reliability="B", cites=["ATT&CK"]),
    ]
    result = check_corroboration(sources)
    for w in result["warnings"]:
        print(f"WARNING: {w}")
    print(result)

    print("\n=== Genuinely independent corroboration (no warning) ===")
    sources = [
        Source(name="VIGINUM technical report"),
        Source(name="Meta threat report"),
    ]
    result = check_corroboration(sources)
    print(f"warnings: {result['warnings']}")
    print(result)


if __name__ == "__main__":
    _demo()
