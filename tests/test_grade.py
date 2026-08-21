import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest

from grade_source import (
    GradingError,
    Source,
    check_corroboration,
    check_estimative_language,
    grade_admiralty,
    grade_probability,
    reject_blended_score,
)


# ---------------------------------------------------------------------------
# Admiralty grading
# ---------------------------------------------------------------------------

def test_grade_admiralty_valid():
    result = grade_admiralty("B", 2)
    assert result["reliability_grade"] == "B"
    assert result["reliability_label"] == "Usually reliable"
    assert result["credibility_grade"] == 2
    assert result["credibility_label"] == "Probably true"
    assert result["combined_code"] == "B2"


def test_grade_admiralty_lowercase_and_whitespace_normalized():
    result = grade_admiralty(" a ", 1)
    assert result["reliability_grade"] == "A"


def test_grade_admiralty_low_reliability_high_credibility_worked_example():
    """
    The scheme's core design point: an unreliable source (E) can still
    deliver information confirmed by other sources (1). This must be a
    legal, non-contradictory grading, not rejected as inconsistent.
    """
    result = grade_admiralty("E", 1)
    assert result["reliability_grade"] == "E"
    assert result["reliability_label"] == "Unreliable"
    assert result["credibility_grade"] == 1
    assert result["credibility_label"] == "Confirmed by other sources"
    assert "independent" in result["note"].lower()


def test_grade_admiralty_invalid_reliability_letter():
    with pytest.raises(GradingError) as exc:
        grade_admiralty("Z", 2)
    assert "not a valid Admiralty reliability grade" in str(exc.value)
    assert "A, B, C, D, E, F" in str(exc.value)


def test_grade_admiralty_invalid_credibility_number():
    with pytest.raises(GradingError) as exc:
        grade_admiralty("B", 9)
    assert "not a valid Admiralty credibility grade" in str(exc.value)


def test_reject_blended_score_explains_why():
    with pytest.raises(GradingError) as exc:
        reject_blended_score("medium-high")
    msg = str(exc.value)
    assert "two separate values" in msg
    assert "reliability" in msg.lower()
    assert "credibility" in msg.lower()


# ---------------------------------------------------------------------------
# ICD 203 probability bands
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "phrase,expected_low,expected_high",
    [
        ("almost no chance", 1, 5),
        ("very unlikely", 5, 20),
        ("unlikely", 20, 45),
        ("roughly even chance", 45, 55),
        ("likely", 55, 80),
        ("very likely", 80, 95),
        ("almost certain", 95, 99),
    ],
)
def test_grade_probability_all_seven_bands(phrase, expected_low, expected_high):
    result = grade_probability(phrase)
    assert result["percent_low"] == expected_low
    assert result["percent_high"] == expected_high


def test_grade_probability_accepts_almost_certainly_alias():
    result = grade_probability("almost certainly")
    assert result["phrase"] == "almost certain"


def test_grade_probability_case_insensitive():
    result = grade_probability("LIKELY")
    assert result["phrase"] == "likely"


def test_grade_probability_rejects_invalid_phrase_and_lists_valid_ones():
    with pytest.raises(GradingError) as exc:
        grade_probability("probably")
    msg = str(exc.value)
    assert "not one of the seven ICD 203" in msg
    for band in [
        "almost no chance",
        "very unlikely",
        "unlikely",
        "roughly even chance",
        "likely",
        "very likely",
        "almost certain",
    ]:
        assert band in msg


# ---------------------------------------------------------------------------
# Mixed-row / mixed-axis detection
# ---------------------------------------------------------------------------

def test_check_estimative_language_flags_mixed_rows():
    result = check_estimative_language(["likely", "almost no chance"])
    assert len(result["warnings"]) == 1
    assert "Mixed rows" in result["warnings"][0]
    assert result["rows_used"] == [0, 4]


def test_check_estimative_language_no_warning_when_single_row_used_repeatedly():
    result = check_estimative_language(["likely", "likely"])
    assert result["warnings"] == []
    assert result["rows_used"] == [4]


def test_check_estimative_language_flags_confidence_fused_into_phrase():
    """
    ICD 203's central rule: likelihood and analytic confidence are separate
    axes and must not be combined into one phrase.
    """
    result = check_estimative_language(["likely with high confidence"])
    assert any("Confidence fused into probability language" in w for w in result["warnings"])


def test_check_estimative_language_confidence_as_separate_field_is_fine():
    result = check_estimative_language(["likely"], confidence="high")
    assert result["confidence"] == "high"
    assert result["warnings"] == []


def test_check_estimative_language_rejects_invalid_confidence_level():
    with pytest.raises(GradingError) as exc:
        check_estimative_language(["likely"], confidence="extremely")
    assert "not a recognized analytic-confidence level" in str(exc.value)


def test_check_estimative_language_rejects_invalid_phrase_in_list():
    with pytest.raises(GradingError):
        check_estimative_language(["likely", "probably"])


# ---------------------------------------------------------------------------
# Circular corroboration
# ---------------------------------------------------------------------------

def test_check_corroboration_flags_circular_citation():
    """
    Modeled on the actor-name-crosswalk finding: MISP synonym strings that
    are themselves ATT&CK group IDs mean MISP is, for those entries, citing
    ATT&CK rather than reporting independently.
    """
    sources = [
        Source(name="ATT&CK"),
        Source(name="MISP galaxy", cites=["ATT&CK"]),
    ]
    result = check_corroboration(sources)
    assert result["circular_pairs"] == [("MISP galaxy", "ATT&CK")]
    assert result["effectively_independent_count"] == 1
    assert len(result["warnings"]) == 1
    assert "circular corroboration" in result["warnings"][0].lower()


def test_check_corroboration_no_warning_for_genuinely_independent_sources():
    sources = [
        Source(name="VIGINUM technical report"),
        Source(name="Meta threat report"),
    ]
    result = check_corroboration(sources)
    assert result["circular_pairs"] == []
    assert result["effectively_independent_count"] == 2
    assert result["warnings"] == []


def test_check_corroboration_ignores_cites_to_sources_outside_the_list():
    """
    Citing something not in the current source list (e.g. a source that is
    not being claimed as independent corroboration here) should not be
    flagged as circular within this check.
    """
    sources = [
        Source(name="Vendor blog", cites=["Some report not in this list"]),
        Source(name="Second vendor blog"),
    ]
    result = check_corroboration(sources)
    assert result["circular_pairs"] == []


def test_check_corroboration_handles_three_sources_one_circular_pair():
    sources = [
        Source(name="ATT&CK"),
        Source(name="MISP galaxy", cites=["ATT&CK"]),
        Source(name="VIGINUM technical report"),
    ]
    result = check_corroboration(sources)
    assert result["source_count"] == 3
    assert result["circular_pairs"] == [("MISP galaxy", "ATT&CK")]
    assert result["effectively_independent_count"] == 2
