"""Tests against the raw scanner evidence files: every number this project
reports must trace back to a raw tool output file kept in evidence/. These
tests check that the evidence exists, is well-formed, and that the specific
tool facts this project relies on (rule names, versions, personas) are
actually present in the raw output, not asserted from memory."""
import json

from conftest import zizmor_findings_flat


def test_zizmor_version_is_1_30_0(root):
    version_text = (root / "evidence" / "zizmor-version.txt").read_text()
    assert "1.30.0" in version_text


def test_scorecard_version_is_v5_5_0(root):
    version_text = (root / "evidence" / "scorecard-version.txt").read_text()
    assert "v5.5.0" in version_text


def test_zizmor_default_run_produced_findings(zizmor_default_json):
    assert len(zizmor_default_json) > 0


def test_zizmor_auditor_run_produced_findings(zizmor_auditor_json):
    assert len(zizmor_auditor_json) > 0


def test_zizmor_default_does_not_include_self_hosted_runner(zizmor_default_json):
    """The headline empirical claim: zizmor's self-hosted-runner rule is
    Auditor persona, so a DEFAULT run must not report it at all."""
    idents = {f["ident"] for f in zizmor_default_json}
    assert "self-hosted-runner" not in idents


def test_zizmor_auditor_does_include_self_hosted_runner(zizmor_auditor_json):
    idents = {f["ident"] for f in zizmor_auditor_json}
    assert "self-hosted-runner" in idents


def test_self_hosted_runner_finding_has_auditor_persona_tag(zizmor_auditor_json):
    finding = next(f for f in zizmor_auditor_json if f["ident"] == "self-hosted-runner")
    assert finding["determinations"]["persona"] == "Auditor"


def test_self_hosted_runner_finding_severity_medium_confidence_high(zizmor_auditor_json):
    """Confirmed against zizmor's own source (self_hosted_runner.rs): a
    literal `runs-on: self-hosted` label is Severity::Medium /
    Confidence::High."""
    finding = next(f for f in zizmor_auditor_json if f["ident"] == "self-hosted-runner")
    assert finding["determinations"]["severity"] == "Medium"
    assert finding["determinations"]["confidence"] == "High"


def test_zizmor_default_includes_dangerous_triggers(zizmor_default_json):
    idents = {f["ident"] for f in zizmor_default_json}
    assert "dangerous-triggers" in idents


def test_zizmor_default_includes_template_injection(zizmor_default_json):
    idents = {f["ident"] for f in zizmor_default_json}
    assert "template-injection" in idents


def test_zizmor_default_includes_cache_poisoning(zizmor_default_json):
    idents = {f["ident"] for f in zizmor_default_json}
    assert "cache-poisoning" in idents


def test_zizmor_no_rule_named_oidc_or_sub_claim(zizmor_default_json, zizmor_auditor_json):
    """Structural blindness claim for class 5: no zizmor rule, in either
    persona, has a name referencing OIDC or the sub claim, because the
    vulnerable artifact (a cloud IAM trust policy) is not a file zizmor
    parses at all."""
    all_idents = {f["ident"] for f in zizmor_default_json} | {f["ident"] for f in zizmor_auditor_json}
    for ident in all_idents:
        assert "oidc" not in ident.lower()
        assert "sub-claim" not in ident.lower()


def test_scorecard_dangerous_workflow_check_present(scorecard_json):
    names = {c["name"] for c in scorecard_json["checks"]}
    assert "Dangerous-Workflow" in names


def test_scorecard_flags_script_injection_by_message_text(scorecard_json):
    check = next(c for c in scorecard_json["checks"] if c["name"] == "Dangerous-Workflow")
    details = " ".join(check["details"])
    assert "script injection" in details.lower()


def test_scorecard_flags_untrusted_checkout_by_message_text(scorecard_json):
    check = next(c for c in scorecard_json["checks"] if c["name"] == "Dangerous-Workflow")
    details = " ".join(check["details"])
    assert "untrusted code checkout" in details.lower()


def test_scorecard_dangerous_workflow_says_nothing_about_cache_or_runner_or_oidc(scorecard_json):
    """Structural blindness claim for classes 3/4/5 in Scorecard: its own
    Dangerous-Workflow output, run against our full corpus including the
    cache-poisoning and self-hosted-runner workflows, mentions none of
    those concepts."""
    check = next(c for c in scorecard_json["checks"] if c["name"] == "Dangerous-Workflow")
    details = " ".join(check["details"]).lower()
    for term in ("cache", "self-hosted", "oidc", "openid"):
        assert term not in details
