"""Hard-constraint tests. These encode the project's non-negotiable safety
rules directly, so a future edit that violates one fails CI/pytest rather
than being caught only by manual review.

All checks below strip full-line '#' comments before scanning, because this
corpus's own header comments explain, in prose, exactly the anti-patterns
these tests exist to rule out (e.g. "unlike a curl to an external endpoint",
"no aws-actions/configure-aws-credentials"). Checking comment text would
produce false failures on the documentation itself, not on executable YAML.
"""
import subprocess


def _executable_text(path):
    """Return the file's content with full-line comments removed. This is a
    line-oriented strip (not a YAML parse), sufficient because every
    intentional anti-pattern reference in this corpus's comments is written
    on its own '#'-prefixed line."""
    lines = path.read_text().splitlines()
    return "\n".join(line for line in lines if not line.strip().startswith("#"))


def test_no_third_party_exfil_destination_anywhere_in_workflows(all_workflow_files):
    """No workflow may curl/wget/post to any external endpoint. The only
    sinks allowed for the 'exfil' demonstration are GitHub-native (artifact
    upload, step summary)."""
    banned_calls = ["curl ", "wget ", "requests.post", "requests.get", "nc ", "netcat"]
    for f in all_workflow_files:
        text = _executable_text(f)
        for call in banned_calls:
            assert call not in text, f"found potential external network call {call!r} in {f.name}"


def test_no_webhook_or_paste_service_domains(all_workflow_files):
    suspicious_domains = [
        "webhook.site", "requestbin", "pipedream.net", "ngrok.io",
        "pastebin.com", "hastebin", "transfer.sh",
    ]
    for f in all_workflow_files:
        text = _executable_text(f).lower()
        for domain in suspicious_domains:
            assert domain not in text, f"found suspicious external domain {domain!r} in {f.name}"


def test_no_cloud_provider_credential_action_anywhere(all_workflow_files):
    cloud_auth_markers = [
        "aws-actions/configure-aws-credentials",
        "azure/login",
        "google-github-actions/auth",
        "aws_access_key_id",
        "aws_secret_access_key",
    ]
    for f in all_workflow_files:
        text = _executable_text(f)
        for marker in cloud_auth_markers:
            assert marker not in text, f"found cloud credential marker {marker!r} in {f.name}"


def test_self_hosted_runner_is_not_registered_on_this_machine():
    """This is the hardest safety constraint in the project: no self-hosted
    runner may ever be registered. We check the two places evidence of a
    registered runner would exist: no `./config.sh` runner directory and no
    running/enabled actions-runner systemd service."""
    result = subprocess.run(
        ["systemctl", "list-units", "--type=service", "--all"],
        capture_output=True, text=True, timeout=10,
    )
    combined = (result.stdout + result.stderr).lower()
    assert "actions.runner" not in combined
    assert "github-actions-runner" not in combined


def test_no_actions_runner_directory_exists_in_home():
    """A registered self-hosted runner creates a directory containing
    `.runner`, `.credentials`, and `run.sh`/`config.sh`. None should exist
    anywhere this project could plausibly have created one."""
    from pathlib import Path
    home = Path.home()
    for candidate in home.glob("**/.runner"):
        # Any hit here is a hard failure: it means a runner was registered.
        assert False, f"found a registered self-hosted runner marker file: {candidate}"


def test_dummy_secret_name_is_unambiguous(all_workflow_files):
    """Per the project's own risk mitigation: dummy secrets must be named
    so an automated secret scanner or a human reviewer cannot mistake them
    for real credentials."""
    for f in all_workflow_files:
        text = f.read_text()
        if "secrets." in text and "DUMMY" not in text.upper() and "secrets.GITHUB_TOKEN" not in text:
            # secrets.GITHUB_TOKEN is the built-in token, not a planted
            # secret, so it's excluded from this check.
            assert False, f"{f.name} references a secret without an unambiguous DUMMY name"


def test_class_5_workflow_never_assumes_a_cloud_role(root):
    """The OIDC debugger workflow and its accompanying analysis doc must
    state plainly that no cloud role is ever assumed, matching the
    project's hardest class-5 constraint."""
    workflow_text = (root / ".github" / "workflows" / "oidc-debug.yml").read_text()
    doc_text = (root / "docs" / "oidc-trust-policy-analysis.md").read_text()
    assert "no cloud" in workflow_text.lower() or "no cloud provider" in workflow_text.lower()
    assert "never assumed" in doc_text.lower() or "never assumes" in doc_text.lower()
