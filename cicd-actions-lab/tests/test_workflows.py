"""Workflow YAML corpus tests: every file parses, the corpus contains
exactly the expected workflow files, and each planted pattern actually
appears in the file at the line the ground truth manifest claims."""
import yaml


def _executable_text(path):
    """Strip full-line '#' comments before scanning executable content, so
    prose in header comments explaining an anti-pattern (e.g. this
    project's own "unlike a curl to an external endpoint") doesn't trip a
    check meant for actual run:/uses: content."""
    lines = path.read_text().splitlines()
    return "\n".join(line for line in lines if not line.strip().startswith("#"))


EXPECTED_WORKFLOW_FILES = {
    "pr-target-exfil.yml",
    "script-injection.yml",
    "cache-poison-write.yml",
    "cache-poison-restore.yml",
    "self-hosted-runner-pattern.yml",
    "oidc-debug.yml",
}


def test_all_expected_workflow_files_present(all_workflow_files):
    names = {f.name for f in all_workflow_files}
    assert EXPECTED_WORKFLOW_FILES <= names


def test_no_unexpected_workflow_files(all_workflow_files):
    names = {f.name for f in all_workflow_files}
    assert names == EXPECTED_WORKFLOW_FILES, (
        f"unexpected extra or missing workflow files: {names.symmetric_difference(EXPECTED_WORKFLOW_FILES)}"
    )


def test_every_workflow_is_valid_yaml(all_workflow_files):
    for f in all_workflow_files:
        with open(f) as fh:
            doc = yaml.safe_load(fh)
        assert isinstance(doc, dict), f"{f.name} did not parse to a mapping"
        assert "jobs" in doc, f"{f.name} has no jobs: key"


def test_class_1_uses_pull_request_target(workflows_dir):
    doc = yaml.safe_load((workflows_dir / "pr-target-exfil.yml").read_text())
    # PyYAML parses the bare key `on:` as boolean True in YAML 1.1.
    triggers = doc.get("on") or doc.get(True)
    assert "pull_request_target" in triggers


def test_class_1_checks_out_pr_head_ref(workflows_dir):
    text = (workflows_dir / "pr-target-exfil.yml").read_text()
    assert "github.event.pull_request.head.sha" in text
    assert "actions/checkout" in text


def test_class_1_secret_is_clearly_dummy(workflows_dir):
    text = (workflows_dir / "pr-target-exfil.yml").read_text()
    assert "DUMMY_API_KEY_DO_NOT_USE" in text


def test_class_1_sink_is_github_artifact_not_external(workflows_dir):
    text = (workflows_dir / "pr-target-exfil.yml").read_text()
    executable = _executable_text(workflows_dir / "pr-target-exfil.yml")
    assert "actions/upload-artifact" in text
    # No outbound HTTP call anywhere in this workflow's executable content.
    assert "curl" not in executable
    assert "wget" not in executable
    assert "http://" not in executable
    assert "https://" not in executable


def test_class_2_interpolates_untrusted_event_field(workflows_dir):
    text = (workflows_dir / "script-injection.yml").read_text()
    assert "${{ github.event.issue.title }}" in text


def test_class_2_also_shows_the_safe_pattern_for_contrast(workflows_dir):
    text = (workflows_dir / "script-injection.yml").read_text()
    assert "env:" in text
    assert "ISSUE_TITLE" in text


def test_class_3_writer_and_restorer_share_predictable_key(workflows_dir):
    writer = (workflows_dir / "cache-poison-write.yml").read_text()
    restorer = (workflows_dir / "cache-poison-restore.yml").read_text()
    assert "key: build-cache-v1" in writer
    assert "key: build-cache-v1" in restorer


def test_class_3_restorer_is_release_shaped_for_zizmor(workflows_dir):
    """zizmor's cache-poisoning rule only inspects jobs it recognizes as
    release workflows (tag push, release event, release-named branch, or a
    well-known publisher action). The restorer must use one of those shapes
    or the rule cannot fire at all, confirmed against zizmor's own source."""
    doc = yaml.safe_load((workflows_dir / "cache-poison-restore.yml").read_text())
    triggers = doc.get("on") or doc.get(True)
    assert "push" in triggers
    assert "tags" in triggers["push"]


def test_class_3_restorer_executes_without_integrity_check(workflows_dir):
    text = (workflows_dir / "cache-poison-restore.yml").read_text()
    assert "build-step.sh" in text
    # No hash pin or signature verification step anywhere near the execution.
    assert "sha256sum" not in text
    assert "gpg --verify" not in text


def test_class_4_uses_self_hosted_runner_label(workflows_dir):
    doc = yaml.safe_load((workflows_dir / "self-hosted-runner-pattern.yml").read_text())
    job = doc["jobs"]["build-on-self-hosted"]
    assert job["runs-on"] == "self-hosted"


def test_class_4_has_no_environment_protection_rule(workflows_dir):
    doc = yaml.safe_load((workflows_dir / "self-hosted-runner-pattern.yml").read_text())
    job = doc["jobs"]["build-on-self-hosted"]
    assert "environment" not in job


def test_class_4_dangerous_trigger_is_commented_out_not_live(workflows_dir):
    """The fork/branch-PR-reachable trigger that would make class 4 actually
    dangerous is intentionally commented out; only workflow_dispatch (never
    invoked) is live, so this workflow can never actually run on an
    attacker-influenced event."""
    text = (workflows_dir / "self-hosted-runner-pattern.yml").read_text()
    assert "# pull_request_target:" in text
    doc = yaml.safe_load(text)
    triggers = doc.get("on") or doc.get(True)
    assert "pull_request_target" not in triggers
    assert "workflow_dispatch" in triggers


def test_class_5_workflow_has_no_cloud_credential_action(workflows_dir):
    """No cloud-provider auth action appears anywhere in the corpus. Checked
    across every workflow file, not just oidc-debug.yml, since the whole
    project's safety claim depends on this being true everywhere."""
    cloud_auth_markers = [
        "aws-actions/configure-aws-credentials",
        "azure/login",
        "google-github-actions/auth",
    ]
    for f in workflows_dir.glob("*.yml"):
        text = _executable_text(f)
        for marker in cloud_auth_markers:
            assert marker not in text, f"found cloud credential action {marker!r} in {f.name}"


def test_class_5_workflow_uses_official_oidc_debugger(workflows_dir):
    text = (workflows_dir / "oidc-debug.yml").read_text()
    assert "github/actions-oidc-debugger" in text
    assert "id-token: write" in text
