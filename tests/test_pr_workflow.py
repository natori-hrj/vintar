"""Security contract tests for the initial Vintar PR workflow."""

import re
from pathlib import Path

import yaml

WORKFLOW_PATH = Path(".github/workflows/vintar-pr.yml")


def workflow_text() -> str:
    return WORKFLOW_PATH.read_text(encoding="utf-8")


def test_pr_event_is_the_only_trigger():
    source = workflow_text()

    assert re.search(r"(?m)^on:\s*$", source)
    assert re.search(r"(?m)^  pull_request:\s*$", source)

    for forbidden in (
        "pull_request_target",
        "workflow_dispatch:",
        "workflow_run:",
        "push:",
    ):
        assert forbidden not in source


def test_pr_events_are_explicit():
    source = workflow_text()

    assert "opened" in source
    assert "synchronize" in source
    assert "reopened" in source
    assert "branches:" in source
    assert "- main" in source


def test_untrusted_pr_has_no_privileged_inputs():
    source = workflow_text().lower()

    for forbidden in (
        "secrets.",
        "vars.",
        "environment:",
        "pull_request_target",
        "id-token: write",
        "contents: write",
        "pull-requests: write",
        "continue-on-error",
    ):
        assert forbidden not in source

    assert "permissions:\n  contents: read" in source


def test_all_actions_are_sha_pinned():
    workflows = sorted(
        (*WORKFLOW_PATH.parent.glob("*.yml"), *WORKFLOW_PATH.parent.glob("*.yaml"))
    )
    assert workflows, (
        "No workflow files found. Restore the workflows before checking action pins."
    )
    for path in workflows:
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job in workflow["jobs"].values():
            for entry in (job, *job.get("steps", [])):
                action = entry.get("uses")
                if action is None or action.startswith("./"):
                    continue
                if action.startswith("docker://"):
                    assert re.fullmatch(r"docker://.+@sha256:[0-9a-f]{64}", action), (
                        f"{path}: {action} is mutable. Pin the container to its full SHA-256 digest."
                    )
                else:
                    assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", action), (
                        f"{path}: {action} is mutable. Pin the action or reusable workflow to its full commit SHA."
                    )


def test_checkout_does_not_keep_credentials():
    source = workflow_text()

    assert "persist-credentials: false" in source


def test_pr_uses_existing_loopback_e2e():
    source = workflow_text()

    assert "scripts.run_ci_e2e" in source
    assert "uv sync --locked" in source
    assert "uv run --locked" in source

    assert "ubuntu-24.04" in source
    assert "vintar-e2e-reports" in source
    assert "Vintar PR Loopback E2E" in source
    assert "security checks" not in source.lower()


def test_pr_checks_generated_error_signature_schema():
    source = workflow_text()

    assert (
        "uv run --locked python scripts/update_error_signature_schema.py --check"
        in source
    )


def test_reports_are_revalidated_before_upload():
    source = workflow_text()

    assert '"$report_dir/pass.json" 0' in source
    assert '"$report_dir/fail.json" 1' in source
    assert '"$report_dir/inconclusive.json" 3' in source
    assert source.count("test ! -L") == 3
    assert "error.json" in source


def test_report_upload_requires_success_and_same_repository():
    source = workflow_text()
    upload = source.split("- name: Upload verification reports", 1)[1]

    assert "success() &&" in source
    assert (
        "github.event.pull_request.head.repo.full_name == github.repository" in source
    )
    assert "if-no-files-found: error" in source
    assert "retention-days: 1" in source
    assert "vintar-pr-loopback-e2e-reports" in source
    assert "*.json" not in upload
    assert upload.count("${{ runner.temp }}/vintar-e2e-reports/") == 3


def test_pr_job_is_bounded():
    source = workflow_text()

    assert "timeout-minutes: 10" in source
    assert "cancel-in-progress: true" in source
    assert "github.event.pull_request.number" in source
