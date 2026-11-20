"""Offline tests for the release rehearsal checks."""

import importlib
import io
import json
import subprocess
import tarfile
from pathlib import Path
from urllib.error import HTTPError
from zipfile import ZipFile

import pytest
import yaml


@pytest.fixture
def rehearsal(monkeypatch):
    monkeypatch.syspath_prepend(str(Path.cwd()))
    return importlib.import_module("scripts.rehearse_release")


def audit_result(code, *, vulns=(), stderr=""):
    report = {
        "dependencies": [
            {"name": "Example_Package", "version": "1.2", "vulns": list(vulns)}
        ]
    }
    return subprocess.CompletedProcess([], code, json.dumps(report), stderr)


def test_audit_returns_complete_clean_inventory(rehearsal, monkeypatch, tmp_path):
    def run(args, **kwargs):
        assert args[-2:] == ["--requirement", str(tmp_path / "requirements.txt")]
        assert {"--strict", "--no-deps", "--disable-pip"} <= set(args)
        assert kwargs["timeout"] > 0
        return audit_result(0)

    monkeypatch.setattr(subprocess, "run", run)
    assert rehearsal.audit(tmp_path / "requirements.txt", "runtime") == {
        "example-package": "1.2"
    }


def test_audit_reports_findings_with_remediation(rehearsal, monkeypatch, tmp_path):
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: audit_result(1, vulns=[{"id": "TEST-1"}])
    )
    with pytest.raises(
        rehearsal.AuditFindings, match="Update the affected dependencies"
    ):
        rehearsal.audit(tmp_path / "requirements.txt", "runtime")


@pytest.mark.parametrize(
    "result",
    [
        audit_result(1, stderr="Service unavailable"),
        audit_result(2, vulns=[{"id": "TEST-1"}]),
        audit_result(0, vulns=[{"id": "TEST-1"}]),
        subprocess.CompletedProcess([], 0, "{", ""),
        subprocess.CompletedProcess([], 0, '{"dependencies": []}', ""),
        subprocess.CompletedProcess(
            [],
            0,
            '{"dependencies": [{"name": "example", "skip_reason": "unsupported"}]}',
            "",
        ),
    ],
)
def test_audit_rejects_failed_or_incomplete_execution(
    rehearsal, monkeypatch, tmp_path, result
):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: result)
    with pytest.raises(
        rehearsal.AuditExecutionError, match="Check the dependency input"
    ):
        rehearsal.audit(tmp_path / "requirements.txt", "runtime")


@pytest.mark.parametrize(
    "exit_code, exception", [(1, "AuditFindings"), (2, "AuditExecutionError")]
)
def test_rehearsal_exit_codes_distinguish_audit_failures(
    rehearsal, monkeypatch, tmp_path, capsys, exit_code, exception
):
    def fail(*args):
        raise getattr(rehearsal, exception)("example audit diagnostic")

    monkeypatch.setattr(rehearsal, "rehearse", fail)
    monkeypatch.setattr(rehearsal, "supported_interpreters", lambda: ["3.13"])
    monkeypatch.setattr("sys.argv", ["rehearse_release", "--output", str(tmp_path)])
    assert rehearsal.main() == exit_code
    assert "example audit diagnostic" in capsys.readouterr().err


@pytest.mark.parametrize(
    "changelog, valid",
    [
        ("## Unreleased\n\n### 0.1.0\n\n- Initial release.\n", True),
        ("## [Unreleased]\n\n## [0.1.0] - 2026-11-20\n\n- Initial release.\n", True),
        ("## [0.1.0] - 2026-11-20\n\n## [0.2.0] - 2026-11-21\n\n- Other.\n", False),
        ("## 0.2.0\n\n- Different release.\n", False),
        ("## 0.1.0\n\n## 0.2.0\n\n- Different release.\n", False),
        ("## 0.1.0\n\n- First.\n\n## 0.1.0\n\n- Second.\n", False),
    ],
)
def test_release_version_requires_populated_changelog_section(
    rehearsal, tmp_path, changelog, valid
):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nversion = "0.1.0"\n', encoding="utf-8"
    )
    (tmp_path / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
    if valid:
        assert rehearsal.release_version(tmp_path) == "0.1.0"
    else:
        with pytest.raises(
            ValueError, match="Add or update the matching version heading"
        ):
            rehearsal.release_version(tmp_path)


def test_installed_inventory_uses_isolated_metadata(rehearsal, monkeypatch, tmp_path):
    def command(args, guidance):
        assert args[:2] == [str(tmp_path / "python"), "-I"]
        return '["3.13.1", [["Vintar", "0.1.0"], ["Example_Package", "1.2"]]]'

    monkeypatch.setattr(rehearsal, "command", command)
    assert rehearsal.installed_packages(tmp_path / "python", "0.1.0") == (
        "3.13.1",
        {"example-package": "1.2"},
    )
    with pytest.raises(ValueError, match="Fix the wheel metadata"):
        rehearsal.installed_packages(tmp_path / "python", "0.2.0")


def test_sbom_includes_the_application_and_installed_packages(rehearsal, tmp_path):
    path = tmp_path / "sbom.json"
    rehearsal.write_sbom(path, "0.1.0", {"z": "1", "a": "2"})
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["bomFormat"] == "CycloneDX"
    assert payload["specVersion"] == "1.6"
    assert payload["metadata"]["component"] == {
        "name": "vintar",
        "type": "application",
        "version": "0.1.0",
    }
    assert [
        (component["name"], component["version"]) for component in payload["components"]
    ] == [
        ("a", "2"),
        ("z", "1"),
    ]


def test_release_scan_reads_members_of_both_archives(rehearsal, monkeypatch, tmp_path):
    wheel, sdist = tmp_path / "example.whl", tmp_path / "example.tar.gz"
    with ZipFile(wheel, "w") as archive:
        archive.writestr("example/module.py", "wheel member")
    with tarfile.open(sdist, "w:gz") as archive:
        content = b"source member"
        member = tarfile.TarInfo("example/module.py")
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))

    def scan(*, release_contents):
        assert (
            release_contents / "wheel/example/module.py"
        ).read_text() == "wheel member"
        assert (
            release_contents / "sdist/example/module.py"
        ).read_text() == "source member"
        return 1

    monkeypatch.setattr(rehearsal, "scan_secrets", scan)
    assert rehearsal.verify_contents(wheel, sdist, tmp_path / "contents") == 1


def test_rehearsal_builds_once_and_reuses_artifacts(rehearsal, monkeypatch, tmp_path):
    events = []

    def build(output):
        events.append("build")
        wheel, sdist = output / "example.whl", output / "example.tar.gz"
        for path in wheel, sdist:
            path.write_bytes(b"abc")
        return wheel, sdist

    def scan(wheel, sdist, destination):
        events.append("scan")
        return 0

    def install(wheel, workspace, version, python_version, locked):
        assert wheel == tmp_path / "output/example.whl"
        assert workspace.is_dir()
        assert version == "0.1.0"
        assert locked.name == "runtime-locked.txt"
        events.append(python_version)

    monkeypatch.setattr(rehearsal, "release_version", lambda root: "0.1.0")
    monkeypatch.setattr(rehearsal, "build_distributions", build)
    monkeypatch.setattr(rehearsal, "verify_contents", scan)
    monkeypatch.setattr(rehearsal, "command", lambda *args: events.append("export"))
    monkeypatch.setattr(rehearsal, "verify_install", install)
    output = tmp_path / "output"
    assert rehearsal.rehearse(output, ["3.13", "3.14", "3.15"]) == 0
    assert events == ["build", "scan", "export", "3.13", "3.14", "3.15"]
    digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert (
        output / "SHA256SUMS"
    ).read_text() == f"{digest}  example.tar.gz\n{digest}  example.whl\n"


def release_workflow():
    path = Path(".github/workflows/vintar-release.yml")
    return yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def test_manual_rehearsal_remains_read_only_and_artifact_only():
    workflow = release_workflow()
    assert workflow["on"] == {
        "workflow_dispatch": "",
        "push": {"tags": ["v[0-9]+.[0-9]+.[0-9]+"]},
    }
    assert workflow["permissions"] == {"contents": "read"}
    jobs = workflow["jobs"]
    assert set(jobs) == {"quality", "rehearse", "publish-pypi", "github-release"}
    assert jobs["rehearse"]["needs"] == "quality"
    assert all("continue-on-error" not in job for job in jobs.values())
    assert all(
        "continue-on-error" not in step
        for job in jobs.values()
        for step in job["steps"]
    )
    for name in ("quality", "rehearse"):
        job = jobs[name]
        assert "if" not in job and "permissions" not in job
        assert all(
            step["uses"].split("@")[0]
            in {"actions/checkout", "astral-sh/setup-uv", "actions/upload-artifact"}
            for step in job["steps"]
            if "uses" in step
        )
    verification, upload = jobs["rehearse"]["steps"][-2:]
    assert 'if [[ "$GITHUB_EVENT_NAME" == push ]]; then' in verification["run"]
    assert 'args+=(--tag "$GITHUB_REF_NAME")' in verification["run"]
    assert "uv run --locked python -m scripts.rehearse_release" in verification["run"]
    assert upload["uses"].startswith("actions/upload-artifact@")
    assert upload["with"]["name"] == "vintar-verified-release"
    assert (
        jobs["rehearse"]["outputs"]["artifact-id"]
        == "${{ steps.verified.outputs.artifact-id }}"
    )
    assert upload["id"] == "verified" and "if" not in upload


def test_publishing_jobs_are_tag_only_and_use_the_verified_artifact():
    jobs = release_workflow()["jobs"]
    pypi = jobs["publish-pypi"]
    release = jobs["github-release"]
    assert pypi["needs"] == "rehearse"
    assert release["needs"] == ["rehearse", "publish-pypi"]
    assert pypi["environment"] == "pypi"
    assert pypi["permissions"] == {"contents": "read", "id-token": "write"}
    assert release["permissions"] == {"contents": "write"}
    for job in (pypi, release):
        assert (
            job["if"]
            == "github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')"
        )
        checkout, download, *remaining = job["steps"]
        assert checkout["uses"].startswith("actions/checkout@")
        assert checkout["with"] == {
            "ref": "${{ github.sha }}",
            "persist-credentials": "false",
        }
        assert download["uses"].startswith("actions/download-artifact@")
        assert download["with"] == {
            "artifact-ids": "${{ needs.rehearse.outputs.artifact-id }}",
            "path": "${{ runner.temp }}/vintar-release",
        }
        assert all(" build " not in step.get("run", "") for step in remaining)
        assert "sha256sum --check --strict SHA256SUMS" in remaining[0]["run"]
    stage, tag_check, publish = pypi["steps"][2:]
    assert stage["id"] == "pypi-files"
    assert stage["run"].index("sha256sum") < stage["run"].index("stage-pypi")
    assert '>> "$GITHUB_OUTPUT"' in stage["run"]
    assert tag_check["run"] == "python3 scripts/prepare_release_publish.py check-tag"
    assert tag_check["env"]["GH_TOKEN"] == "${{ github.token }}"
    assert (
        tag_check["if"] == publish["if"] == "steps.pypi-files.outputs.upload == 'true'"
    )
    assert publish["uses"].startswith("pypa/gh-action-pypi-publish@")
    assert publish["with"] == {"packages-dir": "dist/"}
    create = release["steps"][-1]
    assert create["env"]["GH_TOKEN"] == "${{ github.token }}"
    assert (
        'check-tag\ngh release create --verify-tag --target "$GITHUB_SHA"'
        in create["run"]
    )
    assert all(
        pattern in create["run"]
        for pattern in (
            "*.whl",
            "*.tar.gz",
            "/SHA256SUMS",
            "/sbom-cpython-*.cdx.json",
        )
    )


@pytest.mark.parametrize("tag", ["v0.1.1", "0.1.0", "v0.1.0rc1", "v00.1.0"])
def test_mismatched_release_tag_never_builds(rehearsal, monkeypatch, tmp_path, tag):
    monkeypatch.setattr(rehearsal, "release_version", lambda root: "0.1.0")
    output = tmp_path / "dist"
    with pytest.raises(ValueError, match=r"matching pyproject\.toml \(v0\.1\.0\)"):
        rehearsal.rehearse(output, ["3.13"], tag)
    assert not output.exists()


def test_matching_stable_release_tag_is_accepted(rehearsal):
    rehearsal.validate_release_tag("v0.1.0", "0.1.0")


def test_locked_audit_resolves_markers_for_each_interpreter(rehearsal, tmp_path):
    requirements = tmp_path / "locked.txt"
    requirements.write_text(
        "# export\nExample_Name==1 ; python_full_version < '3.15'\n"
        "Example_Name==2 ; python_full_version >= '3.15'\n",
        encoding="utf-8",
    )
    assert rehearsal.locked_packages(requirements, "3.13.15") == {"example-name": "1"}
    assert rehearsal.locked_packages(requirements, "3.15.0") == {"example-name": "2"}

    requirements.write_text("example>=1\n", encoding="utf-8")
    with pytest.raises(rehearsal.AuditExecutionError, match=r"Regenerate uv.lock"):
        rehearsal.locked_packages(requirements, "3.15.0")


def test_clean_audit_must_account_for_every_input(rehearsal, monkeypatch, tmp_path):
    def audit(path, label):
        assert path.read_text(encoding="utf-8") == "example==1\nmissing==2\n"
        return {"example": "1"}

    monkeypatch.setattr(rehearsal, "audit", audit)
    with pytest.raises(
        rehearsal.AuditExecutionError, match="Fix the audit dependency input"
    ):
        rehearsal.audit_inventory(
            tmp_path / "input.txt", "runtime", {"example": "1", "missing": "2"}
        )


def test_release_gitleaks_uses_redacted_directory_scan(
    rehearsal, monkeypatch, tmp_path, capsys
):
    scanner = importlib.import_module("scripts.scan_git_history")
    binary_archive = tmp_path / "binary.tar.gz"
    with tarfile.open(binary_archive, "w:gz") as archive:
        member = tarfile.TarInfo("gitleaks")
        archive.addfile(member)
    contents = tmp_path / "contents"
    contents.mkdir()

    def run(args, **kwargs):
        assert args[1] == "dir"
        assert args[-1] == str(contents)
        assert "--redact=100" in args
        assert "--ignore-gitleaks-allow" in args
        assert (
            Path(args[args.index("--config") + 1]).read_text()
            == "[extend]\nuseDefault = true\n"
        )
        report = Path(args[args.index("--report-path") + 1])
        report.write_text(
            json.dumps(
                [
                    {
                        "File": "dist/example.py",
                        "Commit": "",
                        "StartLine": 1,
                        "RuleID": "example",
                        "Secret": "must-not-be-printed",
                    }
                ]
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(args, scanner.FINDINGS)

    monkeypatch.setattr(scanner, "verified_archive", lambda: binary_archive)
    monkeypatch.setattr(subprocess, "run", run)
    assert scanner.main(release_contents=contents) == scanner.FINDINGS
    diagnostics = capsys.readouterr().err
    assert "Release contents rejected" in diagnostics
    assert "Revoke or rotate" in diagnostics
    assert "dist/example.py" in diagnostics
    assert "must-not-be-printed" not in diagnostics


def test_interpreter_matrix_uses_released_cpython_from_uv(rehearsal, monkeypatch):
    def record(version, implementation="cpython", variant="default"):
        return {
            "version": version,
            "implementation": implementation,
            "variant": variant,
        }

    catalog = [
        record("3.16.0a1"),
        record("3.16.0", "graalpy"),
        record("3.14.8"),
        record("3.13.16"),
        record("3.15.0"),
        record("3.16.0", variant="freethreaded"),
        record("3.13.16"),
        record("3.12.9"),
    ]

    def command(args, guidance):
        assert args == [
            "uv",
            "python",
            "list",
            ">=3.13",
            "--all-versions",
            "--output-format",
            "json",
        ]
        return json.dumps(catalog)

    monkeypatch.setattr(rehearsal, "command", command)
    assert rehearsal.supported_interpreters() == ["3.13", "3.14", "3.15"]
    catalog[:] = [record("3.14.0")]
    with pytest.raises(RuntimeError, match=r"make CPython 3\.13 available"):
        rehearsal.supported_interpreters()


def test_invalid_sbom_is_not_written(rehearsal, monkeypatch, tmp_path):
    monkeypatch.setattr(
        rehearsal.JsonStrictValidator, "validate_str", lambda *args: "schema error"
    )
    path = tmp_path / "invalid.cdx.json"
    with pytest.raises(ValueError, match="Fix the SBOM generator"):
        rehearsal.write_sbom(path, "0.1.0", {"example": "1"})
    assert not path.exists()


@pytest.fixture
def publish_preflight(monkeypatch):
    monkeypatch.syspath_prepend(str(Path.cwd()))
    return importlib.import_module("scripts.prepare_release_publish")


@pytest.mark.parametrize(
    "state", ["lightweight-match", "annotated-match", "moved", "missing"]
)
def test_remote_tag_must_still_target_built_commit(
    publish_preflight, monkeypatch, state
):
    built = "a" * 40
    annotation = "b" * 40
    base = "https://api.github.com/repos/example/vintar/git"
    ref = f"{base}/ref/tags/v0.1.0"
    calls = []

    def fetch(url, *, token):
        assert token == "fixture-auth"
        calls.append(url)
        if state == "missing":
            raise HTTPError(url, 404, "fixture missing", {}, None)
        if state == "annotated-match" and url == ref:
            return {"object": {"type": "tag", "sha": annotation}}
        return {
            "object": {"type": "commit", "sha": "c" * 40 if state == "moved" else built}
        }

    monkeypatch.setattr(publish_preflight, "read_json", fetch)
    inputs = (
        "https://api.github.com",
        "example/vintar",
        "v0.1.0",
        built,
        "fixture-auth",
    )
    if state in {"moved", "missing"}:
        with pytest.raises(
            publish_preflight.PublishPreflightError,
            match="moved or was deleted after verification",
        ) as caught:
            publish_preflight.verify_remote_tag(*inputs)
        assert "Do not move the tag back" in str(caught.value)
        assert "Cut a new patch version tag from the intended commit" in str(
            caught.value
        )
    else:
        publish_preflight.verify_remote_tag(*inputs)
    expected = (
        [ref, f"{base}/tags/{annotation}"] if state == "annotated-match" else [ref]
    )
    assert calls == expected


@pytest.mark.parametrize(
    "state", ["missing", "all", "partial", "mismatch", "http-error"]
)
def test_pypi_stages_only_missing_verified_files(
    publish_preflight, monkeypatch, tmp_path, state
):
    wheel = "vintar-0.1.0-py3-none-any.whl"
    sdist = "vintar-0.1.0.tar.gz"
    artifact = tmp_path / "artifacts"
    artifact.mkdir()
    for name in (wheel, sdist):
        (artifact / name).write_bytes(name.encode())
    (artifact / "SHA256SUMS").write_text(
        f"{'a' * 64}  {wheel}\n{'b' * 64}  {sdist}\n", encoding="utf-8"
    )
    (artifact / "sbom-cpython-3.13.cdx.json").write_text("{}", encoding="utf-8")

    def fetch(url):
        assert url == "https://pypi.org/pypi/vintar/0.1.0/json"
        if state in {"missing", "http-error"}:
            raise HTTPError(
                url, 404 if state == "missing" else 503, "fixture", {}, None
            )
        files = [
            {
                "filename": wheel,
                "digests": {"sha256": ("0" if state == "mismatch" else "a") * 64},
            }
        ]
        if state == "all":
            files.append({"filename": sdist, "digests": {"sha256": "b" * 64}})
        return {"urls": files}

    monkeypatch.setattr(publish_preflight, "read_json", fetch)
    destination = tmp_path / "dist"
    if state in {"mismatch", "http-error"}:
        message = (
            "A new version is required"
            if state == "mismatch"
            else "Check PyPI availability"
        )
        with pytest.raises(publish_preflight.PublishPreflightError, match=message):
            publish_preflight.stage_pypi(artifact, destination, "0.1.0")
        assert not destination.exists()
    elif state == "all":
        assert not publish_preflight.stage_pypi(artifact, destination, "0.1.0")
        assert not destination.exists()
    else:
        assert publish_preflight.stage_pypi(artifact, destination, "0.1.0")
        expected = {wheel, sdist} if state == "missing" else {sdist}
        assert {file.name for file in destination.iterdir()} == expected
        for name in expected:
            assert (destination / name).read_bytes() == (artifact / name).read_bytes()
