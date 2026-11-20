"""Keep the offline third-party declaration and reviewed summary deterministic."""

import importlib.util
import json
import re
import tarfile
import tomllib
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
from test_sqli_candidate_reliability import classify as reliability_classify

from vintar.checks.sqli.models import Verdict

ROOT = Path(__file__).resolve().parents[1]
THIRD_PARTY = ROOT / "third_party" / "sqli"
TARGETS = THIRD_PARTY / "targets.toml"
RUNNER = ROOT / "scripts" / "run_third_party_sqli_measurement.py"
PREPARER = ROOT / "scripts" / "prepare_third_party_sqli.py"


def load_script(path: Path, name: str) -> ModuleType:
    """Load a standalone script without executing its command-line entry point."""
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def load_runner() -> ModuleType:
    return load_script(RUNNER, "third_party_sqli_measurement")


def load_preparer() -> ModuleType:
    return load_script(PREPARER, "third_party_sqli_preparation")


def declarations() -> dict[str, object]:
    with TARGETS.open("rb") as stream:
        return tomllib.load(stream)


def expected_report() -> dict[str, object]:
    records = [
        {
            "actual_verdict": "inconclusive",
            "classification": "tp",
            "confirmation": {
                "configured": True,
                "reason_code": "confirmation_pattern_matched",
                "request_count": 12,
                "status": "matched",
            },
            "endpoint_id": "dsvw-blind-boolean-id",
            "expected_label": "positive",
            "expected_verdict": "inconclusive",
            "mode": "confirmation",
            "reason_code": "boolean_candidate",
            "request_count": 18,
        },
        {
            "actual_verdict": "inconclusive",
            "classification": "tp",
            "confirmation": {
                "configured": False,
                "reason_code": None,
                "request_count": 0,
                "status": "not_configured",
            },
            "endpoint_id": "dsvw-blind-boolean-id",
            "expected_label": "positive",
            "expected_verdict": "inconclusive",
            "mode": "six_probe",
            "reason_code": "boolean_candidate",
            "request_count": 6,
        },
        {
            "actual_verdict": "inconclusive",
            "classification": "non_decision",
            "confirmation": {
                "configured": True,
                "reason_code": "initial_not_eligible",
                "request_count": 0,
                "status": "not_eligible",
            },
            "endpoint_id": "dsvw-version-query",
            "expected_label": "negative",
            "expected_verdict": "not_detected",
            "mode": "confirmation",
            "reason_code": "unexpected_difference",
            "request_count": 6,
        },
        {
            "actual_verdict": "inconclusive",
            "classification": "non_decision",
            "confirmation": {
                "configured": False,
                "reason_code": None,
                "request_count": 0,
                "status": "not_configured",
            },
            "endpoint_id": "dsvw-version-query",
            "expected_label": "negative",
            "expected_verdict": "not_detected",
            "mode": "six_probe",
            "reason_code": "unexpected_difference",
            "request_count": 6,
        },
    ]
    return {
        "counts": {
            "confirmation": {
                "fn": 0,
                "fp": 0,
                "non_decision": 1,
                "tn": 0,
                "tp": 1,
            },
            "six_probe": {
                "fn": 0,
                "fp": 0,
                "non_decision": 1,
                "tn": 0,
                "tp": 1,
            },
        },
        "records": records,
    }


def test_reviewed_declarations_are_exact_and_digest_bound():
    document = declarations()
    assert document["version"] == 1
    target = document["target"]
    assert target == {
        "archive_sha256": "96690f62ac0fba8a4f0aeac22f2370853bc02b96fb3efd1b8fc3a39398bf302b",
        "archive_url": "https://github.com/stamparm/DSVW/archive/9ca3c9acf3defa0a6148d40e5f5cebeb5dcbb908.tar.gz",
        "commit": "9ca3c9acf3defa0a6148d40e5f5cebeb5dcbb908",
        "license": "Unlicense",
        "name": "DSVW",
        "repository": "https://github.com/stamparm/DSVW",
    }
    records = document["records"]
    assert [record["id"] for record in records] == [
        "dsvw-blind-boolean-id",
        "dsvw-version-query",
    ]
    assert [record["label"] for record in records] == ["positive", "negative"]
    assert [record["evidence_type"] for record in records] == [
        "non_parameterized_sql_sink",
        "parameter_does_not_reach_sql_sink",
    ]
    assert all(record["source_path"] == "dsvw.py" for record in records)
    assert all(
        re.fullmatch(r"[0-9a-f]{64}", record["source_fragment_sha256"])
        for record in records
    )
    assert all(record["reviewer_note"] for record in records)


def test_openapi_and_configs_bind_only_the_two_reviewed_inputs():
    spec = json.loads((THIRD_PARTY / "dsvw" / "openapi.json").read_text())
    parameters = spec["paths"]["/"]["get"]["parameters"]
    assert [(item["name"], item["in"]) for item in parameters] == [
        ("id", "query"),
        ("v", "query"),
    ]
    configs = sorted((THIRD_PARTY / "dsvw" / "configs").glob("*.toml"))
    assert [path.name for path in configs] == [
        "dsvw-blind-boolean-id-confirmation.toml",
        "dsvw-blind-boolean-id-six.toml",
        "dsvw-version-query-confirmation.toml",
        "dsvw-version-query-six.toml",
    ]
    parsed = []
    for path in configs:
        with path.open("rb") as stream:
            config = tomllib.load(stream)
        assert config["target"] == {
            "allowed_origin": "__ORIGIN__",
            "url": "__ORIGIN__/",
        }
        assert config["injection"]["location"] == "query"
        parsed.append(config)
    assert sum(config["limits"]["max_requests"] == 6 for config in parsed) == 2
    assert sum(config["limits"]["max_requests"] == 18 for config in parsed) == 2
    assert sum(config["probes"]["selection"] == "explicit" for config in parsed) == 2
    assert sum(config["probes"]["selection"] == "preset" for config in parsed) == 2


@pytest.mark.parametrize("label", ["positive", "negative"])
@pytest.mark.parametrize(
    ("verdict", "reason"),
    [
        (Verdict.INCONCLUSIVE, "boolean_candidate"),
        (Verdict.NOT_DETECTED, "no_boolean_difference_literal_input"),
        (Verdict.INCONCLUSIVE, "unexpected_difference"),
    ],
)
def test_runner_reuses_the_reliability_classification(label, verdict, reason):
    runner = load_runner()
    assert runner.classify(label, verdict.value, reason) == reliability_classify(
        label, verdict, reason
    )


def test_reviewed_documentation_matches_the_report_contract():
    runner = load_runner()
    report = expected_report()
    runner.check_documented_summary(report)
    rendered = runner.render_summary(report)
    assert "n=2" not in rendered
    assert rendered.count("dsvw-blind-boolean-id") == 2
    assert rendered.count("dsvw-version-query") == 2


def test_compose_is_internal_loopback_only_and_never_pulls():
    compose = (THIRD_PARTY / "dsvw" / "compose.yaml").read_text()
    assert "pull_policy: never" in compose
    assert "expose:" in compose
    assert '"65412"' in compose
    assert "ports:" not in compose
    assert "internal: true" in compose
    assert "PEX_ROOT: /tmp/pex" in compose
    assert "/tmp:size=128m" in compose
    assert "0.0.0.0" not in compose


def test_prepare_ignores_modified_stale_extraction(tmp_path, monkeypatch):
    preparer = load_preparer()
    commit = "0123456789abcdef0123456789abcdef01234567"
    archive_source = tmp_path / "archive-source" / f"DSVW-{commit}"
    archive_source.mkdir(parents=True)
    (archive_source / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    (archive_source / "dsvw.py").write_text("one\ntwo\nthree\n", encoding="utf-8")

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    archive = workspace / f"dsvw-{commit}.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        bundle.add(archive_source, arcname=archive_source.name)

    stale = workspace / "source" / archive_source.name
    stale.mkdir(parents=True)
    (stale / "Dockerfile").write_text("MODIFIED STALE FILE\n", encoding="utf-8")
    archive_digest = preparer.sha256_file(archive)
    monkeypatch.setattr(
        preparer,
        "load_target",
        lambda: {
            "archive_sha256": archive_digest,
            "archive_url": "https://invalid.example/archive",
            "commit": commit,
        },
    )
    monkeypatch.setattr(
        preparer,
        "load_records",
        lambda: [
            {
                "id": "reviewed",
                "source_path": "dsvw.py",
                "source_start_line": 1,
                "source_end_line": 1,
            }
        ],
    )
    observed: dict[str, object] = {}

    def fake_docker(arguments):
        if arguments[0] == "build":
            context = Path(arguments[-1])
            observed["context"] = context
            observed["dockerfile"] = (context / "Dockerfile").read_text(
                encoding="utf-8"
            )
            observed["manifest"] = preparer.source_manifest_sha256(context)
            return ""
        return "sha256:prepared-image"

    monkeypatch.setattr(preparer, "run_docker", fake_docker)
    state_path = preparer.prepare(workspace)
    state = json.loads(state_path.read_text(encoding="utf-8"))

    assert observed["dockerfile"] == "FROM scratch\n"
    assert observed["manifest"] == state["source_manifest_sha256"]
    assert state["source_evidence"] == {
        "reviewed": {
            "source_end_line": 1,
            "source_fragment_sha256": (
                "2c8b08da5ce60398e1f19af0e5dccc744df274b826abe585eaba68c525434806"
            ),
            "source_path": "dsvw.py",
            "source_start_line": 1,
        }
    }
    assert observed["context"] != stale
    assert not Path(observed["context"]).exists()
    assert (stale / "Dockerfile").read_text(encoding="utf-8") == (
        "MODIFIED STALE FILE\n"
    )


def test_compose_projects_are_unique_and_teardown_uses_own_run(monkeypatch, tmp_path):
    runner = load_runner()
    first = runner.compose_project_name(runner.new_run_id(), 0, "six")
    second = runner.compose_project_name(runner.new_run_id(), 0, "six")
    assert first != second
    assert re.fullmatch(r"vintar-dsvw-[0-9a-f]{12}-0-six", first)
    assert len(first) < 64

    monkeypatch.setattr(
        runner,
        "load_declarations",
        lambda: (
            {
                "archive_sha256": "archive",
                "commit": "commit",
                "license": "Unlicense",
                "name": "DSVW",
            },
            [{"id": "case"}],
        ),
    )
    monkeypatch.setattr(runner, "load_document", lambda path: {})
    monkeypatch.setattr(
        runner, "validate_provenance", lambda state, target, records: ("image", "id")
    )
    monkeypatch.setattr(runner, "new_run_id", lambda: "0123456789ab")
    started: list[str] = []
    stopped: list[str] = []

    def fake_start(image_tag, project):
        started.append(project)
        return "172.20.0.2"

    @contextmanager
    def fake_bridge(upstream):
        yield "http://127.0.0.1:12345"

    def fake_result(folder, origin, declaration, mode):
        return {
            "actual_verdict": "inconclusive",
            "classification": "non_decision",
            "confirmation": {"status": "not_eligible"},
            "endpoint_id": "case",
            "expected_label": "negative",
            "expected_verdict": "not_detected",
            "mode": "six_probe" if mode == "six" else "confirmation",
            "reason_code": "unexpected_difference",
            "request_count": 6,
        }

    monkeypatch.setattr(runner, "start_target", fake_start)
    monkeypatch.setattr(
        runner, "stop_target", lambda image, project: stopped.append(project)
    )
    monkeypatch.setattr(runner, "loopback_bridge", fake_bridge)
    monkeypatch.setattr(runner, "run_pipeline_case", fake_result)
    monkeypatch.setattr(runner, "write_report", lambda path, report: None)
    monkeypatch.setattr(runner, "check_documented_summary", lambda report: None)

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    runner.measure(workspace, tmp_path / "report.json")

    assert started == [
        "vintar-dsvw-0123456789ab-0-six",
        "vintar-dsvw-0123456789ab-0-confirmation",
    ]
    assert stopped == started


def prepared_provenance():
    record = {
        "id": "dsvw-record",
        "source_end_line": 23,
        "source_fragment_sha256": "a" * 64,
        "source_path": "dsvw.py",
        "source_start_line": 21,
    }
    state = {
        "archive_sha256": "archive",
        "commit": "commit",
        "image_id": "sha256:image",
        "image_tag": "image:tag",
        "schema_version": 1,
        "source_evidence": {
            "dsvw-record": {key: value for key, value in record.items() if key != "id"}
        },
        "source_manifest_sha256": "b" * 64,
    }
    target = {"archive_sha256": "archive", "commit": "commit"}
    return state, target, record


@pytest.mark.parametrize(
    ("field", "changed"),
    [
        ("source_path", "changed.py"),
        ("source_start_line", 20),
        ("source_end_line", 24),
    ],
)
def test_changed_source_reference_is_rejected_before_docker(
    field, changed, monkeypatch
):
    runner = load_runner()
    state, target, record = prepared_provenance()
    changed_record = {**record, field: changed}
    docker_calls: list[list[str]] = []
    monkeypatch.setattr(
        runner,
        "run_command",
        lambda command, **kwargs: docker_calls.append(command),
    )

    with pytest.raises(
        runner.MeasurementError,
        match=rf"dsvw-record differs at field {field}.*Rerun prepare.*source_fragment_sha256",
    ):
        runner.validate_provenance(state, target, [changed_record])

    assert docker_calls == []


def test_unchanged_source_reference_passes_before_docker(monkeypatch):
    runner = load_runner()
    state, target, record = prepared_provenance()
    docker_calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        docker_calls.append(command)
        return SimpleNamespace(stdout="sha256:image\n")

    monkeypatch.setattr(runner, "run_command", fake_run)

    assert runner.validate_provenance(state, target, [record]) == (
        "image:tag",
        "sha256:image",
    )
    assert docker_calls == [
        ["docker", "image", "inspect", "--format", "{{.Id}}", "image:tag"]
    ]
