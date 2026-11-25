"""POST JSON review CLI privacy and output contracts."""

import json

import pytest
from test_post_json_review import SENTINEL, inputs, write_answer
from typer.testing import CliRunner

from vintar.cli import app
from vintar.regression.post_json_review import STALE_BODY_DIGEST_MESSAGE


def test_review_cli_writes_only_redacted_artifact_and_summary(tmp_path):
    spec, inventory, answers, _ = inputs(tmp_path, nested=True)
    output = tmp_path / "review.json"

    result = CliRunner().invoke(
        app,
        [
            "review-post-json",
            "--spec",
            str(spec),
            "--inventory",
            str(inventory),
            "--answers",
            str(answers),
            "--output",
            str(output),
        ],
    )

    combined = result.stdout + result.stderr + output.read_text(encoding="utf-8")
    assert result.exit_code == 0 and result.stderr == ""
    assert SENTINEL not in combined
    assert json.loads(result.stdout)["report_type"] == (
        "post_json_discovery_review_summary"
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda answer: answer.update(operation_approved=False),
        lambda answer: answer["side_effect"].update(confirmed=False),
        lambda answer: answer["environment"].update(confirmed=False),
        lambda answer: answer["baseline"].update(body_sha256="0" * 64),
        lambda answer: answer.update(concrete_pointer="/missing"),
    ],
)
def test_review_cli_failures_never_echo_body_values(tmp_path, mutation):
    spec, inventory, answers, answer = inputs(tmp_path)
    mutation(answer)
    write_answer(answers, answer)
    output = tmp_path / "review.json"

    result = CliRunner().invoke(
        app,
        [
            "review-post-json",
            "--spec",
            str(spec),
            "--inventory",
            str(inventory),
            "--answers",
            str(answers),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 2 and result.stdout == "" and not output.exists()
    assert SENTINEL not in result.stderr
    if answer["baseline"]["body_sha256"] == "0" * 64:
        assert result.stderr == f"Error: {STALE_BODY_DIGEST_MESSAGE}\n"


@pytest.mark.parametrize(
    ("failure", "code", "diagnostic"),
    [
        (
            None,
            2,
            "Draft path review.json already has different content. Use an empty directory or move the existing file.",
        ),
        (
            OSError,
            2,
            "cannot complete offline POST JSON review. Check the local spec, current inventory, answers, and writable output path.",
        ),
        (
            KeyboardInterrupt,
            130,
            "POST JSON review was interrupted. Rerun to regenerate the review artifact.",
        ),
    ],
)
def test_review_cli_preserves_output_on_publication_failure(
    tmp_path, monkeypatch, failure, code, diagnostic
):
    spec, inventory, answers, _ = inputs(tmp_path)
    directory = tmp_path / "output"
    directory.mkdir()
    output = directory / "review.json"
    existing = b"existing review notes\n"

    def fail_sync(_descriptor):
        # Another writer can publish after the destination check. Exclusive
        # creation also catches a regression that writes directly to output.
        with output.open("xb") as stream:
            stream.write(existing)
        raise failure("synthetic temporary-file sync failure")

    if failure is None:
        output.write_bytes(existing)
    else:
        monkeypatch.setattr("vintar.regression.discovery_drafts.os.fsync", fail_sync)
    result = CliRunner().invoke(
        app,
        [
            "review-post-json",
            "--spec",
            str(spec),
            "--inventory",
            str(inventory),
            "--answers",
            str(answers),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == code
    assert result.stderr == f"Error: {diagnostic}\n"
    assert result.stdout == ""
    assert output.read_bytes() == existing
    assert list(directory.iterdir()) == [output]
