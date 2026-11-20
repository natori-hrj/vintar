"""Verify the documented commands and report excerpts against CLI goldens."""

import json
import re
import shlex
import tomllib
from pathlib import Path

import pytest
from test_cli_goldens import GOLDEN_DIR, SCENARIOS, capture

README = Path(__file__).resolve().parents[1] / "README.md"
EXAMPLES = {
    "verify-pass": "verify/pass.json",
    "sqli-normal": "sqli-verify/normal.json",
    "discover-review": "discover/success.json",
    "discover-drafts": "discover/drafts.json",
    "draft-review": "review-draft/success.json",
}
BLOCKS = {
    "verify-pass/case": "toml",
    "verify-pass/command": "bash",
    "verify-pass/report": "json",
    "sqli-normal/command": "bash",
    "sqli-normal/report": "json",
    "discover-review/selection": "toml",
    "discover-review/command": "bash",
    "discover-review/report": "json",
    "discover-drafts/command": "bash",
    "discover-drafts/report": "json",
    "draft-review/answers": "json",
    "draft-review/command": "bash",
    "draft-review/report": "json",
}
CASE_PATH = "security/cases/a-case.toml"
ORIGIN_VARIABLES = {"VINTAR_TARGET_ORIGIN", "VINTAR_ALLOWED_ORIGIN"}


@pytest.fixture(scope="module")
def readme_blocks():
    source = README.read_text(encoding="utf-8")
    markers = re.finditer(r"^<!-- cli-example: ([^\n]+) -->$", source, re.MULTILINE)
    blocks = {}
    for marker in markers:
        identifier = marker[1]
        assert identifier in BLOCKS, (
            f"Unknown README example identifier {identifier!r}. Use {sorted(BLOCKS)}."
        )
        assert identifier not in blocks, (
            f"Duplicate README example identifier {identifier!r}. Keep one marked block."
        )
        fence = re.match(
            r"\n```(\w+)\n(.*?)\n```(?=\n|$)", source[marker.end() :], re.DOTALL
        )
        assert fence and fence[1] == BLOCKS[identifier], (
            f"README example {identifier!r} has an invalid fence. "
            f"Place a {BLOCKS[identifier]} block immediately after its marker."
        )
        blocks[identifier] = fence[2]

    assert blocks.keys() == BLOCKS.keys(), (
        f"Missing README example identifiers: {sorted(BLOCKS.keys() - blocks.keys())}. "
        "Restore the corresponding markers and fenced blocks."
    )
    return blocks


def read_command(example, command):
    lines = command.splitlines()
    assert lines and all(line.endswith("\\") for line in lines[:-1]), (
        f"Invalid README command {example!r}. Add a trailing backslash to each continuation line."
    )
    try:
        tokens = shlex.split(command.replace("\\\n", ""))
    except ValueError as error:
        pytest.fail(
            f"Invalid quoting in README command {example!r}: {error}. Fix the command block."
        )

    env = {}
    while tokens and tokens[0] != "uv":
        name, separator, value = tokens.pop(0).partition("=")
        assert separator and name in ORIGIN_VARIABLES and name not in env and value, (
            f"Invalid environment assignment in README command {example!r}. "
            "Set each required Vintar origin variable once before the command."
        )
        env[name] = value

    assert tokens[:4] == ["uv", "run", "--locked", "vintar"], (
        f"Invalid command prefix for README example {example!r}. Use uv run --locked vintar."
    )
    return tokens[4:], env


@pytest.mark.parametrize("example", EXAMPLES)
def test_readme_cli_example(example, readme_blocks, tmp_path):
    args, env = read_command(example, readme_blocks[f"{example}/command"])
    if example == "verify-pass":
        assert env.keys() == ORIGIN_VARIABLES, (
            "The README batch command must set both Vintar origin variables."
        )
        case = readme_blocks[f"{example}/case"]
        try:
            tomllib.loads(case)
        except tomllib.TOMLDecodeError as error:
            pytest.fail(
                f"Invalid TOML in the README batch case: {error}. Fix the TOML block."
            )
        assert "--cases" in args, (
            f"The README batch command must pass the documented case with --cases {CASE_PATH}."
        )
        path_arg = args.index("--cases") + 1
        assert args[path_arg : path_arg + 1] == [CASE_PATH], (
            f"Set --cases to the documented case path {CASE_PATH} in the README."
        )
        case_path = tmp_path / Path(CASE_PATH).name
        case_path.write_text(case, encoding="utf-8")
        args[path_arg] = str(case_path)
    elif example == "draft-review":
        assert not env, "Remove origin variables from the offline review command."
        answers = readme_blocks["draft-review/answers"]
        try:
            json.loads(answers)
        except ValueError as error:
            pytest.fail(
                f"Invalid README review answers JSON: {error}. Fix the answers block."
            )
        (tmp_path / "answers.json").write_text(answers, encoding="utf-8")
    elif example in {"discover-review", "discover-drafts"}:
        assert not env, "Remove origin variables from the offline discovery command."
        selection = readme_blocks["discover-review/selection"]
        try:
            tomllib.loads(selection)
        except tomllib.TOMLDecodeError as error:
            pytest.fail(
                f"Invalid discovery selection TOML: {error}. Fix the README TOML block."
            )
        (tmp_path / "review.toml").write_text(selection, encoding="utf-8")
    else:
        assert not env, (
            "Remove batch-only origin variables from the README single-check command."
        )

    golden_name = EXAMPLES[example]
    try:
        actual = capture(
            golden_name, SCENARIOS[golden_name], tmp_path, args=args, env=env
        )
    except ValueError as error:
        pytest.fail(
            f"README example {example!r} failed: {error} "
            "Fix the documented command, flags, or case TOML."
        )
    golden = (GOLDEN_DIR / golden_name).read_text(encoding="utf-8")
    assert actual == golden, (
        f"README example {example!r} differs from {golden_name}. "
        "Update the documented command or TOML to match the scenario."
    )

    try:
        excerpt = json.loads(readme_blocks[f"{example}/report"])
    except ValueError as error:
        pytest.fail(
            f"Invalid JSON excerpt for {example!r}: {error}. Fix the report block."
        )
    assert isinstance(excerpt, dict) and excerpt, (
        f"README report excerpt for {example!r} must be a nonempty JSON object."
    )
    report = json.loads(golden)["stdout_json"]
    expected = {key: report[key] for key in excerpt if key in report}
    assert json.dumps(excerpt, sort_keys=True) == json.dumps(
        expected, sort_keys=True
    ), (
        f"README report excerpt for {example!r} differs from {golden_name}. "
        "Copy the documented fields and values from the golden report."
    )
