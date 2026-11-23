"""Prevent wall-clock loopback tests from asserting exact timing classifications."""

import ast
from pathlib import Path

import pytest

TIMING_RESULT_ATTRIBUTES = frozenset(
    {"status", "reason_code", "final_verdict", "final_reason_code"}
)
LIVE_TEST_NAME_MARKERS = ("http", "loopback", "pipeline")


def _attribute_names(node: ast.AST) -> set[str]:
    return {item.attr for item in ast.walk(node) if isinstance(item, ast.Attribute)}


def _is_nine_request_live_test(node: ast.FunctionDef) -> bool:
    if not node.name.startswith("test_") or not any(
        marker in node.name for marker in LIVE_TEST_NAME_MARKERS
    ):
        return False
    attributes = _attribute_names(node)
    return "request_count" in attributes and any(
        isinstance(item, ast.Constant) and item.value == 9 for item in ast.walk(node)
    )


def exact_live_timing_assertions(source: str, path: str) -> tuple[str, ...]:
    violations = []
    tree = ast.parse(source, filename=path)
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or not _is_nine_request_live_test(
            node
        ):
            continue
        for item in ast.walk(node):
            if not isinstance(item, ast.Assert) or not isinstance(
                item.test, ast.Compare
            ):
                continue
            if not any(
                isinstance(operator, (ast.Eq, ast.Is)) for operator in item.test.ops
            ):
                continue
            if _attribute_names(item.test).isdisjoint(TIMING_RESULT_ATTRIBUTES):
                continue
            violations.append(f"{path}:{item.lineno}: {ast.unparse(item.test)}")
    return tuple(violations)


def test_live_timing_tests_do_not_assert_exact_classifications():
    violations = []
    for path in sorted(Path("tests").glob("test_*.py")):
        violations.extend(
            exact_live_timing_assertions(path.read_text(encoding="utf-8"), str(path))
        )

    assert not violations, (
        "Live nine-request timing tests must not assert an exact wall-clock status or "
        "reason because scheduler jitter can change a valid non-passing result. Use a "
        "named allowed status/reason set for live mechanics and a fixed-observation test "
        "for exact classification instead. Violations: " + "; ".join(violations)
    )


@pytest.mark.parametrize(
    "exact_assertion",
    (
        "assert report.analysis.status is TimeAnalysisStatus.CANDIDATE",
        "assert report.analysis.reason_code == 'timing_pattern_matched'",
        "assert outcome.final_verdict is Verdict.NOT_DETECTED",
    ),
)
def test_exact_live_timing_assertion_guard_rejects_regressions(exact_assertion):
    source = f"""\
def test_example_loopback():
    assert report.analysis.request_count == 9
    {exact_assertion}
"""

    violations = exact_live_timing_assertions(source, "tests/test_example.py")

    assert len(violations) == 1
    assert exact_assertion.removeprefix("assert ") in violations[0]
