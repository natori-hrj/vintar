"""Check that Vintar sends verification requests through its execution layer."""

import ast
import sys
from importlib.util import resolve_name
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src" / "vintar"
HTTP_FILES = {Path("core/http.py"), Path("core/executor.py")}
HTTPX_SEND_APIS = {
    f"httpx.{name}"
    for name in (
        "Client",
        "AsyncClient",
        "delete",
        "get",
        "head",
        "options",
        "patch",
        "post",
        "put",
        "request",
        "stream",
    )
}
SEND_TEMPLATE = "vintar.core.template.send_template"
JSON_BODY_LOCATION = "vintar.core.request.InjectionLocation.JSON_BODY"
JSON_BODY_PRIMITIVE_FILES = {Path("core/request.py"), Path("core/injector.py")}
DISCOVERY_IMPORTS = {
    "__future__",
    "collections.abc",
    "dataclasses",
    "hashlib",
    "json",
    "math",
    "os",
    "pathlib",
    "re",
    "stat",
    "tomllib",
    "urllib.parse",
    "yaml",
    "yaml.events",
}


DISCOVER_CLI_IMPORTS = DISCOVERY_IMPORTS | {
    "tempfile",
    "typing",
    "typer",
    "vintar.regression.discovery",
    "vintar.regression.discovery_drafts",
}


def discovery_diagnostics(path, tree):
    allowed = (
        DISCOVER_CLI_IMPORTS
        if path
        in {
            Path("discover_cli.py"),
            Path("review_draft_cli.py"),
            Path("materialize_case_cli.py"),
        }
        else DISCOVERY_IMPORTS
    )
    if path == Path("review_draft_cli.py"):
        allowed = allowed | {"vintar.regression.discovery_review"}
    if path == Path("materialize_case_cli.py"):
        allowed = DISCOVER_CLI_IMPORTS | {
            "vintar.regression.case_materialization",
            "vintar.regression.discovery_review",
        }
    if path == Path("regression/discovery_review.py"):
        allowed = DISCOVERY_IMPORTS | {
            "vintar.regression.discovery",
            "vintar.regression.discovery_drafts",
        }
    if path == Path("regression/discovery_drafts.py"):
        allowed = DISCOVERY_IMPORTS | {
            "errno",
            "tempfile",
            "vintar.regression.discovery",
        }
    if path == Path("regression/case_materialization.py"):
        allowed = DISCOVERY_IMPORTS | {
            "errno",
            "tempfile",
            "vintar.checks.sqli.presets",
            "vintar.regression.cases",
            "vintar.regression.discovery",
            "vintar.regression.discovery_review",
        }
    if path == Path("checks/sqli/presets.py"):
        allowed = {"collections.abc", "dataclasses", "types"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            modules = ["." * node.level + (node.module or "")]
        else:
            continue
        for module in modules:
            if module not in allowed:
                yield (
                    f"{path}:{node.lineno}: Discovery must remain offline; importing {module} "
                    "can expose HTTP or execution. Use the local parser for inventory and "
                    "keep execution in the regression runner through ExecutionContext."
                )


def import_names(node, package):
    if isinstance(node, ast.Import):
        for alias in node.names:
            root = alias.name.split(".")[0]
            yield (alias.asname, alias.name) if alias.asname else (root, root)
    elif isinstance(node, ast.ImportFrom):
        module = node.module or ""
        if node.level:
            if node.level > len(package.split(".")):
                return
            module = resolve_name("." * node.level + module, package)
        for alias in node.names:
            yield alias.asname or alias.name, f"{module}.{alias.name}"


def qualified_names(node, imports):
    if isinstance(node, ast.Name):
        return imports.get(node.id, ())
    if isinstance(node, ast.Attribute):
        return (f"{name}.{node.attr}" for name in qualified_names(node.value, imports))
    return ()


def check_source(path: Path, source: str) -> list[str]:
    """Check Python source at a path relative to src/vintar."""
    tree = ast.parse(source, filename=str(path))
    if path in {
        Path("discover_cli.py"),
        Path("review_draft_cli.py"),
        Path("materialize_case_cli.py"),
        Path("checks/sqli/presets.py"),
        Path("regression/case_materialization.py"),
        Path("regression/discovery_review.py"),
        Path("regression/discovery.py"),
        Path("regression/discovery_drafts.py"),
    } or path.parts[:2] == (
        "regression",
        "discovery",
    ):
        return sorted(discovery_diagnostics(path, tree))
    package = ".".join(("vintar", *path.parent.parts))
    in_checks = path.parts[0] == "checks"
    imports: dict[str, set[str]] = {}
    violations = set()

    for node in ast.walk(tree):
        for local, qualified in import_names(node, package):
            imports.setdefault(local, set()).add(qualified)
            if in_checks and qualified == SEND_TEMPLATE:
                violations.add((node.lineno, qualified))

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and path not in HTTP_FILES:
            for name in qualified_names(node.func, imports):
                if name in HTTPX_SEND_APIS:
                    violations.add((node.lineno, name))
        if (
            in_checks
            and isinstance(node, ast.Attribute)
            and SEND_TEMPLATE in qualified_names(node, imports)
        ):
            violations.add((node.lineno, SEND_TEMPLATE))
        if path not in JSON_BODY_PRIMITIVE_FILES:
            for name in qualified_names(node, imports):
                if name == JSON_BODY_LOCATION:
                    violations.add((node.lineno, name))

    return [
        (
            f"{path}:{line}: JSON body injection is a request primitive only in PR 1. "
            "Do not construct a JSON_BODY injection point in checks, CLI, regression, or execution paths."
            if name == JSON_BODY_LOCATION
            else f"{path}:{line}: {name} bypasses scope, request budgets, and rate limits. "
            "Use vintar.core.executor.ExecutionContext."
        )
        for line, name in sorted(violations)
    ]


def main() -> int:
    failed = False
    for path in sorted(SOURCE_ROOT.rglob("*.py")):
        for diagnostic in check_source(
            path.relative_to(SOURCE_ROOT), path.read_text(encoding="utf-8")
        ):
            print(f"src/vintar/{diagnostic}", file=sys.stderr)
            failed = True
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
