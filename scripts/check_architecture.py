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
AUTH_APPLY = "vintar.auth.apply"
JSON_BODY_LOCATION = "vintar.core.request.InjectionLocation.JSON_BODY"
JSON_BODY_PRIMITIVE_FILES = {
    Path("core/request.py"),
    Path("core/injector.py"),
    Path("regression/runner.py"),
}
DISCOVERY_IMPORTS = {
    "__future__",
    "collections.abc",
    "dataclasses",
    "enum",
    "hashlib",
    "json",
    "math",
    "os",
    "pathlib",
    "re",
    "stat",
    "tomllib",
    "typing",
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
            Path("materialize_post_json_case_cli.py"),
            Path("post_json_inventory_cli.py"),
            Path("post_json_review_cli.py"),
        }
        else DISCOVERY_IMPORTS
    )
    if path == Path("review_draft_cli.py"):
        allowed = allowed | {"vintar.regression.discovery_review"}
    if path == Path("post_json_inventory_cli.py"):
        allowed = DISCOVER_CLI_IMPORTS | {"vintar.regression.post_json_inventory"}
    if path == Path("post_json_review_cli.py"):
        allowed = DISCOVER_CLI_IMPORTS | {
            "vintar.regression.post_json_review",
        }
    if path == Path("materialize_case_cli.py"):
        allowed = DISCOVER_CLI_IMPORTS | {
            "vintar.regression.case_materialization",
            "vintar.regression.discovery_review",
        }
    if path == Path("materialize_post_json_case_cli.py"):
        allowed = DISCOVER_CLI_IMPORTS | {
            "vintar.regression.post_json_case_materialization",
        }
    if path == Path("regression/discovery_review.py"):
        allowed = DISCOVERY_IMPORTS | {
            "vintar.regression.discovery",
            "vintar.regression.discovery_drafts",
        }
    if path == Path("regression/post_json_inventory.py"):
        allowed = DISCOVERY_IMPORTS | {"vintar.regression.discovery"}
    if path == Path("regression/post_json_review.py"):
        allowed = DISCOVERY_IMPORTS | {
            "vintar.core.json_body",
            "vintar.core.strict_json",
            "vintar.regression.discovery",
            "vintar.regression.discovery_drafts",
            "vintar.regression.post_json_inventory",
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
            "vintar.core.strict_json",
            "vintar.regression.cases",
            "vintar.regression.discovery",
            "vintar.regression.discovery_review",
        }
    if path == Path("regression/post_json_case_materialization.py"):
        allowed = DISCOVERY_IMPORTS | {
            "vintar.core.strict_json",
            "vintar.regression.cases",
            "vintar.regression.cases_v2",
            "vintar.regression.discovery",
            "vintar.regression.discovery_drafts",
            "vintar.regression.file_io",
            "vintar.regression.post_json_review",
        }
    if path == Path("regression/cases_v2.py"):
        allowed = DISCOVERY_IMPORTS | {
            "hashlib",
            "httpx",
            "importlib",
            "jsonschema",
            "jsonschema.exceptions",
            "unicodedata",
            "vintar.checks.sqli.error_analyzer",
            "vintar.checks.sqli.models",
            "vintar.core.json_body",
            "vintar.core.scope",
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
        Path("materialize_post_json_case_cli.py"),
        Path("post_json_inventory_cli.py"),
        Path("post_json_review_cli.py"),
        Path("checks/sqli/presets.py"),
        Path("regression/case_materialization.py"),
        Path("regression/cases_v2.py"),
        Path("regression/post_json_case_materialization.py"),
        Path("regression/discovery_review.py"),
        Path("regression/post_json_inventory.py"),
        Path("regression/post_json_review.py"),
        Path("regression/discovery.py"),
        Path("regression/discovery_drafts.py"),
    } or path.parts[:2] == (
        "regression",
        "discovery",
    ):
        return sorted(discovery_diagnostics(path, tree))
    package = ".".join(("vintar", *path.parent.parts))
    in_checks = path.parts[0] == "checks"
    in_auth = path.parts[0] == "auth"
    imports: dict[str, set[str]] = {}
    violations = set()

    for node in ast.walk(tree):
        direct_modules: tuple[str, ...] = ()
        if isinstance(node, ast.Import):
            direct_modules = tuple(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            direct_modules = (node.module or "",)
        for module in direct_modules:
            if module == AUTH_APPLY and path != Path("regression/runner.py"):
                violations.add((node.lineno, AUTH_APPLY))
            if in_checks and (
                module == "vintar.auth" or module.startswith("vintar.auth.")
            ):
                violations.add((node.lineno, "vintar.auth"))
        for local, qualified in import_names(node, package):
            imports.setdefault(local, set()).add(qualified)
            if in_checks and qualified == SEND_TEMPLATE:
                violations.add((node.lineno, qualified))
            if in_auth and (
                qualified.startswith(("vintar.regression", "vintar.checks"))
                or qualified
                in {
                    "vintar.cli",
                    "vintar.sqli_cli",
                    "vintar.regression_cli",
                    "vintar.core.executor.ExecutionContext",
                    SEND_TEMPLATE,
                }
            ):
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
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.ctx, ast.Store)
            and isinstance(node.value, ast.Attribute)
            and node.value.attr == "headers"
            and path != Path("auth/apply.py")
        ):
            violations.add((node.lineno, "credential-header-application"))
        if path not in JSON_BODY_PRIMITIVE_FILES:
            for name in qualified_names(node, imports):
                if name == JSON_BODY_LOCATION:
                    violations.add((node.lineno, name))

    return [
        (
            f"{path}:{line}: JSON body injection may be constructed only by core primitives "
            "or the trusted POST execution adapter in regression/runner.py."
            if name == JSON_BODY_LOCATION
            else f"{path}:{line}: Authentication application may be composed only by regression/runner.py."
            if name == AUTH_APPLY
            else f"{path}:{line}: Checks cannot import authentication or touch credential material."
            if name == "vintar.auth"
            else f"{path}:{line}: Credential headers may be applied only by vintar.auth.apply."
            if name == "credential-header-application"
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
