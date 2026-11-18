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

    return [
        f"{path}:{line}: {name} bypasses scope, request budgets, and rate limits. "
        "Use vintar.core.executor.ExecutionContext."
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
