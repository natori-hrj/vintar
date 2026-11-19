"""Serialize and write offline review drafts from typed inventory records."""

import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile

from vintar.regression.discovery import Input, Inventory, Operation, input_id

MISSING_DECISIONS = (
    "route mapping and baseline query values",
    "trusted target, authorization, and any credential requirements",
    "reviewed check configuration and probe inputs",
    "expected verdict",
    "trusted limits and required Schema v1 case fields",
)


class DraftExportError(ValueError):
    """A safe diagnostic for an invalid draft export."""


def _string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False).replace("\x7f", r"\u007f")


def _draft(
    operation: Operation, item: Input, identifier: str, source_file: Path
) -> bytes:
    lines = [
        'kind = "vintar_review_draft"',
        "draft_version = 1",
        f'id = "case-{identifier.removeprefix("input-")}"',
        f"input_id = {_string(identifier)}",
        f"method = {_string(operation.method)}",
        f"path = {_string(operation.path)}",
        f"query_parameter = {_string(item.name)}",
        f"missing_decisions = [{', '.join(map(_string, MISSING_DECISIONS))}]",
        "",
        "[source]",
        f"file = {_string(source_file.as_posix())}",
        f"operation = {_string(operation.source.pointer)}",
        f"operation_definition = {_string(operation.definition.pointer)}",
        f"declaration = {_string(item.source.pointer)}",
        f"definition = {_string(item.definition.pointer)}",
    ]
    for parameter in operation.inputs:
        if parameter.location == "query":
            lines.extend(
                (
                    "",
                    "[[query_parameters]]",
                    f"name = {_string(parameter.name)}",
                    f"required = {str(parameter.required).lower()}",
                )
            )
    return ("\n".join(lines) + "\n").encode("utf-8")


def draft_files(
    inventory: Inventory, selected: frozenset[str], source_file: Path
) -> dict[str, bytes]:
    try:
        source_file.as_posix().encode("utf-8")
    except UnicodeEncodeError as exc:
        raise DraftExportError(
            f"Spec path {source_file.as_posix()!a} cannot be encoded as UTF-8. "
            "Rename the file or its parent directories using valid UTF-8 names."
        ) from exc
    drafts = {}
    for operation in inventory.operations:
        for item in operation.inputs:
            identifier = input_id(operation, item)
            if identifier in selected:
                name = f"case-{identifier.removeprefix('input-')}.draft.toml"
                content = _draft(operation, item, identifier, source_file)
                if len(content) > 65_536:
                    raise DraftExportError(
                        f"Draft {name} exceeds 64 KiB. Shorten the declarations and retry."
                    )
                drafts[name] = content
    return dict(sorted(drafts.items()))


def write_drafts(
    directory: Path, drafts: dict[str, bytes], inputs: tuple[Path, ...]
) -> None:
    directory = directory.absolute()
    for parent in (*directory.parents, directory):
        if parent.is_symlink() or (parent.exists() and not parent.is_dir()):
            raise DraftExportError(
                "Draft directory traverses a symlink or non-directory. Choose a real directory."
            )
    pending = {}
    for name, content in drafts.items():
        path = directory / name
        if path.is_symlink():
            raise DraftExportError(
                f"Draft path {name} is a symlink. Choose a different directory."
            )
        if any(path.resolve() == source.resolve() for source in inputs):
            raise DraftExportError(
                f"Draft path {name} aliases an input file. Choose a different directory."
            )
        if not path.exists():
            pending[path] = content
            continue
        if any(path.samefile(source) for source in inputs):
            raise DraftExportError(
                f"Draft path {name} aliases an input file. Choose a different directory."
            )
        if path.is_file() and path.stat().st_size == len(content):
            with path.open("rb") as stream:
                if stream.read(len(content) + 1) == content:
                    continue
        raise DraftExportError(
            f"Draft path {name} already has different content. Use an empty directory or move the existing file."
        )
    if pending:
        directory.mkdir(parents=True, exist_ok=True)
    for path, content in pending.items():
        _publish(path, content)


def _publish(path: Path, content: bytes) -> None:
    temporary: Path | None = None
    try:
        with NamedTemporaryFile(
            dir=path.parent, prefix=".vintar-draft-", delete=False
        ) as stream:
            temporary = Path(stream.name)
            if stream.write(content) != len(content):
                raise OSError("Incomplete draft write.")
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise DraftExportError(
                f"Draft path {path.name} appeared during export. Choose an empty directory or rerun after reviewing it."
            ) from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
