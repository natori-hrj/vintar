"""Package and verify binaries from the exact-SHA Go foundation rehearsal."""

import gzip
import hashlib
import io
import json
import re
import sys
import tarfile
import zipfile
from pathlib import Path
from urllib.parse import quote

TARGETS = (
    "linux/amd64",
    "linux/arm64",
    "darwin/amd64",
    "darwin/arm64",
    "windows/amd64",
)
MODULE = "github.com/natori-hrj/vintar"
SOURCE = "https://github.com/natori-hrj/vintar"
NOTICE_FILES = ("LICENSE", "LICENCE", "COPYING", "NOTICE", "PATENTS")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_builds(foundation, commit, toolchain):
    rows = (foundation / "targets.tsv").read_text(encoding="utf-8").splitlines()
    require(
        rows[:1] == ["commit\tgo\ttarget\tsha256\trepeated-build"],
        "wrong matrix header",
    )
    builds = {}
    for row in rows[1:]:
        sha, go, target, checksum, repeated = row.split("\t")
        require(
            sha == commit
            and go == toolchain
            and target in TARGETS
            and target not in builds
            and repeated == "match"
            and re.fullmatch(r"[0-9a-f]{64}", checksum),
            f"invalid build evidence: {row}",
        )
        builds[target] = checksum
    require(set(builds) == set(TARGETS), "missing release targets")
    return builds


def read_metadata(path, executable, toolchain, target, commit, sums):
    lines = path.read_text(encoding="utf-8").splitlines()
    require(lines[:1] == [f"{executable}: {toolchain}"], f"{target}: wrong Go version")
    fields = [line.strip().split("\t") for line in lines[1:]]
    require(["path", f"{MODULE}/cmd/vintar"] in fields, f"{target}: wrong entry point")
    require(
        any(f[:2] == ["mod", MODULE] for f in fields), f"{target}: wrong main module"
    )
    settings = dict(f[1].split("=", 1) for f in fields if f[0] == "build")
    system, arch = target.split("/")
    expected = {
        "GOOS": system,
        "GOARCH": arch,
        "CGO_ENABLED": "0",
        "-trimpath": "true",
        "vcs": "git",
        "vcs.revision": commit,
        "vcs.modified": "false",
    }
    require(
        all(settings.get(k) == v for k, v in expected.items()),
        f"{target}: bad build metadata",
    )
    dependencies = []
    for f in fields:
        require(f[0] != "=>", f"{target}: replacement module")
        if f[0] == "dep":
            _, path, version, checksum = f
            require(
                (path, version, checksum) in sums,
                f"{target}: dependency is not in go.sum",
            )
            require(
                path != "github.com/santhosh-tekuri/jsonschema/v6",
                f"{target}: test-only dependency",
            )
            dependencies.append((path, version, checksum))
    return sorted(dependencies)


def notices(directory, prefix):
    entries = {
        f"{prefix}/{name}": ((directory / name).read_bytes(), 0o644)
        for name in NOTICE_FILES
        if (directory / name).is_file()
    }
    require(bool(entries), f"no license or notices found for {prefix}")
    return entries


def make_archive(path, members):
    if path.suffix == ".zip":
        with zipfile.ZipFile(path, "w") as archive:
            for name, (data, mode) in sorted(members.items()):
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (0o100000 | mode) << 16
                archive.writestr(info, data)
        with zipfile.ZipFile(path) as archive:
            found = {
                info.filename: (archive.read(info), (info.external_attr >> 16) & 0o777)
                for info in archive.infolist()
            }
            require(len(archive.infolist()) == len(members), "unexpected ZIP members")
    else:
        with (
            path.open("wb") as dest,
            gzip.GzipFile(filename="", fileobj=dest, mtime=0) as gz,
            tarfile.open(mode="w", fileobj=gz, format=tarfile.USTAR_FORMAT) as archive,
        ):
            for name, (data, mode) in sorted(members.items()):
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.mtime = len(data), mode, 0
                archive.addfile(info, io.BytesIO(data))
        with tarfile.open(path, "r:gz") as archive:
            found = {}
            for info in archive:
                require(
                    info.isreg() and info.name not in found, "unexpected tar member"
                )
                with archive.extractfile(info) as member:
                    found[info.name] = member.read(), info.mode
    require(found == members, f"{path.name}: archived bytes or mode differ")


def purl(module, version):
    return f"pkg:golang/{quote(module, safe='/')}@{quote(version, safe='')}"


def package(
    foundation,
    destination,
    commit,
    version,
    toolchain,
    archive_sha,
    repo,
    goroot,
    modcache,
):
    sums = {
        tuple(line.split())
        for line in (repo / "go.sum").read_text(encoding="utf-8").splitlines()
    }
    builds = read_builds(foundation, commit, toolchain)
    destination.mkdir()
    subjects = []
    binaries = []
    for target in TARGETS:
        tag = target.replace("/", "_")
        windows = target.startswith("windows/")
        executable = "vintar.exe" if windows else "vintar"
        directory = foundation / target.replace("/", "-")
        binary = (directory / executable).read_bytes()
        require(
            digest(binary) == builds[target],
            f"{target}: binary checksum differs from gate",
        )
        deps = read_metadata(
            directory / f"{executable}.buildinfo",
            executable,
            toolchain,
            target,
            commit,
            sums,
        )
        members = {
            executable: (binary, 0o755),
            "LICENSE": ((repo / "LICENSE").read_bytes(), 0o644),
            "README.md": (
                (repo / "docs/migration/v0.7.0-go-distribution.md").read_bytes(),
                0o644,
            ),
        }
        members.update(notices(goroot, "licenses/go"))
        for module, dependency_version, _ in deps:
            members.update(
                notices(
                    modcache / f"{module}@{dependency_version}", f"licenses/{module}"
                )
            )
        name = f"vintar_{version}_{tag}"
        asset = destination / (name + (".zip" if windows else ".tar.gz"))
        make_archive(asset, members)
        sbom = destination / f"{name}.cdx.json"
        root = purl(MODULE, version)
        components = [
            {
                "type": "library",
                "name": module,
                "version": v,
                "bom-ref": purl(module, v),
                "purl": purl(module, v),
                "properties": [{"name": "go:module:h1", "value": checksum}],
            }
            for module, v, checksum in deps
        ]
        components.append(
            {
                "type": "library",
                "name": "Go standard library",
                "version": toolchain,
                "bom-ref": purl("stdlib", toolchain),
                "purl": purl("stdlib", toolchain),
            }
        )
        write_json(
            sbom,
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "version": 1,
                "metadata": {
                    "component": {
                        "type": "application",
                        "name": "vintar",
                        "version": version,
                        "bom-ref": root,
                        "purl": root,
                        "hashes": [{"alg": "SHA-256", "content": builds[target]}],
                    },
                    "properties": [
                        {"name": "vintar:target", "value": target},
                        {"name": "vintar:sourceRevision", "value": commit},
                    ],
                },
                "components": components,
                "dependencies": [
                    {"ref": root, "dependsOn": [item["bom-ref"] for item in components]}
                ],
            },
        )
        for file in (asset, sbom):
            subjects.append(
                {"name": file.name, "digest": {"sha256": digest(file.read_bytes())}}
            )
        binaries.append(
            {
                "target": target,
                "name": executable,
                "sha256": builds[target],
                "archive": asset.name,
                "independentRebuild": "match",
            }
        )
    write_json(
        destination / "provenance.json",
        {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": subjects,
            "predicateType": f"{SOURCE}/go-release-rehearsal/v1",
            "predicate": {
                "source": {"uri": SOURCE, "gitCommit": commit},
                "version": version,
                "toolchain": {
                    "version": toolchain,
                    "archive": f"{toolchain}.linux-amd64.tar.gz",
                    "sha256": archive_sha,
                },
                "build": {
                    "host": "linux/amd64",
                    "CGO_ENABLED": "0",
                    "trimpath": True,
                    "vcsModified": False,
                    "recipe": "scripts/check_go_foundation.sh",
                },
                "binaries": binaries,
                "attestation": "unsigned rehearsal record",
            },
        },
    )
    checksums = [
        f"{digest(file.read_bytes())}  {file.name}\n"
        for file in sorted(destination.iterdir())
    ]
    (destination / "SHA256SUMS").write_text("".join(checksums), encoding="utf-8")
    print(
        f"Verified {len(builds)} archives, linked dependency SBOMs and provenance for {commit}"
    )


if __name__ == "__main__":
    (
        foundation,
        destination,
        commit,
        version,
        toolchain,
        archive_sha,
        repo,
        goroot,
        modcache,
    ) = sys.argv[1:]
    package(
        Path(foundation),
        Path(destination),
        commit,
        version,
        toolchain,
        archive_sha,
        Path(repo),
        Path(goroot),
        Path(modcache),
    )
