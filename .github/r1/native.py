"""Run exact-distribution R1 checks on the observed native host."""

import csv
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile

import native_shell
import native_signal


class Blocked(Exception):
    pass


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def run(args, cwd=None, env=None):
    return subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=85)


def require(result):
    check(result.returncode == 0, f"exit {result.returncode}: {result.stdout[-3000:]} {result.stderr[-1000:]}")
    return result.stdout


def select_tests(root, binary, package, pattern, names):
    env = dict(os.environ, VINTAR_TEST_BINARY=str(binary))
    result = run(["go", "test", "-json", "-count=1", "-timeout=65s", package, "-run", pattern],
                 cwd=root, env=env)
    actions = {}
    for line in result.stdout.splitlines():
        event = json.loads(line)
        if event.get("Test") in names and event["Action"] in ("pass", "fail", "skip"):
            actions[event["Test"]] = event["Action"]
    print(f"R1 native tests {package}: {actions}", flush=True)
    require(result)
    if set(actions) != set(names) or "skip" in actions.values():
        raise Blocked(f"native test missing or skipped: {actions}")
    check(all(state == "pass" for state in actions.values()), str(actions))


def filesystem(root, binary):
    select_tests(root, binary, "./internal/acceptance",
                 "^TestProductBinary$/^(discover-offline|review-draft-offline)$",
                 ["TestProductBinary/discover-offline", "TestProductBinary/review-draft-offline"])
    select_tests(root, binary, "./internal/cli",
                 "^TestOffline(ReviewOutputDirectory|OutputDirectoryDiscardedNameLength)$",
                 ["TestOfflineReviewOutputDirectory", "TestOfflineOutputDirectoryDiscardedNameLength"])
    return "discover/review-draft: golden output, reuse/conflict/hard link; native output directory checks"


def prepare_review(root, binary, work):
    work.mkdir()
    spec = root / "tests/fixtures/discovery/openapi30.json"
    golden = root / "tests/golden/cli/discover/drafts.json"
    drafts = json.loads(golden.read_bytes())["draft_files"]
    name, draft = next((name, draft) for name, draft in drafts.items() if name.startswith("case-24a9c"))
    shutil.copyfile(spec, work / "openapi.json")
    (work / name).write_text(draft, encoding="utf-8")
    (work / "answers.json").write_text(
        '{"version":1,"expected_verdict":"not_detected","parameters":{"q":{"value":"fixture-baseline"}}}',
        encoding="utf-8")
    return [binary, "review-draft", "--spec", "openapi.json", "--draft", name]


def competing_writers(root, binary, work):
    args = prepare_review(root, binary, work)
    first = (work / "answers.json").read_text(encoding="utf-8")
    (work / "other.json").write_text(first.replace("fixture-baseline", "other-baseline"), encoding="utf-8")
    with subprocess.Popen([*args, "--answers", "answers.json", "--output", "review.json"], cwd=work,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) as a, \
         subprocess.Popen([*args, "--answers", "other.json", "--output", "review.json"], cwd=work,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) as b:
        try:
            messages = [process.communicate(timeout=15) for process in (a, b)]
        finally:
            for process in (a, b):
                if process.poll() is None:
                    process.kill()
    codes = [a.returncode, b.returncode]
    check(sorted(codes) == [0, 2], f"expected one winner and one rejection: {codes}, {messages}")
    winner = codes.index(0)
    out, err = messages[winner]
    reject_out, reject_err = messages[1 - winner]
    check(bool(out) and not err and not reject_out and reject_err.startswith(b"Error:"),
          f"unexpected writer diagnostics: {messages}")
    raw = (work / "review.json").read_bytes()
    digest = hashlib.sha256((b'"fixture-baseline"', b'"other-baseline"')[winner]).hexdigest()
    check(json.loads(raw)["parameters"]["q"]["value_sha256"] == digest,
          "published file was incomplete or overwritten by the losing writer")
    return "two native processes, one exit 0, one exit 2, complete winner artifact"


def output_links(root, binary, work, junction=False):
    args = prepare_review(root, binary, work)
    real = work / "real"
    real.mkdir()
    link = work / "linked"
    if junction:
        result = run(["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(real)])
        if result.returncode:
            raise Blocked("junction creation unavailable: " + result.stderr.strip())
        attrs = link.lstat().st_file_attributes
        check(bool(attrs & 0x400) and link.is_dir(), "junction is not a directory reparse point")
    else:
        try:
            link.symlink_to(real, target_is_directory=True)
        except OSError as error:
            if getattr(error, "winerror", None) == 1314 or error.errno in (1, 13, 95):
                raise Blocked("directory symlink creation unavailable") from error
            raise
        check(link.is_symlink(), "fixture did not create a real symbolic link")
    for target in ("linked/escape.json", "linked/../escape.json"):
        result = run([*args, "--answers", "answers.json", "--output", target], cwd=work)
        check(result.returncode == 2 and not result.stdout and result.stderr.startswith("Error:"),
              f"{target}: exit={result.returncode}, stdout={result.stdout!r}, stderr={result.stderr!r}")
        check(not (real / "escape.json").exists() and not (work / "escape.json").exists(),
              "unexpected publication through a linked path")
    return "real link and link/.. refused, no file published"


def policies(root, binary, link):
    name = "TestReadRejectsFinalSymlink" if link else "TestReadBoundedRegularFile"
    select_tests(root, binary, "./internal/execution/internal/policyfile", f"^{name}$", [name])
    return "native reader: final file link rejected" if link else "native reader: bounded regular file only"


def http(root, binary):
    name = "TestProductBinary/http-single-local-request"
    select_tests(root, binary, "./internal/acceptance", "^TestProductBinary$/^http-single-local-request$", [name])
    return "one inert loopback request: Host, raw path/query, no redirect; invalid input has zero requests"


def identity(root, binary, target, candidate, manifest):
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
    system = {"Windows": "windows", "Linux": "linux", "Darwin": "darwin"}
    observed = f"{system.get(platform.system())}/{arch.get(platform.machine().lower())}"
    runner_arch = os.environ.get("RUNNER_ARCH_VALUE", "").lower()
    check(observed == target and (not runner_arch or arch.get(runner_arch) == target.split("/")[1]
                                  or runner_arch == "x64" and target.endswith("/amd64")),
          f"expected {target}, observed {observed} (runner arch {runner_arch})")
    govars = json.loads(require(run(["go", "env", "-json", "GOHOSTOS", "GOHOSTARCH", "GOVERSION"], cwd=root)))
    check(f'{govars["GOHOSTOS"]}/{govars["GOHOSTARCH"]}' == target and govars["GOVERSION"] == "go1.27.4",
          f"wrong host toolchain: {govars}")
    check(require(run(["git", "rev-parse", "HEAD"], cwd=root)).strip() == candidate, "wrong checkout")
    check(not require(run(["git", "status", "--porcelain", "--ignored=matching"], cwd=root)).strip(),
          "source checkout is not clean")
    with manifest.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle, delimiter="\t"))
    matches = [row for row in rows if row.get("target") == target]
    check(len(matches) == 1, "missing expected distribution hash")
    row, = matches
    check((row["commit"], row["go"], row["repeated-build"]) == (candidate, "go1.27.4", "match"),
          "expected distribution row has the wrong inputs")
    require(run(["go", "mod", "download"], cwd=root))
    require(run(["go", "mod", "verify"], cwd=root))
    require(run(["go", "build", "-mod=readonly", "-buildvcs=true", "-trimpath", "-o", binary, "./cmd/vintar"], cwd=root))
    metadata = require(run(["go", "version", "-m", binary], cwd=root))
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    print(f"R1 binary observed_sha256={digest} expected_sha256={row['sha256']}\n{metadata}", flush=True)
    check(digest == row["sha256"], f"binary differs from distribution: {digest} != {row['sha256']}")
    for field in (f"vcs.revision={candidate}", "vcs.modified=false", "CGO_ENABLED=0", "-trimpath=true",
                  f"GOOS={govars['GOHOSTOS']}", f"GOARCH={govars['GOHOSTARCH']}"):
        check(f"\tbuild\t{field}" in metadata.splitlines(), f"missing binary metadata: {field}")
    return f"{platform.platform()}, {observed}; go1.27.4; sha256={digest}"


def cli(binary):
    check(require(run([binary, "version"])).strip() == "Vintar v0.7.0", "unexpected product version")
    help_text = require(run([binary, "--help"]))
    check("review-draft" in help_text and "http" in help_text, "public help missing commands")
    return "native version and public help"


def main():
    root, target, candidate, manifest = sys.argv[1:]
    root, manifest = Path(root).resolve(), Path(manifest).resolve()
    results = {}

    def record(name, status, detail):
        results[name] = status
        print("R1_RESULT " + json.dumps(dict(check=name, status=status, detail=detail), ensure_ascii=True), flush=True)
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as out:
                out.write(f"- **{status}** `{name}`: {detail.replace(chr(10), ' ')[:300]}\n")

    def execute(name, task):
        try:
            record(name, "PASS", task())
        except (Blocked, native_shell.Blocked, native_signal.Blocked) as error:
            record(name, "ENVIRONMENT BLOCKED", str(error))
        except Exception as error:
            record(name, "FAIL", str(error))

    windows = target.startswith("windows/")
    shells = ["powershell", "pwsh"] if windows else ["bash", "zsh", "fish", "pwsh"]
    with tempfile.TemporaryDirectory(prefix="vintar-r1-") as temp:
        work = Path(temp)
        binary = work / ("vintar.exe" if windows else "vintar")
        execute("binary/architecture", lambda: identity(root, binary, target, candidate, manifest))
        checks = {
            "cli": lambda: cli(binary),
            "filesystem/conflicts-and-hard-links": lambda: filesystem(root, binary),
            "filesystem/competing-writers": lambda: competing_writers(root, binary, work / "competing"),
            "filesystem/symbolic-links": lambda: output_links(root, binary, work / "links"),
            "policy/regular-file": lambda: policies(root, binary, False),
            "policy/final-link": lambda: policies(root, binary, True),
            "http/loopback": lambda: http(root, binary),
            "cancellation/http-send": lambda: native_signal.http_send(binary),
            "cancellation/discover": lambda: native_signal.offline(root, binary, "discover"),
            "cancellation/review-draft": lambda: native_signal.offline(root, binary, "review-draft"),
        }
        if windows:
            checks["filesystem/windows-junction"] = lambda: output_links(root, binary, work / "junction", True)
        for shell in shells:
            checks[f"shell/{shell}"] = lambda shell=shell: native_shell.accept(binary, shell)
        for name, task in checks.items():
            if results["binary/architecture"] != "PASS":
                record(name, "NOT RUN", "unverified native distribution binary")
            else:
                execute(name, task)
    return 0 if all(status == "PASS" for status in results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
