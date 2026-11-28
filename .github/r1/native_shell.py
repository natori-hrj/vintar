"""Exercise the generated completion in actual shell processes."""

from contextlib import contextmanager
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time


class Blocked(Exception):
    pass


def shell_run(cmd, env, cwd=None):
    result = subprocess.run(cmd, env=env, cwd=cwd, capture_output=True,
                            encoding="utf-8", errors="replace", timeout=35)
    if result.returncode:
        if "PSSecurityException" in result.stderr:
            raise Blocked("runner PowerShell policy blocked the disposable profile")
        raise AssertionError(f"shell exit {result.returncode}: {result.stdout[-900:]} {result.stderr[-900:]}")
    return result.stdout.strip()


def zsh_completion(exe, env, home):
    import pty
    import select

    def read_until(fd, marker):
        limit = time.monotonic() + 10
        received = b""
        while time.monotonic() < limit:
            if select.select([fd], [], [], 0.25)[0]:
                received += os.read(fd, 4096)
                if marker in received:
                    return
        raise AssertionError(f"zsh terminal did not emit {marker!r}: {received[-900:]!r}")

    with (home / ".zshrc").open("a", encoding="utf-8") as rc:
        rc.write("\nPROMPT='__R1_READY__> '\n")
    term = dict(env, TERM="xterm")
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(home)
        os.execve(exe, [exe, "-i"], term)
    try:
        read_until(fd, b"__R1_READY__")
        os.write(fd, b"vintar http se\t\n")
        read_until(fd, b"Error: Missing argument METHOD")
        os.write(fd, b"exit\n")
    finally:
        os.close(fd)
        os.waitpid(pid, 0)


@contextmanager
def documents_directory(home):
    if os.name != "nt":
        yield
        return
    # A real Windows PowerShell uses the user's Windows Documents folder,
    # not solely USERPROFILE. Redirect only that value on the disposable runner.
    import winreg

    key_name = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_name, 0, winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as key:
        try:
            original = winreg.QueryValueEx(key, "Personal")
        except FileNotFoundError:
            original = None
        docs = home / "Documents"
        docs.mkdir(exist_ok=True)
        winreg.SetValueEx(key, "Personal", 0, winreg.REG_EXPAND_SZ, str(docs))
        try:
            yield
        finally:
            if original is None:
                winreg.DeleteValue(key, "Personal")
            else:
                value, kind = original
                winreg.SetValueEx(key, "Personal", 0, kind, value)


def powershell(exe, env, home):
    base = [exe, "-NoProfile", "-NonInteractive", "-Command"]
    prefix = "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.Encoding]::UTF8; "

    def call(code):
        return shell_run([*base, prefix + code], env, home)

    if os.name == "nt" and os.environ.get("GITHUB_ACTIONS") != "true":
        raise Blocked("Windows Documents redirection requires a disposable Actions runner")
    with documents_directory(home):
        version = call("[Console]::Write($PSVersionTable.PSVersion.ToString())")
        profile = Path(call("[Console]::Write([string]$PROFILE)")).resolve()
        if not profile.is_relative_to(home):
            raise Blocked(f"PowerShell {version} resolves its profile outside the disposable home")
        profile.parent.mkdir(parents=True, exist_ok=True)
        marker = b"# R1 disposable profile\n"
        profile.write_bytes(marker)
        shown = call("vintar --show-completion; exit $LASTEXITCODE")
        if "Register-ArgumentCompleter -Native" not in shown:
            raise AssertionError("actual shell did not select the PowerShell completion")
        output = call("vintar --install-completion; exit $LASTEXITCODE")
        if str(profile).casefold() not in output.casefold():
            raise AssertionError("install did not report the actual current-host profile")
        installed = profile.read_bytes()
        call("vintar --install-completion; exit $LASTEXITCODE")
        if not installed.startswith(marker) or installed != profile.read_bytes() or installed.count(b"Register-ArgumentCompleter") != 1:
            raise AssertionError("profile prefix or idempotence differs")
        completion = call(". $PROFILE; (TabExpansion2 'vintar http se' 14).CompletionMatches.CompletionText")
        if "send" not in completion.splitlines():
            raise AssertionError(f"native PowerShell completion did not return send: {completion!r}")
    return f"{version}; real shell detection, disposable profile resolution, install/reuse, completion send"


def accept(binary, name):
    exe = shutil.which(name)
    if not exe:
        raise Blocked(f"{name} is not installed on this runner")
    with tempfile.TemporaryDirectory(prefix="vintar-r1-shell-") as temp:
        home = Path(temp).resolve()
        env = dict(os.environ, HOME=str(home), USERPROFILE=str(home), ZDOTDIR=str(home),
                   XDG_CONFIG_HOME=str(home / ".config"),
                   PATH=str(binary.parent) + os.pathsep + os.environ["PATH"])
        for key in ("SHELL", "_VINTAR_COMPLETE", "_TYPER_COMPLETE_TEST_DISABLE_SHELL_DETECTION",
                    "BASH_ENV", "ENV"):
            env.pop(key, None)
        if name in ("powershell", "pwsh"):
            return powershell(exe, env, home)
        version = shell_run([exe, "--version"], env).splitlines()[0]
        launch = {"bash": [exe, "--noprofile", "--norc", "-c"], "zsh": [exe, "-fc"],
                  "fish": [exe, "--no-config", "-c"]}[name]
        script, marker = {
            "bash": (home / ".bash_completions/vintar.sh", "_vintar_complete"),
            "zsh": (home / ".zfunc/_vintar", "#compdef vintar"),
            "fish": (home / ".config/fish/completions/vintar.fish", "complete --command vintar"),
        }[name]

        def call(code):
            return shell_run([*launch, code], env, home)

        shown = call("vintar --show-completion; exit $?" if name != "fish"
                     else "vintar --show-completion; exit $status")
        if marker not in shown or script.exists():
            raise AssertionError("real shell detection selected the wrong script or show wrote a file")
        status = "$status" if name == "fish" else "$?"
        call(f"vintar --install-completion; exit {status}")
        installed = script.read_bytes()
        call(f"vintar --install-completion; exit {status}")
        if installed != script.read_bytes() or installed.decode().strip() != shown:
            raise AssertionError("installed completion differs or was not reusable")
        if name == "zsh":
            zsh_completion(exe, env, home)
        elif name == "fish":
            output = call('source "$XDG_CONFIG_HOME/fish/completions/vintar.fish"; complete -C "vintar http se"')
            if not re.search(r"(?m)^send(?:\t|$)", output):
                raise AssertionError(f"native fish completion did not return send: {output!r}")
        elif call('source "$HOME/.bash_completions/vintar.sh" && complete -p vintar >/dev/null && '
                  'COMP_WORDS=(vintar http se); COMP_CWORD=2; _vintar_complete; printf "%s\\n" "${COMPREPLY[@]}"') != "send":
            raise AssertionError("native Bash completion callback did not return send")
    return f"{version}; detected actual shell, installed and reused completion, observed send"
