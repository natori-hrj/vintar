package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

const explicitCompletionShell = "_TYPER_COMPLETE_TEST_DISABLE_SHELL_DETECTION"

// The generated scripts pass shell-tokenized arguments, including the word
// being completed, to the same command definitions as the normal parser.
var completionScripts = map[string]string{
	"bash": `_vintar_complete() {
    local IFS=$'\n'
    local count=$((COMP_CWORD > 0 ? COMP_CWORD - 1 : 0))
    local -a prior=("${COMP_WORDS[@]:1:count}")
    COMPREPLY=($(_VINTAR_COMPLETE=complete_words "${COMP_WORDS[0]}" "${prior[@]}" "${COMP_WORDS[COMP_CWORD]}"))
}
complete -o default -F _vintar_complete vintar
`,
	"zsh": `#compdef vintar
_vintar_complete() {
    local -a choices
    choices=("${(@f)$( _VINTAR_COMPLETE=complete_words "$words[1]" "${(@)words[2,CURRENT-1]}" "$PREFIX" )}")
    if (( $#choices )); then
        compadd -a choices
    else
        _files
    fi
}
if [[ $funcstack[1] == _vintar ]]; then
    _vintar_complete "$@"
else
    compdef _vintar_complete vintar
fi
`,
	"fish": `function __vintar_complete
    set -l words (commandline -opc)
    set -l current (commandline -ct | string collect --allow-empty)
    env _VINTAR_COMPLETE=complete_words $words[1] $words[2..-1] "$current"
end
complete --command vintar --arguments '(__vintar_complete)'
`,
	"powershell": `Register-ArgumentCompleter -Native -CommandName vintar -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    $prior = @($commandAst.CommandElements | Select-Object -Skip 1 | Where-Object {
        $_.Extent.EndOffset -le ($cursorPosition - $wordToComplete.Length)
    } | ForEach-Object { if ($_ -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $_.Value } else { $_.Extent.Text } })
    $previous = $env:_VINTAR_COMPLETE
    try {
        $env:_VINTAR_COMPLETE = 'complete_words'
        & vintar @prior $wordToComplete | Where-Object { $_ } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
    } finally {
        $env:_VINTAR_COMPLETE = $previous
    }
}
`,
}

func completionRoot() *command {
	if os.Getenv(explicitCompletionShell) == "" {
		return &rootCommand
	}
	root := rootCommand
	root.options = slices.Clone(root.options)
	for i := range root.options {
		root.options[i].kind = text
	}
	return &root
}

func shellScript(shell string) (string, bool) {
	if shell == "pwsh" {
		shell = "powershell"
	}
	script, ok := completionScripts[shell]
	return script, ok
}

func runCompletion(ctx context.Context, action, shell string, stdout, stderr io.Writer) int {
	explicit := os.Getenv(explicitCompletionShell) != ""
	if !explicit {
		shell = detectedCompletionShell()
	}
	script, supported := shellScript(shell)
	if !supported {
		switch {
		case explicit:
			return diagnostic(stderr, 2, "Invalid shell for --"+action+". Choose bash, zsh, fish, powershell or pwsh.")
		case action == "show-completion":
			return writeText(stderr, stderr, "Shell "+shell+" not supported.\n", 1)
		default:
			if shell == "" {
				shell = "None"
			}
			return writeText(stdout, stderr, "Shell "+shell+" is not supported.\n", 1)
		}
	}
	if action == "show-completion" {
		return writeText(stdout, stderr, script, 0)
	}
	path, err := installCompletion(ctx, shell, script)
	if ctx.Err() != nil {
		return diagnostic(stderr, 130, "interrupted")
	}
	if err != nil {
		return diagnostic(stderr, 1, "could not install shell completion; check the completion directory and shell configuration")
	}
	return writeText(stdout, stderr, fmt.Sprintf("%s completion installed in %s\nCompletion will take effect once you restart the terminal\n", shell, path), 0)
}

func shellName(name string) string {
	name = strings.TrimPrefix(name, "-")
	name = strings.ToLower(filepath.Base(name))
	name = strings.TrimSuffix(name, ".exe")
	switch name {
	case "bash", "zsh", "fish", "powershell", "pwsh",
		"sh", "ash", "dash", "ksh", "mksh", "csh", "tcsh", "nu", "xonsh", "cmd":
		return name
	default:
		return ""
	}
}

// Inspect the running shell, not just the user's configured login shell.
func detectedCompletionShell() string {
	if runtime.GOOS == "linux" {
		for pid, depth := os.Getppid(), 0; pid > 1 && depth < 10; depth++ {
			dir := "/proc/" + strconv.Itoa(pid)
			if raw, err := os.ReadFile(dir + "/cmdline"); err == nil {
				name, _, _ := strings.Cut(string(raw), "\x00")
				if name := shellName(name); name != "" {
					return name
				}
			}
			raw, err := os.ReadFile(dir + "/stat")
			if err != nil {
				break
			}
			end := strings.LastIndexByte(string(raw), ')')
			if end < 0 {
				break
			}
			fields := strings.Fields(string(raw[end+1:]))
			if len(fields) < 2 {
				break
			}
			pid, _ = strconv.Atoi(fields[1])
		}
	}
	if runtime.GOOS == "darwin" {
		for pid, depth := os.Getppid(), 0; pid > 1 && depth < 10; depth++ {
			raw, err := exec.Command("/bin/ps", "-p", strconv.Itoa(pid), "-o", "ppid=", "-o", "comm=").Output()
			if err != nil {
				break
			}
			parent, name, ok := strings.Cut(strings.TrimSpace(string(raw)), " ")
			if !ok {
				break
			}
			if shell := shellName(strings.TrimSpace(name)); shell != "" {
				return shell
			}
			pid, _ = strconv.Atoi(parent)
		}
	}
	if shell := windowsCompletionShell(); shell != "" {
		return shell
	}
	if shell := shellName(os.Getenv("SHELL")); shell != "" {
		return shell
	}
	return ""
}

func installCompletion(ctx context.Context, shell, script string) (string, error) {
	if shell == "powershell" || shell == "pwsh" {
		// Query only the profile location; never change execution policy or
		// load the existing profile in the subprocess.
		command := exec.CommandContext(ctx, shell, "-NoProfile", "-NonInteractive", "-Command", "$PROFILE")
		result, err := command.Output()
		if err != nil {
			return "", err
		}
		path := strings.TrimSpace(string(result))
		if !filepath.IsAbs(path) || strings.ContainsAny(path, "\r\n\x00") {
			return "", errors.New("invalid PowerShell profile path")
		}
		return path, appendCompletion(path, strings.TrimSpace(script))
	}
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return "", errors.New("invalid home directory")
	}
	var path, rc, init string
	switch shell {
	case "bash":
		path = filepath.Join(home, ".bash_completions", "vintar.sh")
		rc = filepath.Join(home, ".bashrc")
		init = "source '" + strings.ReplaceAll(path, "'", `'\''`) + "'"
	case "zsh":
		path = filepath.Join(home, ".zfunc", "_vintar")
		rc = filepath.Join(home, ".zshrc")
		init = "fpath+=~/.zfunc; autoload -Uz compinit; compinit"
	case "fish":
		path = filepath.Join(home, ".config", "fish", "completions", "vintar.fish")
	}
	if err := installCompletionScript(path, script); err != nil {
		return "", err
	}
	if rc != "" {
		return path, appendCompletion(rc, init)
	}
	return path, nil
}

func installCompletionScript(path, script string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		if info, statErr := os.Stat(path); statErr != nil || !info.Mode().IsRegular() {
			return errors.New("completion script is not a regular file")
		}
		current, readErr := os.ReadFile(path)
		if readErr == nil && strings.TrimSpace(string(current)) == strings.TrimSpace(script) {
			return nil
		}
		return errors.New("completion script already exists")
	}
	if err != nil {
		return err
	}
	_, err = io.WriteString(f, script)
	return errors.Join(err, f.Close())
}

func appendCompletion(path, text string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if info, err := os.Stat(path); err == nil && !info.Mode().IsRegular() {
		return errors.New("shell configuration is not a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	old, err := io.ReadAll(f)
	if err == nil && !strings.Contains("\n"+string(old)+"\n", "\n"+text+"\n") {
		prefix := ""
		if len(old) > 0 && old[len(old)-1] != '\n' {
			prefix = "\n"
		}
		_, err = io.WriteString(f, prefix+text+"\n")
	}
	return errors.Join(err, f.Close())
}

func runCompletionProtocol(mode string, args []string, stdout, stderr io.Writer) int {
	if mode == "complete_words" {
		if len(args) == 0 {
			return 0
		}
		return writeCandidates(stdout, stderr, completionCandidates(args[:len(args)-1], args[len(args)-1]), "")
	}
	action, shell, ok := strings.Cut(mode, "_")
	if !ok {
		return writeText(stderr, stderr, "Invalid completion instruction.\n", 1)
	}
	script, ok := shellScript(shell)
	if !ok {
		return writeText(stderr, stderr, "Shell not supported.\n", 1)
	}
	if action == "source" {
		return writeText(stdout, stderr, script, 0)
	}
	if action != "complete" {
		return writeText(stderr, stderr, "Completion instruction not supported.\n", 1)
	}
	var prefix string
	if shell == "bash" {
		words := splitCompletionLine(os.Getenv("COMP_WORDS"))
		cursor, _ := strconv.Atoi(os.Getenv("COMP_CWORD"))
		cursor = max(1, cursor)
		if cursor < len(words) {
			prefix = words[cursor]
		}
		if len(words) > 0 {
			args = words[1:min(cursor, len(words))]
		}
	} else {
		line := os.Getenv("_TYPER_COMPLETE_ARGS")
		words := splitCompletionLine(line)
		if len(words) > 0 {
			args = words[1:]
		}
		if shell == "powershell" || shell == "pwsh" {
			prefix = os.Getenv("_TYPER_COMPLETE_WORD_TO_COMPLETE")
			if prefix != "" && len(args) > 0 {
				args = args[:len(args)-1]
			}
		} else if len(args) > 0 && !strings.HasSuffix(line, " ") {
			prefix, args = args[len(args)-1], args[:len(args)-1]
		}
	}
	return writeCandidates(stdout, stderr, completionCandidates(args, prefix), shell)
}

func writeCandidates(stdout, stderr io.Writer, candidates []string, shell string) int {
	switch shell {
	case "zsh":
		if len(candidates) == 0 {
			return writeText(stdout, stderr, "_files\n", 0)
		}
		return writeText(stdout, stderr, "_arguments '*: :(("+strings.Join(candidates, " ")+"))'\n", 0)
	case "fish":
		if os.Getenv("_TYPER_COMPLETE_FISH_ACTION") == "is-args" {
			if len(candidates) > 0 {
				return 0
			}
			return 1
		}
	case "powershell", "pwsh":
		for i := range candidates {
			candidates[i] += "::: "
		}
	}
	return writeText(stdout, stderr, strings.Join(candidates, "\n")+"\n", 0)
}

func completionCandidates(args []string, prefix string) []string {
	cmd := completionRoot()
	used := make(map[string]bool)
	endOptions := false
	for i := 0; i < len(args); i++ {
		word := args[i]
		if !endOptions && word == "--" {
			endOptions = true
			continue
		}
		if !endOptions && word != "-" && strings.HasPrefix(word, "-") {
			opt, _, attached := cmd.matchOption(word)
			if opt == nil {
				continue
			}
			if opt.kind != boolean && !attached {
				if i+1 == len(args) {
					if strings.HasPrefix(prefix, "-") {
						break
					}
					return nil
				}
				i++
			}
			used[opt.name] = true
		} else if child := cmd.child(word); child != nil {
			cmd, endOptions = child, false
			clear(used)
		} else if len(cmd.children) > 0 {
			break
		}
	}
	var out []string
	if strings.HasPrefix(prefix, "-") {
		for _, opt := range append(slices.Clone(cmd.options), helpOption) {
			if opt.repeat || !used[opt.name] {
				for _, name := range []string{"--" + opt.name, opt.short} {
					if strings.HasPrefix(name, prefix) {
						out = append(out, name)
					}
				}
			}
		}
		return out
	}
	for _, child := range cmd.children {
		if strings.HasPrefix(child.name, prefix) {
			out = append(out, child.name)
		}
	}
	return out
}

// Compatibility with the released completion environment; generated scripts
// pass real argv instead, avoiding any reconstruction of shell quoting.
func splitCompletionLine(line string) []string {
	var words []string
	var word strings.Builder
	var quote rune
	escaped, started := false, false
	for _, r := range line {
		switch {
		case escaped:
			word.WriteRune(r)
			escaped = false
		case r == '\\' && quote != '\'':
			escaped, started = true, true
		case quote != 0:
			if quote == r {
				quote = 0
			} else {
				word.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote, started = r, true
		case unicode.IsSpace(r):
			if started {
				words = append(words, word.String())
				word.Reset()
				started = false
			}
		default:
			word.WriteRune(r)
			started = true
		}
	}
	if started {
		words = append(words, word.String())
	}
	return words
}
