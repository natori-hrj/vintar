package completionhost

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

// DetectShell prefers the running shell to the configured login shell.
func DetectShell(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	lookup := processLookup(ctx)
	if shell := ancestorShell(ctx, lookup(os.Getpid()).parent, lookup); shell != "" {
		return shell
	}
	return shellName(os.Getenv("SHELL"))
}

type process struct {
	name   string
	parent int
}

func ancestorShell(ctx context.Context, pid int, lookup func(int) process) string {
	for depth := 0; pid > 1 && depth < 10 && ctx.Err() == nil; depth++ {
		proc := lookup(pid)
		if shell := shellName(proc.name); shell != "" {
			return shell
		}
		pid = proc.parent
	}
	return ""
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
