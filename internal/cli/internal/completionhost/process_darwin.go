package completionhost

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"unicode"
)

func processLookup(ctx context.Context) func(int) process {
	return func(pid int) process {
		// Use the operating system's ps, not a program from PATH.
		cmd := exec.CommandContext(ctx, "/bin/ps", "-ww", "-p", strconv.Itoa(pid), "-o", "ppid=", "-o", "comm=")
		raw, err := probeOutput(cmd)
		if err != nil {
			return process{}
		}
		line := strings.TrimSpace(string(raw))
		index := strings.IndexFunc(line, unicode.IsSpace)
		if index < 0 {
			return process{}
		}
		parent, _ := strconv.Atoi(line[:index])
		return process{strings.TrimSpace(line[index:]), parent}
	}
}
