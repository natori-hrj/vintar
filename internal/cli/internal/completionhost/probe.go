// Package completionhost owns the operating-system probes used only by shell
// completion. It does not accept shell programs or arguments from the CLI.
package completionhost

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	probeTimeout = 4 * time.Second
	maxOutput    = 128 << 10 // includes UTF-8 representations of long Windows paths
)

// PowerShellProfile asks the selected PowerShell for its current-user,
// current-host profile. It neither loads that profile nor changes policy.
func PowerShellProfile(ctx context.Context, shell string) (string, error) {
	switch shell {
	case "powershell", "pwsh":
	default:
		return "", errors.New("not a PowerShell executable")
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, shell, "-NoProfile", "-NonInteractive", "-Command",
		`[Console]::OutputEncoding = [Text.Encoding]::UTF8; [Console]::Write([string]$PROFILE)`)
	raw, err := probeOutput(cmd)
	if err != nil {
		return "", err
	}
	path := strings.TrimRight(strings.TrimPrefix(string(raw), "\ufeff"), "\r\n")
	if !utf8.ValidString(path) || strings.ContainsAny(path, "\x00\r\n") || !filepath.IsAbs(path) {
		return "", errors.New("invalid PowerShell profile path")
	}
	return path, nil
}

func probeOutput(cmd *exec.Cmd) ([]byte, error) {
	var output probeBuffer
	cmd.Stdout = &output
	cmd.WaitDelay = 250 * time.Millisecond
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return output.buffer.Bytes(), nil
}

type probeBuffer struct{ buffer bytes.Buffer }

func (b *probeBuffer) Write(p []byte) (int, error) {
	if len(p) > maxOutput-b.buffer.Len() {
		return 0, errors.New("shell probe output exceeded its limit")
	}
	return b.buffer.Write(p)
}
