package completionhost

import (
	"context"
	"testing"
)

func TestAncestorShell(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"/usr/local/bin/bash", "bash"},
		{"pwsh.EXE", "pwsh"},
		{"cmd.exe", "cmd"},
	} {
		table := map[int]process{5: {"launcher", 4}, 4: {tc.name, 3}, 3: {"zsh", 1}}
		if got := ancestorShell(t.Context(), 5, func(pid int) process { return table[pid] }); got != tc.want {
			t.Errorf("closest shell to %q = %q, want %q", tc.name, got, tc.want)
		}
	}
	if got := ancestorShell(t.Context(), 1, func(int) process { return process{name: "bash"} }); got != "bash" {
		t.Fatalf("PID 1 shell detection = %q, want bash", got)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got := ancestorShell(ctx, 5, func(int) process {
		t.Fatal("looked up a parent after cancellation")
		return process{}
	}); got != "" {
		t.Fatalf("cancelled detection returned %q", got)
	}
}

func TestProbeOutputLimit(t *testing.T) {
	var b probeBuffer
	if n, err := b.Write(make([]byte, maxOutput)); n != maxOutput || err != nil {
		t.Fatalf("exact output limit: %d, %v", n, err)
	}
	if n, err := b.Write([]byte{1}); n != 0 || err == nil {
		t.Fatalf("above output limit: %d, %v", n, err)
	}
}
