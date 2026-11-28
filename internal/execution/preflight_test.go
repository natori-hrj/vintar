package execution

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPrepareAllRejectsBeforeLookup(t *testing.T) {
	p := parsePolicyFixture(t, policyFixture)
	good := fixturePolicyRequest(t, "GET")
	bad := fixturePolicyRequest(t, "POST")
	bad.SideEffect = "mutating"
	calls := 0
	lookup := func(string) (string, bool) { calls++; return "synthetic-token", true }
	if out, err := p.PrepareAll(t.Context(), []ApprovalRequest{good, bad}, []Origin{good.Origin}, time.Now(), lookup); err == nil || out != nil || calls != 0 {
		t.Fatal("invalid second operation did not fail preflight before credential lookup")
	}
	if out, err := p.PrepareAll(t.Context(), []ApprovalRequest{good}, nil, time.Now(), lookup); err == nil || out != nil || calls != 0 {
		t.Fatal("case policy alone could authorize preparation")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if out, err := p.PrepareAll(ctx, []ApprovalRequest{good}, []Origin{good.Origin}, time.Now(), lookup); err == nil || out != nil || calls != 0 {
		t.Fatal("canceled preflight resolved a credential")
	}
	out, err := p.PrepareAll(t.Context(), []ApprovalRequest{good}, []Origin{good.Origin}, time.Now(), lookup)
	if err != nil || len(out) != 1 || calls != 1 || out[0].URL != "https://example.invalid/items" ||
		strings.Contains(fmt.Sprintf("%+v %#v", out, out), "synthetic-token") {
		t.Fatal("approved preflight failed or disclosed credential")
	}
	headers := map[string]string{}
	if err := out[0].ApplyCredential(headers); err != nil || headers["Authorization"] != "Bearer synthetic-token" {
		t.Fatal("credential was not available for explicit application")
	}
}

func TestLoadRuntimePolicySource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(policyFixture), 0600); err != nil {
		t.Fatal(err)
	}
	lookup := func(env map[string]string) func(string) (string, bool) {
		return func(key string) (string, bool) { val, ok := env[key]; return val, ok }
	}
	if _, err := LoadRuntimePolicy(lookup(map[string]string{"VINTAR_RUNTIME_POLICY_JSON": policyFixture})); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRuntimePolicy(lookup(map[string]string{
		"VINTAR_RUNTIME_POLICY_JSON": "", "VINTAR_RUNTIME_POLICY_FILE": path,
	})); err == nil {
		t.Fatal("empty inline source fell back to file")
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		if _, err := LoadRuntimePolicy(lookup(map[string]string{"VINTAR_RUNTIME_POLICY_FILE": path})); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "policy-link.json")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadRuntimePolicy(lookup(map[string]string{"VINTAR_RUNTIME_POLICY_FILE": link})); err == nil {
			t.Fatal("policy file followed a final symlink")
		}
	}
}
