package cli

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	const secret = "private-input-527"
	const url = "https://" + secret + "@example.invalid/?q=" + secret
	tests := []struct {
		name   string
		args   []string
		code   int
		stdout string
		stderr string
	}{
		{"version", []string{"version"}, 0, "Vintar v0.7.0\n", ""},
		{"root help implied", nil, 2, "Commands:", ""},
		{"root help explicit", []string{"--help"}, 0, "--show-completion", ""},
		{"group help implied", []string{"sqli"}, 2, "verify", ""},
		{"group requires command", []string{"http"}, 2, "", "Missing command"},
		{"group help explicit", []string{"http", "--help"}, 0, "send", ""},
		{"leaf help explicit", []string{"http", "send", "--help"}, 0, "METHOD URL", ""},
		{"required options in help", []string{"materialize-post-json-case", "--help"}, 0, "--config TEXT (required)", ""},
		{"unknown command", []string{secret}, 2, "", "Unknown command"},
		{"unknown option", []string{"http", "send", "--" + secret + "=value"}, 2, "", "Unknown option"},
		{"extra operand", []string{"version", secret}, 2, "", "Unexpected positional"},
		{"missing positional", []string{"http", "send", "GET"}, 2, "", "Missing argument URL"},
		{"missing value", []string{"verify", "--cases"}, 2, "", "--cases requires a value"},
		{"missing required flag", []string{"verify", "--authorized"}, 2, "", "--cases"},
		{"boolean rejects value", []string{"verify", "--cases=test.toml", "--authorized=false"}, 2, "", "does not take a value"},
		{"verify requires authorization", []string{"verify", "--cases", secret}, 2, "", "explicit testing authorization"},
		{"verify upper boundaries", []string{"verify", "--cases", secret, "--authorized", "--max-requests=768", "--max-response-size=1048576", "--time-deadline=120", "--rps=10", "--timeout=60"}, 2, "", "not available"},
		{"verify small count", []string{"verify", "--cases", secret, "--authorized", "--max-requests=0"}, 2, "", "--max-requests"},
		{"verify fraction as count", []string{"verify", "--cases", secret, "--authorized", "--max-requests=1.0"}, 2, "", "--max-requests"},
		{"verify large deadline", []string{"verify", "--cases", secret, "--authorized", "--time-deadline=120.01"}, 2, "", "--time-deadline"},
		{"sqli requires authorization", []string{"sqli", "verify", "--url", url, "--allow-origin", secret, "--inject-param", secret, "--true-payload", secret, "--false-payload", secret}, 2, "", "explicit authorization"},
		{"sqli accepts public flags", []string{"sqli", "verify", "--url", url, "--allow-origin=https://example.invalid", "--inject-param", "id", "--true-payload", "fixture-a", "--false-payload", "fixture-b", "--authorized", "--append", "--pretty", "--param", "id=1", "--param=id=2", "--occurrence=0"}, 2, "", "not available"},
		{"discover requires output mode", []string{"discover", "--spec", secret}, 2, "", "exactly one"},
		{"discover rejects both modes", []string{"discover", "--spec", secret, "--output=inventory.json", "--drafts-dir=drafts"}, 2, "", "exactly one"},
		{"discover drafts require selection", []string{"discover", "--spec", secret, "--drafts-dir=drafts"}, 2, "", "requires --selection"},
		{"discover draft flags", []string{"discover", "--spec", secret, "--drafts-dir=drafts", "--selection=selected.toml"}, 2, "", "not available"},
		{"discover inventory flags", []string{"discover", "--spec", secret, "--output=inventory.json"}, 2, "", "not available"},
		{"discover optional inventory selection", []string{"discover", "--spec", secret, "--selection=selected.toml", "--output=inventory.json"}, 2, "", "not available"},
		{"completion show", []string{"--show-completion"}, 2, "", "not available"},
		{"completion install", []string{"--install-completion"}, 2, "", "not available"},
		{"HTTP unsupported method", []string{"http", "send", secret, url}, 1, "Only GET and POST", ""},
		{"HTTP malformed header", []string{"http", "send", "GET", url, "-H" + secret}, 1, "Invalid header", ""},
		{"HTTP empty header name", []string{"http", "send", "GET", url, "--header= : " + secret}, 1, "Header name cannot be empty", ""},
		{"HTTP malformed cookie", []string{"http", "send", "GET", url, "-C", secret}, 1, "Invalid cookies", ""},
		{"HTTP empty cookie name", []string{"http", "send", "GET", url, "-C", " =" + secret}, 1, "Cookie name cannot be empty", ""},
		{"HTTP malformed parameter", []string{"http", "send", "GET", url, "-p", secret}, 1, "Invalid parameter", ""},
		{"HTTP empty parameter name", []string{"http", "send", "GET", url, "-p", "=" + secret}, 1, "Parameter name cannot be empty", ""},
		{"HTTP terminator", []string{"http", "send", "-t.1", "--", "post", "-literal"}, 2, "", "not available"},
		{"HTTP terminator prevents flag parsing", []string{"http", "send", "GET", url, "--", "--help"}, 2, "", "Unexpected positional"},
		{"HTTP scalar last wins", []string{"http", "send", "get", "-t", secret, url, "--timeout=60"}, 2, "", "not available"},
		{"HTTP range checked before method", []string{"http", "send", secret, url, "--timeout=60", "-t60.01"}, 2, "", "--timeout"},
		{"HTTP non-finite value", []string{"http", "send", "GET", url, "--timeout=NaN"}, 2, "", "--timeout"},
		{"HTTP hexadecimal value", []string{"http", "send", "GET", url, "--timeout=0x1p+1"}, 2, "", "--timeout"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), tt.args, &stdout, &stderr)
			if strings.Contains(stdout.String(), secret) || strings.Contains(stderr.String(), secret) {
				t.Fatal("CLI disclosed an argument secret")
			}
			if code != tt.code {
				t.Errorf("exit = %d, want %d", code, tt.code)
			}
			checkStream(t, "stdout", stdout.String(), tt.stdout)
			checkStream(t, "stderr", stderr.String(), tt.stderr)
			if tt.name == "version" && stdout.String() != tt.stdout {
				t.Error("version must be one exact line")
			}
		})
	}
}

func checkStream(t *testing.T, name, got, want string) {
	t.Helper()
	if (want == "" && got != "") || !strings.Contains(got, want) {
		t.Errorf("%s = %q, want empty or containing %q as specified", name, got, want)
	}
}

func TestParseHTTPRepeats(t *testing.T) {
	http := rootCommand.child("http").child("send")
	args, err := http.parse([]string{
		"POST", "https://example.invalid/",
		"-H", " X-Demo : first ", "--header=X-Demo: last:part ",
		"-Cdemo=old", "--cookie", " demo= new=value ",
		"-p", "tag=one", "--param=tag=", "-ptag=three=four",
		"--body=first", "--body", "--verbatim",
	})
	if err != nil {
		t.Fatal(err)
	}
	if args.value("body") != "--verbatim" {
		t.Error("last body value should be consumed even when it starts with a dash")
	}
	if args.value("timeout") != "10.0" {
		t.Error("missing timeout default")
	}
	fields, err := parseHTTPFields(args)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fields.headers, map[string]string{"X-Demo": "last:part"}) ||
		!reflect.DeepEqual(fields.cookies, map[string]string{"demo": " new=value "}) ||
		!reflect.DeepEqual(fields.params, []pair{{"tag", "one"}, {"tag", ""}, {"tag", "three=four"}}) {
		t.Error("incorrect HTTP field splitting, trimming or repetition")
	}
}

func TestCancelledRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	if code := Run(ctx, []string{"version"}, &stdout, &stderr); code != 130 {
		t.Errorf("exit = %d, want 130", code)
	}
	checkStream(t, "stdout", stdout.String(), "")
	checkStream(t, "stderr", stderr.String(), "interrupted")
}
