package cli

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
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
		{"verify zero fraction as count", []string{"verify", "--cases", secret, "--max-requests=1.00"}, 2, "", "explicit testing authorization"},
		{"verify nonzero fraction as count", []string{"verify", "--cases", secret, "--max-requests=1.01"}, 2, "", "--max-requests"},
		{"verify explicit error wins over absent option", []string{"verify", "--timeout=bad", "--max-requests=0"}, 2, "", "--timeout"},
		{"verify large deadline", []string{"verify", "--cases", secret, "--authorized", "--time-deadline=120.01"}, 2, "", "--time-deadline"},
		{"sqli requires authorization", []string{"sqli", "verify", "--url", url, "--allow-origin", secret, "--inject-param", secret, "--true-payload", secret, "--false-payload", secret}, 2, "", "explicit authorization"},
		{"sqli accepts public flags", []string{"sqli", "verify", "--url", url, "--allow-origin=https://example.invalid", "--inject-param", "id", "--true-payload", "fixture-a", "--false-payload", "fixture-b", "--authorized", "--append", "--pretty", "--param", "id=1", "--param=id=2", "--occurrence=0"}, 2, "", "not available"},
		{"discover requires output mode", []string{"discover", "--spec", secret}, 2, "", "exactly one"},
		{"discover rejects both modes", []string{"discover", "--spec", secret, "--output=inventory.json", "--drafts-dir=drafts"}, 2, "", "exactly one"},
		{"discover drafts require selection", []string{"discover", "--spec", secret, "--drafts-dir=drafts"}, 2, "", "requires --selection"},
		{"discover draft flags", []string{"discover", "--spec", secret, "--drafts-dir=drafts", "--selection=selected.toml"}, 2, "", "invalid OpenAPI spec"},
		{"discover inventory flags", []string{"discover", "--spec", secret, "--output=inventory.json"}, 2, "", "invalid OpenAPI spec"},
		{"discover optional inventory selection", []string{"discover", "--spec", secret, "--selection=selected.toml", "--output=inventory.json"}, 2, "", "invalid OpenAPI spec"},
		{"HTTP unsupported method", []string{"http", "send", secret, url}, 1, "Only GET and POST", ""},
		{"HTTP malformed header", []string{"http", "send", "GET", url, "-H" + secret}, 1, "Invalid header", ""},
		{"HTTP empty header name", []string{"http", "send", "GET", url, "--header= : " + secret}, 1, "Header name cannot be empty", ""},
		{"HTTP header name with Python whitespace", []string{"http", "send", "GET", url, "--header=\x1c:" + secret}, 1, "Header name cannot be empty", ""},
		{"HTTP malformed cookie", []string{"http", "send", "GET", url, "-C", secret}, 1, "Invalid cookies", ""},
		{"HTTP empty cookie name", []string{"http", "send", "GET", url, "-C", " =" + secret}, 1, "Cookie name cannot be empty", ""},
		{"HTTP cookie name with Python whitespace", []string{"http", "send", "GET", url, "-C", "\x1f=" + secret}, 1, "Cookie name cannot be empty", ""},
		{"HTTP malformed parameter", []string{"http", "send", "GET", url, "-p", secret}, 1, "Invalid parameter", ""},
		{"HTTP empty parameter name", []string{"http", "send", "GET", url, "-p", "=" + secret}, 1, "Parameter name cannot be empty", ""},
		{"HTTP terminator", []string{"http", "send", "-t.1", "--", "post", "-literal"}, 1, "HTTP request failed.", ""},
		{"HTTP terminator prevents flag parsing", []string{"http", "send", "GET", url, "--", "--help"}, 2, "", "Unexpected positional"},
		{"HTTP scalar last wins", []string{"http", "send", "get", "-t", secret, "https://[invalid/" + secret, "--timeout=60"}, 1, "HTTP request failed.", ""},
		{"HTTP range checked before method", []string{"http", "send", secret, url, "--timeout=60", "-t60.01"}, 2, "", "--timeout"},
		{"HTTP fullwidth timeout rejected", []string{"http", "send", "PATCH", "unused", "--timeout=１"}, 2, "", "--timeout"},
		{"HTTP Unicode decimal and exponent rejected", []string{"http", "send", "PATCH", "unused", "--timeout=١.٥e𝟙"}, 2, "", "--timeout"},
		{"verify Unicode integer limit rejected", []string{"verify", "--cases", "unused", "--max-requests=７６８"}, 2, "", "--max-requests"},
		{"HTTP non-finite value", []string{"http", "send", "GET", url, "--timeout=NaN"}, 2, "", "--timeout"},
		{"HTTP hexadecimal value", []string{"http", "send", "GET", url, "--timeout=0x1p+1"}, 2, "", "--timeout"},
		{"HTTP exponent separators", []string{"http", "send", "PATCH", "unused", "-t1_._0e+_1"}, 1, "Only GET and POST", ""},
		{"HTTP separators with whitespace rejected", []string{"http", "send", "PATCH", "unused", "--timeout= 1_0 "}, 2, "", "--timeout"},
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

func TestRunHTTPSendLocal(t *testing.T) {
	type observed struct{ method, host, target, body, cookie string }
	received := make(chan observed, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error("read local fixture request")
		}
		received <- observed{r.Method, r.Host, r.RequestURI, string(body), r.Header.Get("Cookie")}
		w.Header().Set("Location", "/should-not-follow")
		w.WriteHeader(http.StatusFound)
		io.WriteString(w, "ok")
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	exit := Run(t.Context(), []string{"http", "send", "POST", server.URL, "-H", ":"}, &stdout, &stderr)
	if exit != 1 || len(received) != 0 || stderr.Len() != 0 {
		t.Fatalf("malformed input: exit = %d, requests = %d, stderr = %q", exit, len(received), stderr.String())
	}
	stdout.Reset()
	exit = Run(t.Context(), []string{
		"http", "send", "poſt", server.URL + "/a%2Fb/path-marker?old=query-marker#fragment-marker",
		"-H", "Host: fixture.invalid",
		"-p", "q=a b+", "-p", "q=", "-C", "first=one", "-C", "second=two",
		"-C", "first=last", "--body", "sample", "-t0_._5",
	}, &stdout, &stderr)
	if exit != 0 || stderr.Len() != 0 {
		t.Fatalf("exit = %d, stderr = %q", exit, stderr.String())
	}
	if len(received) != 1 {
		t.Fatalf("wanted exactly one request, observed %d", len(received))
	}
	if got := <-received; got != (observed{"POST", "fixture.invalid", "/a%2Fb/path-marker?q=a%20b%2B&q=", "sample", "first=last; second=two"}) {
		t.Fatalf("unexpected local request: %+v", got)
	}
	if !strings.HasPrefix(stdout.String(), "Target: "+server.URL+"\nMethod: POST\nStatus: 302\n") ||
		!strings.Contains(stdout.String(), "Content size: 2 bytes\n") {
		t.Fatalf("unexpected or unsanitized output: %q", stdout.String())
	}
}

func TestRunHTTPSendRejectsUnsupportedDestinations(t *testing.T) {
	for _, target := range []string{
		"http://127.0.0.1:0/path-marker", "http://127.0.0.1:-0/path-marker", "http://127.0.0.1:+0/path-marker",
		"http://[::1%lo]:8080/path-marker", "http://[::1%7]:8080/path-marker", "http://[::1%25lo]:8080/path-marker",
		"http://fixture-user:credential-marker@127.0.0.1:8080/path-marker",
	} {
		var stdout, stderr bytes.Buffer
		code := Run(t.Context(), []string{"http", "send", "GET", target}, &stdout, &stderr)
		if code != 1 || stdout.String() != "HTTP request failed.\n" || stderr.Len() != 0 {
			t.Errorf("target %q: exit = %d, stdout = %q, stderr = %q", target, code, stdout.String(), stderr.String())
		}
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
		"-H", " X-Demo : first ", "--header=X-Demo:\x1d last:part \x1e",
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
