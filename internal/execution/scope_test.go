package execution

import (
	"net/url"
	"testing"
)

func mustParseScopeOrigin(t *testing.T, raw string) Origin {
	t.Helper()
	got, err := ParseTrustedOrigin(raw)
	if err != nil {
		t.Fatalf("ParseTrustedOrigin(%q): %v", raw, err)
	}
	return got
}

func TestParseTrustedOriginIdentity(t *testing.T) {
	tests := []struct {
		raw  string
		want Origin
	}{
		{"HTTPS://EXAMPLE.Test:00443/", Origin{"https", "example.test", 443}},
		{"Http://LocalHost", Origin{"http", "localhost", 80}},
		{"http://example.test.:65535", Origin{"http", "example.test.", 65535}},
		{"http://127.0.0.1:1/", Origin{"http", "127.0.0.1", 1}},
		{"https://[2001:0DB8:0:0:0:0:0:1]", Origin{"https", "2001:0db8:0:0:0:0:0:1", 443}},
		{"http://[::FFFF:192.0.2.1]:8080", Origin{"http", "::ffff:192.0.2.1", 8080}},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			if got := mustParseScopeOrigin(t, tt.raw); got != tt.want {
				t.Errorf("origin = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseTrustedOriginRejectsUnsupportedInput(t *testing.T) {
	for _, raw := range []string{
		"", "example.test", "//example.test", "ftp://example.test", "http:/example.test",
		" http://example.test", "http://example.test\n", "http://exa mple.test",
		"http://", "http:///", "http://:80", "http://a.test//", "http://a.test/path",
		"http://a.test?", "http://a.test/#", "http://a.test/%2f", "http://a.test\\/",
		"http://user@a.test", "http://user:secret@a.test", "http://a.test%2e",
		"http://a,b.test", "http://a_b.test", "http://a..test", "http://-a.test",
		"http://a-.test", "http://bücher.test", "http://XN--BCHER-KVA.test",
		"http://a.test:", "http://a.test:+80", "http://a.test:-80", "http://a.test:８０",
		"http://a.test:0", "http://a.test:65536", "http://a.test:80:80",
		"http://[::1", "http://[::1]]", "http://[::1]junk", "http://[::1]:",
		"http://[]", "http://[127.0.0.1]", "http://[v1.addr]", "http://::1",
		"http://[fe80::1%eth0]", "http://[fe80::1%25eth0]", "http://[::gg]",
		"http://127.1", "http://0177.0.0.1", "http://2130706433", "http://0x7f000001",
		"http://256.0.0.1",
	} {
		t.Run(raw, func(t *testing.T) {
			if got, err := ParseTrustedOrigin(raw); err == nil || got != (Origin{}) {
				t.Errorf("ParseTrustedOrigin(%q) = %+v, %v; want zero origin and error", raw, got, err)
			}
		})
	}
}

func TestRebindApprovedPathPreservesLiteralBytes(t *testing.T) {
	tests := []struct {
		target  string
		allowed string
		path    string
		want    string
	}{
		{"https://Example.Test:443/", "https://example.test", "/", "https://example.test/"},
		{"http://example.test:0080", "HTTP://EXAMPLE.TEST/", "/a//b", "http://example.test/a//b"},
		{"https://example.test:8443", "https://example.test:8443/", "/a%2fb/%7E%20%3F%23",
			"https://example.test:8443/a%2fb/%7E%20%3F%23"},
		{"http://[2001:0DB8::1]:8080", "http://[2001:0db8::1]:8080", "/docs/v1.0;view",
			"http://[2001:0db8::1]:8080/docs/v1.0;view"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			target := mustParseScopeOrigin(t, tt.target)
			allowed := []Origin{{}, mustParseScopeOrigin(t, tt.allowed)}
			got, err := RebindApprovedPath(target, allowed, tt.path)
			if err != nil || got != tt.want {
				t.Fatalf("RebindApprovedPath() = %q, %v; want %q", got, err, tt.want)
			}
			parsed, err := url.Parse(got)
			if err != nil || parsed.RequestURI() != tt.path {
				t.Errorf("Go URL parse of %q did not preserve path %q: %v", got, tt.path, err)
			}
		})
	}
}

func TestRebindApprovedPathRequiresExactAllowedOrigin(t *testing.T) {
	allow := mustParseScopeOrigin(t, "https://example.test:443")
	for _, raw := range []string{
		"http://example.test:443", "https://other.test:443", "https://example.test:80",
		"https://sub.example.test", "https://example.test.",
	} {
		t.Run(raw, func(t *testing.T) {
			target := mustParseScopeOrigin(t, raw)
			if got, err := RebindApprovedPath(target, []Origin{allow}, "/"); err == nil || got != "" {
				t.Errorf("unlisted target = %q, %v; want no URL and an error", got, err)
			}
		})
	}

	lexicalV6 := mustParseScopeOrigin(t, "https://[2001:db8::1]")
	expandedV6 := mustParseScopeOrigin(t, "https://[2001:db8:0:0:0:0:0:1]")
	bad := Origin{scheme: "https", host: "example.test"}
	for _, tt := range []struct {
		target  Origin
		allowed []Origin
	}{
		{allow, nil},
		{allow, []Origin{{}}},
		{Origin{}, []Origin{{}, allow}},
		{bad, []Origin{bad}},
		{lexicalV6, []Origin{expandedV6}},
	} {
		if got, err := RebindApprovedPath(tt.target, tt.allowed, "/"); err == nil || got != "" {
			t.Errorf("invalid or unlisted target %+v = %q, %v; want no URL and an error", tt.target, got, err)
		}
	}
}

func TestRebindApprovedPathRejectsInvalidOrAuthorityLikePath(t *testing.T) {
	target := mustParseScopeOrigin(t, "https://example.test")
	for _, path := range []string{
		"", "docs", "https://example.test/docs", "https://other.test/docs",
		"//example.test/docs", "//other.test/docs", "/%2Fother.test/docs",
		"/docs?", "/docs#section", "/%", "/%2", "/%xz",
		"/.", "/./docs", "/docs/..", "/docs/%2e", "/docs/.%2E/x", "/a%2f..%2fb",
		"/a b", "/café", "/{x}", "/a\\b", "/a%5Cb", "/a\tb", "/a%00b", "/a%7fb",
	} {
		t.Run(path, func(t *testing.T) {
			if got, err := RebindApprovedPath(target, []Origin{target}, path); err == nil || got != "" {
				t.Errorf("RebindApprovedPath(%q) = %q, %v; want no URL and an error", path, got, err)
			}
		})
	}
}

func FuzzTrustedOriginRebind(f *testing.F) {
	f.Add("https://example.test:443", "/a%2Fb/%7Euser")
	f.Add("http://[::1]:8080", "/")
	f.Add("http://user@localhost", "/")
	f.Fuzz(func(t *testing.T, raw, path string) {
		target, err := ParseTrustedOrigin(raw)
		if err != nil {
			return
		}
		if _, err := RebindApprovedPath(target, nil, path); err == nil {
			t.Fatal("rebind accepted without a trusted origin")
		}
		output, err := RebindApprovedPath(target, []Origin{target}, path)
		if err != nil {
			return
		}
		u, err := url.Parse(output)
		if err != nil || u.RequestURI() != path || u.User != nil {
			t.Fatal("rebound URL changed the approved path or added credentials")
		}
		if got, err := ParseTrustedOrigin(u.Scheme + "://" + u.Host); err != nil || got != target {
			t.Fatal("rebound URL changed origin")
		}
	})
}
