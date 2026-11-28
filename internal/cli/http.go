package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/natori-hrj/vintar/internal/casefile"
	"github.com/natori-hrj/vintar/internal/execution"
)

func runHTTPSend(ctx context.Context, args arguments, stdout, stderr io.Writer) int {
	if !httpSendMethod.MatchString(args.positionals[0]) {
		return writeText(stdout, stderr, "Only GET and POST are supported.\n", 1)
	}
	fields, err := parseHTTPFields(args)
	if err != nil {
		return writeText(stdout, stderr, err.Error()+"\n", 1)
	}
	method := "POST"
	if strings.EqualFold(args.positionals[0], "GET") {
		method = "GET"
	}
	request := execution.HTTPRequest{
		Method:  method,
		URL:     args.positionals[1],
		Headers: fields.headers,
		Body:    []byte(args.value("body")),
	}
	if len(fields.cookieNames) != 0 {
		if request.Headers == nil {
			request.Headers = make(map[string]string)
		}
		for name := range request.Headers {
			if strings.EqualFold(name, "Cookie") {
				delete(request.Headers, name)
			}
		}
		cookies := make([]string, 0, len(fields.cookieNames))
		for _, name := range fields.cookieNames {
			cookies = append(cookies, name+"="+fields.cookies[name])
		}
		request.Headers["Cookie"] = strings.Join(cookies, "; ")
	}
	if len(fields.params) != 0 {
		params := make([]casefile.QueryPair, len(fields.params))
		for i, p := range fields.params {
			params[i] = casefile.QueryPair{Name: p.name, Value: p.value}
		}
		query := casefile.EncodeQuery(params)
		request.RawQuery = &query
	}
	seconds := args.decimals["timeout"]
	response, err := execution.SendHTTP(ctx, request, time.Duration(seconds*float64(time.Second)), 1<<20)
	if ctx.Err() != nil {
		return diagnostic(stderr, 130, "interrupted")
	}
	if err != nil {
		return writeText(stdout, stderr, "HTTP request failed.\n", 1)
	}
	text := fmt.Sprintf("Target: %s\nMethod: %s\nStatus: %d\nResponse time: %.3fs\nContent size: %d bytes\n",
		httpTargetLabel(request.URL), method, response.Status, response.Elapsed.Seconds(), len(response.Body))
	return writeText(stdout, stderr, text, 0)
}

func httpTargetLabel(raw string) string {
	// Display the endpoint without userinfo, the query, or the fragment:
	// these can contain credentials and tokens.
	raw, _, _ = strings.Cut(raw, "?")
	raw, _, _ = strings.Cut(raw, "#")
	scheme, rest, _ := strings.Cut(raw, "://")
	authority, path, hasPath := strings.Cut(rest, "/")
	authority = authority[strings.LastIndexByte(authority, '@')+1:]
	label := scheme + "://" + authority
	if hasPath {
		label += "/" + path
	}
	return label
}
