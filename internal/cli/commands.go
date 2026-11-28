package cli

import (
	"errors"
	"fmt"
	"strings"
)

type command struct {
	name        string
	summary     string
	helpOnEmpty bool
	positionals []string
	options     []option
	children    []command
}

var (
	helpOption  = option{name: "help", description: "Show this message and exit.", eager: true}
	authorized  = option{name: "authorized", description: "Attest explicit testing authorization; this does not verify permission."}
	pretty      = option{name: "pretty", description: "Indent the JSON report."}
	rps         = option{name: "rps", kind: decimal, defaultValue: "2.0", min: "0.1", max: "10.0", description: "Requests per second."}
	timeout     = option{name: "timeout", kind: decimal, defaultValue: "10.0", min: "0.1", max: "60.0", description: "Request timeout in seconds."}
	httpTimeout = timeout.withAlias("-t")
)

var rootCommand = command{
	name:        "vintar",
	summary:     "Security regression tests for CI pipelines.",
	helpOnEmpty: true,
	options: []option{
		{name: "install-completion", description: "Install completion for the current shell.", eager: true},
		{name: "show-completion", description: "Show completion for the current shell.", eager: true},
	},
	children: []command{
		{
			name:    "version",
			summary: "Show the current version.",
		},
		{
			name:    "http",
			summary: "HTTP inspection commands.",
			children: []command{{
				name:        "send",
				summary:     "Send a GET or POST request and inspect the response.",
				positionals: []string{"METHOD", "URL"},
				options: []option{
					{name: "body", kind: text, description: "Request body."},
					{name: "header", short: "-H", kind: text, repeat: true, description: "Custom HTTP header (Name: Value)."},
					{name: "cookie", short: "-C", kind: text, repeat: true, description: "Cookie (name=value)."},
					{name: "param", short: "-p", kind: text, repeat: true, description: "Query parameter (name=value)."},
					httpTimeout,
				},
			}},
		},
		{
			name:        "sqli",
			summary:     "Authorized SQL injection verification commands.",
			helpOnEmpty: true,
			children: []command{{
				name:    "verify",
				summary: "Verify Boolean SQL injection on an authorized target.",
				options: []option{
					{name: "url", kind: text, required: true, description: "Target URL."},
					{name: "allow-origin", kind: text, required: true, description: "Allowed origin."},
					{name: "inject-param", kind: text, required: true, description: "Query parameter name."},
					{name: "true-payload", kind: text, required: true, description: "True payload."},
					{name: "false-payload", kind: text, required: true, description: "False payload."},
					{name: "param", kind: text, repeat: true, description: "Query parameter (name=value)."},
					authorized,
					{name: "append", description: "Append rather than replace the value."},
					{name: "occurrence", kind: integer, defaultValue: "0", min: "0", description: "Zero-based occurrence."},
					rps,
					timeout,
					pretty,
				},
			}},
		},
		{
			name:    "verify",
			summary: "Run authorized regression cases using trusted runtime target settings.",
			options: []option{
				{name: "cases", kind: text, required: true, description: "TOML file or nonrecursive directory."},
				authorized,
				{name: "max-requests", kind: integer, defaultValue: "48", min: "1", max: "768", description: "Request budget."},
				rps,
				timeout,
				{name: "time-deadline", kind: decimal, defaultValue: "45.0", min: "0.1", max: "120.0", description: "Overall deadline in seconds for each time SQLi case."},
				{name: "max-response-size", kind: integer, defaultValue: "1048576", min: "1", max: "1048576", description: "Response size limit in bytes."},
				pretty,
			},
		},
		{
			name:    "discover",
			summary: "Inventory a local OpenAPI spec for review. Choose exactly one of --output or --drafts-dir.",
			options: []option{
				{name: "spec", kind: text, required: true, description: "Local OpenAPI JSON or YAML file."},
				{name: "output", kind: text, description: "Destination for the JSON inventory."},
				{name: "selection", kind: text, description: "Reviewer-approved input IDs in TOML; required with --drafts-dir."},
				{name: "drafts-dir", kind: text, description: "Directory for offline review drafts."},
			},
		},
		offline("inventory-post-json", "Inventory POST application/json request bodies offline.", "spec", "output"),
		offline("review-draft", "Review a discovery draft offline and export a decision report.", "spec", "draft", "answers", "output"),
		offline("review-post-json", "Record one explicit POST JSON review decision offline.", "spec", "inventory", "answers", "output"),
		offline("materialize-case", "Materialize reviewed discovery decisions into a Schema v1 case.", "spec", "draft", "answers", "review", "config", "output"),
		offline("materialize-post-json-case", "Materialize one explicitly reviewed POST JSON candidate offline.", "spec", "inventory", "answers", "review", "config", "output"),
	},
}

func offline(name, summary string, flags ...string) command {
	cmd := command{name: name, summary: summary}
	for _, flag := range flags {
		cmd.options = append(cmd.options, option{name: flag, kind: text, required: true})
	}
	return cmd
}

func (o option) withAlias(short string) option {
	o.short = short
	return o
}

func (c *command) child(name string) *command {
	for i := range c.children {
		if c.children[i].name == name {
			return &c.children[i]
		}
	}
	return nil
}

func (c *command) help(path string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Usage: %s [OPTIONS]", path)
	for _, name := range c.positionals {
		fmt.Fprint(&b, " ", name)
	}
	if len(c.children) != 0 {
		fmt.Fprint(&b, " COMMAND [ARGS]...")
	}
	fmt.Fprintf(&b, "\n\n%s\n\nOptions:\n", c.summary)
	for _, opt := range c.options {
		fmt.Fprintln(&b, opt.help())
	}
	fmt.Fprintln(&b, helpOption.help())
	if len(c.children) != 0 {
		fmt.Fprintln(&b, "\nCommands:")
		for _, child := range c.children {
			fmt.Fprintf(&b, "  %-27s %s\n", child.name, child.summary)
		}
	}
	return b.String()
}

func (o option) help() string {
	var b strings.Builder
	b.WriteString("  --" + o.name)
	if o.short != "" {
		b.WriteString(", " + o.short)
	}
	switch o.kind {
	case text:
		b.WriteString(" TEXT")
	case integer:
		b.WriteString(" INTEGER")
	case decimal:
		b.WriteString(" FLOAT")
	}
	if o.required {
		b.WriteString(" (required)")
	}
	if o.repeat {
		b.WriteString(" (repeatable)")
	}
	if o.description != "" {
		b.WriteString("  " + o.description)
	}
	if o.defaultValue != "" {
		b.WriteString(" [default: " + o.defaultValue + "; " + o.bounds() + "]")
	}
	return b.String()
}

type pair struct {
	name, value string
}

type httpFields struct {
	headers, cookies map[string]string
	params           []pair
}

// parseHTTPFields only processes the CLI's delimiter and whitespace rules.
// It does not validate a destination or build or send a request.
func parseHTTPFields(args arguments) (httpFields, error) {
	var fields httpFields
	headers, err := splitFields(args.options["header"], ":", "Invalid header.", "Header name cannot be empty.", true, true)
	if err != nil {
		return fields, err
	}
	cookies, err := splitFields(args.options["cookie"], "=", "Invalid cookies.", "Cookie name cannot be empty.", true, false)
	if err != nil {
		return fields, err
	}
	fields.params, err = splitFields(args.options["param"], "=", "Invalid parameter.", "Parameter name cannot be empty.", false, false)
	if err != nil {
		return fields, err
	}
	fields.headers = lastValues(headers)
	fields.cookies = lastValues(cookies)
	return fields, nil
}

func splitFields(items []string, separator, invalid, empty string, trimName, trimValue bool) ([]pair, error) {
	var pairs []pair
	for _, item := range items {
		name, value, ok := strings.Cut(item, separator)
		if !ok {
			return nil, errors.New(invalid)
		}
		if trimName {
			name = strings.TrimSpace(name)
		}
		if name == "" {
			return nil, errors.New(empty)
		}
		if trimValue {
			value = strings.TrimSpace(value)
		}
		pairs = append(pairs, pair{name, value})
	}
	return pairs, nil
}

func lastValues(pairs []pair) map[string]string {
	if len(pairs) == 0 {
		return nil
	}
	values := make(map[string]string, len(pairs))
	for _, p := range pairs {
		values[p.name] = p.value
	}
	return values
}
