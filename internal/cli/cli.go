// Package cli owns the command line, diagnostics and process exit status.
package cli

import (
	"context"
	"fmt"
	"io"
	"regexp"
)

const version = "Vintar v0.7.0"

// Exact spellings whose Python 3.13 str.upper() result is GET or POST.
// The POST suffix includes long s and both ligatures that uppercase to ST.
var httpSendMethod = regexp.MustCompile(`\A(?:[Gg][Ee][Tt]|[Pp][Oo](?:[Ss\x{017F}][Tt]|[\x{FB05}\x{FB06}]))\z`)

// Run invokes the CLI. Diagnostics never include raw arguments or lower-level
// errors, since both may contain sensitive values.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	cmd, path := &rootCommand, rootCommand.name
	for {
		if ctx.Err() != nil {
			return diagnostic(stderr, 130, "interrupted")
		}

		parsed, err := cmd.parse(args)
		if ctx.Err() != nil {
			return diagnostic(stderr, 130, "interrupted")
		}
		if err != nil {
			return diagnostic(stderr, 2, err.Error())
		}
		switch parsed.eager {
		case "help":
			return writeText(stdout, stderr, cmd.help(path), 0)
		case "show-completion", "install-completion":
			return diagnostic(stderr, 2, "shell completion is not available")
		}

		if len(cmd.children) == 0 {
			return runCommand(path, parsed, stdout, stderr)
		}
		if len(parsed.remaining) == 0 {
			if len(args) == 0 && cmd.helpOnEmpty {
				return writeText(stdout, stderr, cmd.help(path), 2)
			}
			return diagnostic(stderr, 2, "Missing command")
		}
		child := cmd.child(parsed.remaining[0])
		if child == nil {
			return diagnostic(stderr, 2, "Unknown command")
		}
		cmd, path, args = child, path+" "+child.name, parsed.remaining[1:]
	}
}

func runCommand(path string, args arguments, stdout, stderr io.Writer) int {
	switch path {
	case "vintar version":
		return writeText(stdout, stderr, version+"\n", 0)
	case "vintar verify":
		if !args.has("authorized") {
			return diagnostic(stderr, 2, "explicit testing authorization is required.")
		}
	case "vintar sqli verify":
		if !args.has("authorized") {
			return diagnostic(stderr, 2, "explicit authorization is required.")
		}
	case "vintar discover":
		output, drafts := args.has("output"), args.has("drafts-dir")
		switch {
		case output == drafts:
			return diagnostic(stderr, 2, "Choose exactly one of --output or --drafts-dir.")
		case drafts && !args.has("selection"):
			return diagnostic(stderr, 2, "Draft export requires --selection. Supply a reviewed selection file.")
		}
	case "vintar http send":
		if !httpSendMethod.MatchString(args.positionals[0]) {
			return writeText(stdout, stderr, "Only GET and POST are supported.\n", 1)
		}
		if _, err := parseHTTPFields(args); err != nil {
			return writeText(stdout, stderr, err.Error()+"\n", 1)
		}
	}
	return diagnostic(stderr, 2, path+" is not available")
}

func diagnostic(w io.Writer, code int, message string) int {
	fmt.Fprintln(w, "Error:", message)
	return code
}

func writeText(stdout, stderr io.Writer, text string, code int) int {
	if n, err := io.WriteString(stdout, text); err != nil || n != len(text) {
		return diagnostic(stderr, 2, "could not write stdout")
	}
	return code
}
