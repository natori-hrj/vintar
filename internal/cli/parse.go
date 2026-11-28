package cli

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type optionKind uint8

const (
	boolean optionKind = iota
	text
	integer
	decimal
)

type option struct {
	name, short, description string
	kind                     optionKind
	required, repeat, eager  bool
	defaultValue, min, max   string
}

type arguments struct {
	positionals []string
	options     map[string][]string
	remaining   []string // unparsed child command and its arguments
	eager       string
}

func (a arguments) has(name string) bool {
	_, ok := a.options[name]
	return ok
}

func (a arguments) value(name string) string {
	if values := a.options[name]; len(values) != 0 {
		return values[len(values)-1]
	}
	return ""
}

func (c *command) parse(args []string) (arguments, error) {
	parsed := arguments{options: make(map[string][]string)}
	group := len(c.children) != 0
	endOptions := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case !endOptions && arg == "--":
			endOptions = true
		case !endOptions && arg != "-" && strings.HasPrefix(arg, "-"):
			opt, value, attached := c.matchOption(arg)
			if opt == nil {
				return arguments{}, errors.New("Unknown option")
			}
			if opt.kind == boolean {
				if attached {
					return arguments{}, fmt.Errorf("--%s does not take a value", opt.name)
				}
				if opt.eager && parsed.eager == "" {
					parsed.eager = opt.name
				}
			} else if !attached {
				i++
				if i == len(args) {
					return arguments{}, fmt.Errorf("--%s requires a value", opt.name)
				}
				value = args[i]
			}
			if opt.repeat {
				parsed.options[opt.name] = append(parsed.options[opt.name], value)
			} else {
				parsed.options[opt.name] = []string{value}
			}
		case group:
			parsed.remaining = args[i:]
			return parsed, nil
		default:
			parsed.positionals = append(parsed.positionals, arg)
		}
	}
	if group || parsed.eager != "" {
		return parsed, nil
	}
	return c.validate(parsed)
}

func (c *command) matchOption(arg string) (*option, string, bool) {
	if long, ok := strings.CutPrefix(arg, "--"); ok {
		name, value, attached := strings.Cut(long, "=")
		if name == helpOption.name {
			return &helpOption, value, attached
		}
		for i := range c.options {
			if c.options[i].name == name {
				return &c.options[i], value, attached
			}
		}
	} else {
		short, value := arg[:2], arg[2:]
		for i := range c.options {
			if c.options[i].short == short {
				return &c.options[i], value, value != ""
			}
		}
	}
	return nil, "", false
}

func (c *command) validate(parsed arguments) (arguments, error) {
	for _, opt := range c.options {
		if !parsed.has(opt.name) {
			switch {
			case opt.required:
				return arguments{}, fmt.Errorf("Missing required option --%s", opt.name)
			case opt.defaultValue != "":
				parsed.options[opt.name] = []string{opt.defaultValue}
			}
			continue
		}
		// Click validates the effective scalar, not each overwritten value.
		if !opt.valid(parsed.value(opt.name)) {
			return arguments{}, fmt.Errorf("--%s must be %s", opt.name, opt.bounds())
		}
	}
	switch {
	case len(parsed.positionals) < len(c.positionals):
		return arguments{}, fmt.Errorf("Missing argument %s", c.positionals[len(parsed.positionals)])
	case len(parsed.positionals) > len(c.positionals):
		return arguments{}, errors.New("Unexpected positional argument")
	}
	return parsed, nil
}

var (
	intSyntax     = regexp.MustCompile(`^[+-]?[0-9](_?[0-9])*$`)
	decimalSyntax = regexp.MustCompile(`^[+-]?([0-9](_?[0-9])*(\.([0-9](_?[0-9])*)?)?|\.[0-9](_?[0-9])*)([eE][+-]?[0-9](_?[0-9])*)?$`)
)

func (o option) valid(value string) bool {
	switch o.kind {
	case integer:
		value = strings.TrimSpace(value)
		if !intSyntax.MatchString(value) {
			return false
		}
		value = strings.ReplaceAll(value, "_", "")
		if o.max == "" {
			// --occurrence has no upper bound. Avoid imposing a machine
			// integer limit while checking that it is not negative.
			magnitude, negative := strings.CutPrefix(value, "-")
			return !negative || strings.TrimLeft(magnitude, "0") == ""
		}
		n, err := strconv.ParseInt(value, 10, 64)
		minimum, _ := strconv.ParseInt(o.min, 10, 64)
		maximum, _ := strconv.ParseInt(o.max, 10, 64)
		return err == nil && minimum <= n && n <= maximum
	case decimal:
		value = strings.TrimSpace(value)
		if !decimalSyntax.MatchString(value) {
			return false
		}
		n, err := strconv.ParseFloat(value, 64)
		minimum, _ := strconv.ParseFloat(o.min, 64)
		maximum, _ := strconv.ParseFloat(o.max, 64)
		return err == nil && minimum <= n && n <= maximum
	default:
		return true
	}
}

func (o option) bounds() string {
	kind := "a number"
	if o.kind == integer {
		kind = "an integer"
	}
	if o.max == "" {
		return kind + " >= " + o.min
	}
	return kind + " in [" + o.min + ", " + o.max + "]"
}
