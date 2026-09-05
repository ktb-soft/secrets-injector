// Package provider parses the Compose provider invocation and runs its
// lifecycle verbs.
package provider

import (
	"errors"
	"fmt"
	"strings"
)

const (
	flagProjectName = "project-name"
	backendOption   = "backend"
)

var validComposeCmds = map[string]bool{
	"up":       true,
	"down":     true,
	"stop":     true,
	"metadata": true,
}

// Invocation is a parsed Compose provider command line.
type Invocation struct {
	ProjectName string
	Action      string
	Service     string
	Options     map[string][]string
}

// ParseInvocation parses the arguments Compose passes to a provider, which is
// os.Args[1:] in production. Options are collected as repeated values because
// Compose emits one flag per element of an array option.
func ParseInvocation(args []string) (Invocation, error) {
	if len(args) == 0 || args[0] != "compose" {
		return Invocation{}, errors.New(`expected "compose" as the first argument`)
	}

	inv := Invocation{Options: make(map[string][]string)}
	var positionals []string // extracted commands from compose ("up", "down", ...etc)

	remainingArgs := args[1:]
	// Separate args into options and positionals
	for i := 0; i < len(remainingArgs); i++ {
		arg := remainingArgs[i]

		if arg == "--"+flagProjectName {
			if i+1 >= len(remainingArgs) {
				return Invocation{}, fmt.Errorf("option %q has no value", arg)
			}
			i++
			inv.ProjectName = remainingArgs[i]
			continue
		}

		if !strings.HasPrefix(arg, "--") {
			positionals = append(positionals, arg)
			continue
		}

		key, value, found := strings.Cut(arg[2:], "=")
		if !found {
			return Invocation{}, fmt.Errorf("option %q must use the --key=value form", arg)
		}
		if key == "" {
			return Invocation{}, fmt.Errorf("option %q has an empty name", arg)
		}
		inv.Options[key] = append(inv.Options[key], value)
	}

	if len(positionals) == 0 {
		return Invocation{}, errors.New(`no compose action given | e.g. "up", "down", ...etc`)
	}

	if len(positionals) > 2 {
		return Invocation{}, fmt.Errorf("unexpected arguments: %v", positionals[2:])
	}

	inv.Action = positionals[0]
	if !validComposeCmds[inv.Action] {
		return Invocation{}, fmt.Errorf("unknown compose command: %q", inv.Action)
	}

	if len(positionals) == 2 {
		inv.Service = positionals[1]
	}

	if inv.Action != "metadata" && inv.Service == "" {
		return Invocation{}, fmt.Errorf("compose action %q requires a service name", inv.Action)
	}

	return inv, nil
}
