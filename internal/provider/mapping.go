package provider

import (
	"fmt"
	"regexp"
	"strings"
)

const secretMappingOption = "secret_mapping"

var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ParseSecretMapping turns the repeated secret_mapping option values into a map
// of environment variable name to backend locator. Each entry is NAME=locator.
// The locator may itself contain "=", so only the first one separates the two.
func ParseSecretMapping(entries []string) (map[string]string, error) {
	mapping := make(map[string]string, len(entries))

	for _, entry := range entries {
		name, locator, found := strings.Cut(entry, "=")
		if !found {
			return nil, fmt.Errorf("secret_mapping %q must use the NAME=locator form", entry)
		}
		if !envNamePattern.MatchString(name) {
			return nil, fmt.Errorf("secret_mapping %q has an invalid variable name %q", entry, name)
		}
		if locator == "" {
			return nil, fmt.Errorf("secret_mapping %q has an empty locator", entry)
		}
		if existing, ok := mapping[name]; ok {
			return nil, fmt.Errorf("secret_mapping declares %s twice: %q and %q", name, existing, locator)
		}
		mapping[name] = locator
	}

	return mapping, nil
}
