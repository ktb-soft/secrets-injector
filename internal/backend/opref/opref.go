// Package opref parses 1Password secret references. Both 1Password backends
// accept the same syntax, so the grammar lives here rather than in either one:
// a compose file must resolve identically whichever backend reads it.
package opref

import (
	"fmt"
	"strings"
)

// Scheme prefixes every 1Password secret reference.
const Scheme = "op://"

// Reference is a parsed op://vault/item[/section]/field locator.
type Reference struct {
	Vault   string
	Item    string
	Section string
	Field   string
}

// Parse splits a secret reference into its parts. A query string is accepted
// and discarded: the service account SDK understands query parameters, and
// dropping them here keeps validation from rejecting a locator it would accept.
func Parse(locator string) (Reference, error) {
	if !strings.HasPrefix(locator, Scheme) {
		return Reference{}, fmt.Errorf("want an %s reference, got %q", Scheme, locator)
	}

	path, _, _ := strings.Cut(strings.TrimPrefix(locator, Scheme), "?")
	segments := strings.Split(path, "/")
	if len(segments) < 3 || len(segments) > 4 {
		return Reference{}, fmt.Errorf("want %svault/item[/section]/field, got %q", Scheme, locator)
	}
	for _, segment := range segments {
		if segment == "" {
			return Reference{}, fmt.Errorf("%q has an empty path segment", locator)
		}
	}

	reference := Reference{Vault: segments[0], Item: segments[1], Field: segments[len(segments)-1]}
	if len(segments) == 4 {
		reference.Section = segments[2]
	}
	return reference, nil
}

// Validate reports whether a locator is well formed.
func Validate(locator string) error {
	_, err := Parse(locator)
	return err
}
