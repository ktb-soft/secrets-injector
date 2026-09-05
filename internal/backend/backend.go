// Package backend defines the secret retrieval interface and the registry
// that maps a backend option value to an implementation.
package backend

import (
	"context"
	"fmt"
	"slices"
)

// Backend retrieves secret values for backend specific locators.
type Backend interface {
	// ValidateLocator reports whether locator is syntactically valid. It never
	// contacts the backend, so a typo fails before authentication.
	ValidateLocator(locator string) error

	// Resolve returns a value for every locator it is given, keyed by the same
	// environment variable names. Backends never interpret those names.
	Resolve(ctx context.Context, locators map[string]string) (map[string]string, error)
}

// Factory constructs a Backend from the provider options. It must not contact
// the backend or read credentials, so that locator validation can run first.
type Factory func(options map[string][]string) (Backend, error)

var factories = make(map[string]Factory)

// Register makes a backend available under name. Backend packages call it from
// init. A duplicate name can only be a programming error, so it panics.
func Register(name string, factory Factory) {
	if _, exists := factories[name]; exists {
		panic("backend: duplicate registration of " + name)
	}
	factories[name] = factory
}

// New constructs the backend registered under name.
func New(name string, options map[string][]string) (Backend, error) {
	factory, ok := factories[name]
	if !ok {
		return nil, fmt.Errorf("unknown backend %q, want one of %v", name, Names())
	}
	return factory(options)
}

// Names lists the registered backends in sorted order.
func Names() []string {
	names := make([]string, 0, len(factories))
	for name := range factories {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}
