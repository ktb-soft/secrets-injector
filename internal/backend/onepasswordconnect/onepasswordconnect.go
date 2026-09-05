// Package onepasswordconnect resolves op:// references through a self-hosted
// 1Password Connect server.
package onepasswordconnect

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/1Password/connect-sdk-go/connect"
	"github.com/1Password/connect-sdk-go/onepassword"
	"github.com/opentracing/opentracing-go"

	"github.com/ktb-soft/secrets-injector/internal/backend"
	"github.com/ktb-soft/secrets-injector/internal/backend/opref"
)

const backendName = "onepassword-connect"

// HostEnvVar and TokenEnvVar name the Connect server and the access token. They
// match the variables the Connect SDK reads on its own.
const (
	HostEnvVar  = "OP_CONNECT_HOST"
	TokenEnvVar = "OP_CONNECT_TOKEN"
)

func init() {
	backend.Register(backendName, New)
}

type resolver struct{}

// New returns a Connect backend. Construction stays offline so locator
// validation runs before the server is contacted.
func New(_ map[string][]string) (backend.Backend, error) {
	return resolver{}, nil
}

// ValidateLocator accepts the same op:// syntax as the service account backend,
// so a compose file works unchanged against either.
func (resolver) ValidateLocator(locator string) error {
	return opref.Validate(locator)
}

// Resolve reads each referenced item once and picks the requested field out of
// it. The Connect SDK takes no context, so ctx bounds only the work done here.
func (resolver) Resolve(ctx context.Context, locators map[string]string) (map[string]string, error) {
	client, err := newClient()
	if err != nil {
		return nil, err
	}

	items := make(map[string]*onepassword.Item)
	values := make(map[string]string, len(locators))

	for name, locator := range locators {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		reference, err := opref.Parse(locator)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}

		cacheKey := reference.Vault + "/" + reference.Item
		item, cached := items[cacheKey]
		if !cached {
			if item, err = client.GetItem(reference.Item, reference.Vault); err != nil {
				return nil, fmt.Errorf("%s: reading %s: %w", name, cacheKey, err)
			}
			items[cacheKey] = item
		}

		value, found := fieldValue(item, reference)
		if !found {
			return nil, fmt.Errorf("%s: no field %q in %s", name, fieldPath(reference), cacheKey)
		}
		values[name] = value
	}
	return values, nil
}

// fieldValue matches on field label first and falls back to field ID, because a
// locator's last segment is a label to whoever wrote the compose file.
func fieldValue(item *onepassword.Item, reference opref.Reference) (string, bool) {
	for _, matchesName := range []func(*onepassword.ItemField) bool{
		func(f *onepassword.ItemField) bool { return strings.EqualFold(f.Label, reference.Field) },
		func(f *onepassword.ItemField) bool { return f.ID == reference.Field },
	} {
		for _, field := range item.Fields {
			if field == nil || !inSection(field, reference.Section) {
				continue
			}
			if matchesName(field) {
				return field.Value, true
			}
		}
	}
	return "", false
}

// inSection reports whether a field belongs to the named section. An empty
// section matches any field, so a three segment reference stays unrestricted.
func inSection(field *onepassword.ItemField, section string) bool {
	if section == "" {
		return true
	}
	if field.Section == nil {
		return false
	}
	return strings.EqualFold(field.Section.Label, section) || field.Section.ID == section
}

func fieldPath(reference opref.Reference) string {
	if reference.Section == "" {
		return reference.Field
	}
	return reference.Section + "/" + reference.Field
}

// newClient builds a Connect client from the environment.
//
// A no-op tracer is registered first: the Connect SDK installs a global Jaeger
// tracer when none exists, and an uninvited library writing to a stream is
// exactly what corrupts the NDJSON protocol on stdout.
func newClient() (connect.Client, error) {
	host := os.Getenv(HostEnvVar)
	token := os.Getenv(TokenEnvVar)
	switch {
	case host == "":
		return nil, fmt.Errorf("%s is not set; point it at the Connect server", HostEnvVar)
	case token == "":
		return nil, fmt.Errorf("%s is not set; export it or name it in credentials_file", TokenEnvVar)
	}

	if !opentracing.IsGlobalTracerRegistered() {
		opentracing.SetGlobalTracer(opentracing.NoopTracer{})
	}
	return connect.NewClient(host, token), nil
}
