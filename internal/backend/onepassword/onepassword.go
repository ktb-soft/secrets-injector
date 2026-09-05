// Package onepassword resolves op:// references using a 1Password service
// account.
package onepassword

import (
	"context"
	"fmt"
	"os"
	"strings"

	opsdk "github.com/1password/onepassword-sdk-go"
	"github.com/ktb-soft/secrets-injector/internal/backend"
)

const (
	backendName = "onepassword"

	// TokenEnvVar holds the service account token. It is read from the process
	// environment so the token never appears in a compose file.
	TokenEnvVar = "OP_SERVICE_ACCOUNT_TOKEN"

	locatorScheme      = "op://"
	integrationName    = "secrets-injector"
	integrationVersion = "0.1.0"
)

func init() {
	backend.Register(backendName, New)
}

type resolver struct{}

// New returns a 1Password backend. Construction is deliberately cheap: the SDK
// client is built in Resolve, after every locator has been validated.
func New(_ map[string][]string) (backend.Backend, error) {
	return resolver{}, nil
}

// ValidateLocator checks an op://vault/item[/section]/field reference.
func (resolver) ValidateLocator(locator string) error {
	if !strings.HasPrefix(locator, locatorScheme) {
		return fmt.Errorf("want an %s reference, got %q", locatorScheme, locator)
	}

	path, _, _ := strings.Cut(strings.TrimPrefix(locator, locatorScheme), "?")
	segments := strings.Split(path, "/")
	if len(segments) < 3 || len(segments) > 4 {
		return fmt.Errorf("want %svault/item[/section]/field, got %q", locatorScheme, locator)
	}
	for _, segment := range segments {
		if segment == "" {
			return fmt.Errorf("%q has an empty path segment", locator)
		}
	}
	return nil
}

// Resolve fetches every reference in one call and maps the values back onto the
// environment variable names they were requested under.
func (resolver) Resolve(ctx context.Context, locators map[string]string) (map[string]string, error) {
	token := os.Getenv(TokenEnvVar)
	if token == "" {
		return nil, fmt.Errorf("%s is not set; export it or point credentials_file at a file defining it", TokenEnvVar)
	}

	client, err := opsdk.NewClient(ctx,
		opsdk.WithServiceAccountToken(token),
		opsdk.WithIntegrationInfo(integrationName, integrationVersion),
	)
	if err != nil {
		return nil, fmt.Errorf("authenticating with 1Password: %w", err)
	}

	response, err := client.Secrets().ResolveAll(ctx, uniqueLocators(locators))
	if err != nil {
		return nil, fmt.Errorf("resolving 1Password references: %w", err)
	}

	values := make(map[string]string, len(locators))
	for name, locator := range locators {
		result, ok := response.IndividualResponses[locator]
		switch {
		case !ok:
			return nil, fmt.Errorf("%s: 1Password returned no result for %s", name, locator)
		case result.Error != nil:
			return nil, fmt.Errorf("%s: 1Password could not resolve %s: %s", name, locator, result.Error.Type)
		case result.Content == nil:
			return nil, fmt.Errorf("%s: 1Password returned an empty result for %s", name, locator)
		}
		values[name] = result.Content.Secret
	}
	return values, nil
}

// uniqueLocators collapses references shared by several variables so each one is
// fetched once.
func uniqueLocators(locators map[string]string) []string {
	seen := make(map[string]bool, len(locators))
	references := make([]string, 0, len(locators))
	for _, locator := range locators {
		if seen[locator] {
			continue
		}
		seen[locator] = true
		references = append(references, locator)
	}
	return references
}
