// Package infisical resolves Infisical secrets, either by explicit mapping or
// by pulling every key under a folder.
package infisical

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	infisical "github.com/infisical/go-sdk"

	"github.com/ktb-soft/secrets-injector/internal/backend"
)

const (
	backendName   = "infisical"
	locatorScheme = "infisical://"

	// TokenEnvVar holds a pre-issued access token and wins over universal auth,
	// matching the Infisical CLI.
	TokenEnvVar = "INFISICAL_TOKEN"

	defaultSecretPath = "/"
)

func init() {
	backend.Register(backendName, New)
}

type options struct {
	projectID   string
	projectSlug string
	environment string
	secretPath  string
	recursive   bool
	domain      string
}

type resolver struct {
	options options
}

// New reads the Infisical options. Construction stays offline so locator
// validation runs before any login.
func New(raw map[string][]string) (backend.Backend, error) {
	opts := options{secretPath: defaultSecretPath}

	for _, field := range []struct {
		key    string
		target *string
	}{
		{"project_id", &opts.projectID},
		{"project_slug", &opts.projectSlug},
		{"env", &opts.environment},
		{"path", &opts.secretPath},
		{"domain", &opts.domain},
	} {
		value, err := scalar(raw, field.key)
		if err != nil {
			return nil, err
		}
		if value != "" {
			*field.target = value
		}
	}

	recursive, err := scalar(raw, "recursive")
	if err != nil {
		return nil, err
	}
	if recursive != "" {
		if opts.recursive, err = strconv.ParseBool(recursive); err != nil {
			return nil, fmt.Errorf("option recursive expects a boolean, got %q", recursive)
		}
	}

	switch {
	case opts.environment == "":
		return nil, fmt.Errorf("option env is required by the %s backend", backendName)
	case opts.projectID == "" && opts.projectSlug == "":
		return nil, fmt.Errorf("the %s backend requires project_id or project_slug", backendName)
	case opts.projectID != "" && opts.projectSlug != "":
		return nil, fmt.Errorf("options project_id and project_slug are mutually exclusive")
	}
	return resolver{options: opts}, nil
}

func scalar(raw map[string][]string, key string) (string, error) {
	values := raw[key]
	switch len(values) {
	case 0:
		return "", nil
	case 1:
		return values[0], nil
	default:
		return "", fmt.Errorf("option %s given %d times, want one", key, len(values))
	}
}

// ValidateLocator checks an infisical://[folder/]KEY reference. A locator
// without a folder reads from the path option.
func (r resolver) ValidateLocator(locator string) error {
	if !strings.HasPrefix(locator, locatorScheme) {
		return fmt.Errorf("want an %s reference, got %q", locatorScheme, locator)
	}
	_, key := splitLocator(locator, r.options.secretPath)
	if key == "" {
		return fmt.Errorf("%q names no secret key", locator)
	}
	return nil
}

// splitLocator returns the folder a locator reads from and the secret key
// within it. Everything after the last separator is the key.
func splitLocator(locator, defaultPath string) (path, key string) {
	trimmed := strings.TrimPrefix(locator, locatorScheme)
	index := strings.LastIndex(trimmed, "/")
	if index < 0 {
		return defaultPath, trimmed
	}
	folder := trimmed[:index]
	if !strings.HasPrefix(folder, "/") {
		folder = "/" + folder
	}
	return folder, trimmed[index+1:]
}

// Resolve reads every folder the locators name once, then picks out the
// requested keys.
func (r resolver) Resolve(ctx context.Context, locators map[string]string) (map[string]string, error) {
	client, err := r.client(ctx)
	if err != nil {
		return nil, err
	}

	byPath := make(map[string]map[string]string)
	for name, locator := range locators {
		path, key := splitLocator(locator, r.options.secretPath)
		if byPath[path] == nil {
			byPath[path] = make(map[string]string)
		}
		byPath[path][name] = key
	}

	values := make(map[string]string, len(locators))
	for path, wanted := range byPath {
		secrets, err := r.list(client, path)
		if err != nil {
			return nil, err
		}
		for name, key := range wanted {
			value, ok := secrets[key]
			if !ok {
				return nil, fmt.Errorf("%s: no secret %q in %s%s", name, key, r.options.environment, path)
			}
			values[name] = value
		}
	}
	return values, nil
}

// List pulls every secret under the configured path, keyed by its Infisical
// name. It implements backend.Lister.
func (r resolver) List(ctx context.Context) (map[string]string, error) {
	client, err := r.client(ctx)
	if err != nil {
		return nil, err
	}
	return r.list(client, r.options.secretPath)
}

func (r resolver) list(client infisical.InfisicalClientInterface, path string) (map[string]string, error) {
	result, err := client.Secrets().ListSecrets(infisical.ListSecretsOptions{
		ProjectID:              r.options.projectID,
		ProjectSlug:            r.options.projectSlug,
		Environment:            r.options.environment,
		SecretPath:             path,
		Recursive:              r.options.recursive,
		IncludeImports:         true,
		ExpandSecretReferences: true,
	})
	if err != nil {
		return nil, fmt.Errorf("listing secrets from %s%s: %w", r.options.environment, path, err)
	}

	secrets := make(map[string]string, len(result.Secrets))
	for _, secret := range result.Secrets {
		secrets[secret.SecretKey] = secret.SecretValue
	}
	return secrets, nil
}

// client builds an authenticated Infisical client. SDK logging is pinned to
// stderr because stdout carries the Compose protocol.
func (r resolver) client(ctx context.Context) (infisical.InfisicalClientInterface, error) {
	config := infisical.Config{SilentMode: true, LogWriter: os.Stderr}
	if r.options.domain != "" {
		config.SiteUrl = r.options.domain
	}

	client := infisical.NewInfisicalClient(ctx, config)

	if token := os.Getenv(TokenEnvVar); token != "" {
		client.Auth().SetAccessToken(token)
		return client, nil
	}

	// Empty arguments make the SDK read INFISICAL_UNIVERSAL_AUTH_CLIENT_ID and
	// INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET from the environment, so no
	// credential ever appears in a compose file.
	if _, err := client.Auth().UniversalAuthLogin("", ""); err != nil {
		return nil, fmt.Errorf("infisical universal auth login failed: %w", err)
	}
	return client, nil
}
