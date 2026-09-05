package provider

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/ktb-soft/secrets-injector/internal/backend"
	"github.com/ktb-soft/secrets-injector/internal/protocol"
)

// Run dispatches a parsed invocation. down and stop are no-ops, and metadata is
// left unimplemented so Compose passes every option through unfiltered.
func Run(ctx context.Context, emitter *protocol.Emitter, inv Invocation) error {
	switch inv.Action {
	case "up":
		return runUp(ctx, emitter, inv)
	case "down", "stop", "metadata":
		return nil
	default:
		return fmt.Errorf("unsupported compose action %q", inv.Action)
	}
}

func runUp(ctx context.Context, emitter *protocol.Emitter, inv Invocation) error {
	mapping, err := inv.SecretMapping()
	if err != nil {
		return err
	}

	name, err := inv.BackendName()
	if err != nil {
		return err
	}

	client, err := backend.New(name, inv.Options)
	if err != nil {
		return err
	}
	if err := validateLocators(client, mapping); err != nil {
		return err
	}

	if err := inv.applyCredentialsFile(); err != nil {
		return err
	}

	values, err := fetch(ctx, emitter, client, name, mapping)
	if err != nil {
		return err
	}
	if len(values) == 0 {
		emitter.Info("no secrets declared")
		return nil
	}

	names := slices.Sorted(maps.Keys(values))
	for _, envName := range names {
		if !envNamePattern.MatchString(envName) {
			return fmt.Errorf("backend %s returned %q, which is not a valid environment variable name", name, envName)
		}
	}
	for _, envName := range names {
		emitter.RawSetEnv(envName, values[envName])
	}

	emitter.Info("injected %d secrets from %s", len(names), name)
	return nil
}

// fetch resolves an explicit secret_mapping, or falls back to enumerating the
// backend when the compose file declares none.
func fetch(
	ctx context.Context,
	emitter *protocol.Emitter,
	client backend.Backend,
	name string,
	mapping map[string]string,
) (map[string]string, error) {
	if len(mapping) == 0 {
		lister, ok := client.(backend.Lister)
		if !ok {
			return nil, fmt.Errorf("backend %s requires secret_mapping", name)
		}
		emitter.Debug("listing every secret from %s", name)
		return lister.List(ctx)
	}

	requested := slices.Sorted(maps.Keys(mapping))
	emitter.Debug("resolving %s from %s", strings.Join(requested, ", "), name)

	values, err := client.Resolve(ctx, mapping)
	if err != nil {
		return nil, err
	}
	for _, envName := range requested {
		if _, ok := values[envName]; !ok {
			return nil, fmt.Errorf("backend %s returned no value for %s", name, envName)
		}
	}
	return values, nil
}

// validateLocators reports every malformed locator at once, before any
// credential is read or any network call is made.
func validateLocators(client backend.Backend, mapping map[string]string) error {
	var problems []string
	for _, name := range slices.Sorted(maps.Keys(mapping)) {
		if err := client.ValidateLocator(mapping[name]); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", name, err))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("invalid secret_mapping: %s", strings.Join(problems, "; "))
	}
	return nil
}
