package provider

import "fmt"

// BackendName returns the backend selected by the compose file.
func (i Invocation) BackendName() (string, error) {
	return i.scalarOption(backendOption)
}

// SecretMapping parses the repeated secret_mapping option into environment
// variable name to locator pairs.
func (i Invocation) SecretMapping() (map[string]string, error) {
	return ParseSecretMapping(i.Options[secretMappingOption])
}

// scalarOption returns the single value of a required option that must not be
// repeated. Options arrive as slices because Compose emits one flag per element
// of an array, so a repeated scalar would otherwise be silently resolved by
// last write wins.
func (i Invocation) scalarOption(key string) (string, error) {
	values := i.Options[key]
	switch len(values) {
	case 0:
		return "", fmt.Errorf("option %s is required", key)
	case 1:
		if values[0] == "" {
			return "", fmt.Errorf("option %s is empty", key)
		}
		return values[0], nil
	default:
		return "", fmt.Errorf("option %s given %d times, want one", key, len(values))
	}
}

// optionalScalarOption returns the single value of an option that may be absent.
func (i Invocation) optionalScalarOption(key string) (string, error) {
	if len(i.Options[key]) == 0 {
		return "", nil
	}
	return i.scalarOption(key)
}
