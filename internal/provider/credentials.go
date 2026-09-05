package provider

import (
	"fmt"
	"os"
	"strings"
)

const credentialsFileOption = "credentials_file"

// applyCredentialsFile loads a dotenv file into the process environment so a
// backend client can pick its token up from there. Variables already present in
// the host environment are left alone: whoever runs Compose wins over the file.
func (i Invocation) applyCredentialsFile() error {
	path, err := i.optionalScalarOption(credentialsFileOption)
	if err != nil || path == "" {
		return err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", credentialsFileOption, err)
	}

	for number, line := range strings.Split(string(data), "\n") {
		name, value, err := parseDotenvLine(line)
		if err != nil {
			return fmt.Errorf("%s %s line %d: %w", credentialsFileOption, path, number+1, err)
		}
		if name == "" {
			continue
		}
		if _, alreadySet := os.LookupEnv(name); alreadySet {
			continue
		}
		if err := os.Setenv(name, value); err != nil {
			return fmt.Errorf("setting %s: %w", name, err)
		}
	}
	return nil
}

// parseDotenvLine returns an empty name for blank and comment lines.
func parseDotenvLine(line string) (name, value string, err error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", nil
	}
	line = strings.TrimPrefix(line, "export ")

	name, value, found := strings.Cut(line, "=")
	if !found {
		return "", "", fmt.Errorf("want NAME=value, got %q", line)
	}

	name = strings.TrimSpace(name)
	if !envNamePattern.MatchString(name) {
		return "", "", fmt.Errorf("invalid variable name %q", name)
	}
	return name, trimQuotes(strings.TrimSpace(value)), nil
}

// trimQuotes removes one matching pair of surrounding quotes.
func trimQuotes(value string) string {
	if len(value) < 2 {
		return value
	}
	quote := value[0]
	if (quote == '"' || quote == '\'') && value[len(value)-1] == quote {
		return value[1 : len(value)-1]
	}
	return value
}
