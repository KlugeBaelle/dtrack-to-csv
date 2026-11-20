// Package config loads connection settings from the environment and an optional env file.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/joho/godotenv"
)

const (
	// URLVariable names the variable holding the Dependency-Track base URL.
	URLVariable = "DTRACK_URL"
	// APIKeyVariable names the variable holding the Dependency-Track API key.
	APIKeyVariable = "DTRACK_API_KEY"
)

// Config holds the settings needed to reach Dependency-Track.
type Config struct {
	URL    string
	APIKey string
}

// Load reads settings from the process environment first and falls back to the
// env file. A missing env file is only an error when envFileRequired is set.
// A non-empty urlOverride wins over both.
func Load(envFilePath string, envFileRequired bool, urlOverride string) (Config, error) {
	fileValues, err := readEnvFile(envFilePath, envFileRequired)
	if err != nil {
		return Config{}, err
	}

	url := urlOverride
	if url == "" {
		url = lookup(URLVariable, fileValues)
	}
	if url == "" {
		return Config{}, fmt.Errorf("no Dependency-Track URL: set %s or use --url", URLVariable)
	}

	apiKey := lookup(APIKeyVariable, fileValues)
	if apiKey == "" {
		return Config{}, fmt.Errorf("no API key: set %s in the environment or in %s", APIKeyVariable, envFilePath)
	}
	return Config{URL: url, APIKey: apiKey}, nil
}

func readEnvFile(path string, required bool) (map[string]string, error) {
	values, err := godotenv.Read(path)
	if errors.Is(err, fs.ErrNotExist) && !required {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read env file %s: %w", path, err)
	}
	return values, nil
}

func lookup(name string, fileValues map[string]string) string {
	value := os.Getenv(name)
	if value != "" {
		return value
	}
	return fileValues[name]
}
