package loader

import (
	"fmt"
	"os"
)

type EnvironmentVariableLoader struct {
	key string
}

func NewEnvironmentVariableLoader(key string) *EnvironmentVariableLoader {
	return &EnvironmentVariableLoader{
		key: key,
	}
}

func (loader *EnvironmentVariableLoader) Load() (string, error) {
	value, exists := os.LookupEnv(loader.key)
	if !exists {
		return "", fmt.Errorf("environment variable [ %s ] not found", loader.key)
	}

	return value, nil
}
