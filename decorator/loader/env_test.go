package loader

import (
	"testing"

	"github.com/go-openapi/testify/v2/assert"
)

var _ Loader[string] = (*EnvironmentVariableLoader)(nil)

func TestNewEnvironmentVariableLoader(t *testing.T) {
	loader := NewEnvironmentVariableLoader("TEST_ENV_KEY")
	assert.NotNil(t, loader)
	assert.Equal(t, "TEST_ENV_KEY", loader.key)
}

func TestEnvironmentVariableLoader_Load_Success(t *testing.T) {
	t.Setenv("TEST_KEY", "test_value")

	loader := NewEnvironmentVariableLoader("TEST_KEY")
	val, err := loader.Load()
	assert.NoError(t, err)
	assert.Equal(t, "test_value", val)
}

func TestEnvironmentVariableLoader_Load_NotFound(t *testing.T) {
	loader := NewEnvironmentVariableLoader("NON_EXISTENT_KEY_FOR_TESTING")
	val, err := loader.Load()
	assert.Error(t, err)
	assert.Equal(t, "", val)
	assert.Contains(t, err.Error(), "environment variable [ NON_EXISTENT_KEY_FOR_TESTING ] not found")
}
