package decorator

import (
	"testing"

	"github.com/go-openapi/testify/v2/assert"
)

func Test_NewEnvironmentVariableReader(t *testing.T) {
	t.Setenv("TEST_KEY", "test_value")

	reader := NewEnvironmentVariableReader("TEST_KEY")
	assert.NotNil(t, reader)
}

func Test_ParseLines(t *testing.T) {
	t.Run("early exit", func(t *testing.T) {
		count := 0
		for key, val := range parseLines([]byte("key1=val1\nkey2=val2\n")) {
			assert.Equal(t, "key1", key)
			assert.Equal(t, "val1", val)
			count++
			break
		}
		assert.Equal(t, 1, count)
	})

	t.Run("comments, empty lines, and quotes", func(t *testing.T) {
		text := []byte("# Comment\n\nkey1 = 'val1'\nkey2=\"val2\"\ninvalidline\nkey3=val3\n")
		results := make(map[string]string)
		for key, val := range parseLines(text) {
			results[key] = val
		}
		assert.Equal(t, 3, len(results))
		assert.Equal(t, "val1", results["key1"])
		assert.Equal(t, "val2", results["key2"])
		assert.Equal(t, "val3", results["key3"])
	})
}
