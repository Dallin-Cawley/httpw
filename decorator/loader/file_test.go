package loader

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-openapi/testify/v2/assert"
)

var _ Loader[[]byte] = (*FileLoader)(nil)

func TestNewFileLoader(t *testing.T) {
	loader := NewFileLoader("/path/to/file.txt")
	assert.NotNil(t, loader)
	assert.Equal(t, "/path/to/file.txt", loader.path)
}

func TestFileLoader_Load_Success(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "sample.txt")
	expectedContent := []byte("hello file loader")

	err := os.WriteFile(filePath, expectedContent, 0600)
	assert.NoError(t, err)

	loader := NewFileLoader(filePath)
	content, err := loader.Load()
	assert.NoError(t, err)
	assert.Equal(t, expectedContent, content)
}

func TestFileLoader_Load_FileNotFound(t *testing.T) {
	tempDir := t.TempDir()
	nonExistentPath := filepath.Join(tempDir, "does_not_exist.txt")

	loader := NewFileLoader(nonExistentPath)
	content, err := loader.Load()
	assert.Error(t, err)
	assert.Nil(t, content)
	assert.Contains(t, err.Error(), "failed to read file [ "+nonExistentPath+" ]")
}
