package loader

import (
	"fmt"
	"os"
)

type FileLoader struct {
	path string
}

func NewFileLoader(path string) *FileLoader {
	return &FileLoader{path: path}
}

func (loader *FileLoader) Load() ([]byte, error) {
	content, err := os.ReadFile(loader.path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file [ %s ]: %w", loader.path, err)
	}

	return content, nil
}
