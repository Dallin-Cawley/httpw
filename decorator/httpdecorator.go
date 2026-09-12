package decorator

import (
	"io"
	"iter"
	"net/http"
	"os"
	"strings"
)

type HttpDecorator interface {
	Decorate(*http.Client, *http.Request) error
}

// NewEnvironmentVariableReader is a convenience function that returns a reader for an environment variable
func NewEnvironmentVariableReader(key string) io.Reader {
	return strings.NewReader(os.Getenv(key))
}

func parseLines(text []byte) iter.Seq2[string, string] {
	return func(yield func(string, string) bool) {
		for line := range strings.SplitSeq(string(text), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				val = strings.Trim(val, `"'`)
				if !yield(key, val) {
					return
				}
			}
		}
	}
}
