package httpw

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/go-openapi/testify/v2/assert"
)

func TestResponseError_WrapsErr(t *testing.T) {
	inner := NewNotFoundError("x", "/a/x")
	response := &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("missing"))}

	err := NewResponseError(response, inner)
	assert.Equal(t, "[ x ] not found", err.Error())
	assert.Same(t, inner, err.Unwrap())
	assert.True(t, errors.Is(err, &NotFoundError{}))
	assert.Equal(t, http.StatusNotFound, err.StatusCode())
	assert.Equal(t, "missing", string(err.Body()))
}

func TestResponseError_BodyIsCapped(t *testing.T) {
	large := bytes.Repeat([]byte("a"), maxErrorBodyBytes+10)
	response := &http.Response{StatusCode: http.StatusBadGateway, Body: io.NopCloser(bytes.NewReader(large))}

	err := NewResponseError(response, errors.New("bad gateway"))
	assert.Len(t, err.Body(), maxErrorBodyBytes)
}
