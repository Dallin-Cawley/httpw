package httpw

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-openapi/testify/v2/assert"
)

func TestNewJsonRequest_Success(t *testing.T) {
	ctx := context.Background()
	body := map[string]string{"foo": "bar"}
	req, err := NewJsonRequest(ctx, http.MethodPost, "http://example.com", body)
	assert.NoError(t, err)
	assert.NotNil(t, req)
	assert.Equal(t, http.MethodPost, req.Method)
	assert.Equal(t, "http://example.com", req.URL.String())

	var actualBody map[string]string
	err = json.NewDecoder(req.Body).Decode(&actualBody)
	assert.NoError(t, err)
	assert.Equal(t, body, actualBody)
}

func TestNewJsonRequest_MarshalError(t *testing.T) {
	ctx := context.Background()
	req, err := NewJsonRequest(ctx, http.MethodPost, "http://example.com", make(chan int))
	assert.Nil(t, req)
	assert.ErrorContains(t, err, "failed to marshal request body")
}

func TestCloseReader_Success(t *testing.T) {
	ctx := context.Background()
	closer := io.NopCloser(bytes.NewReader(nil))
	CloseReader(ctx, closer, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

type errorCloser struct{}

func (e errorCloser) Read(_ []byte) (n int, err error) { return 0, io.EOF }
func (e errorCloser) Close() error                     { return errors.New("close error") }

func TestCloseReader_Error(t *testing.T) {
	ctx := context.Background()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	err := errors.New("close error")

	CloseReader(ctx, errorCloser{}, logger)
	assert.Contains(t, buf.String(), "Failed to close response body")
	assert.Contains(t, buf.String(), err.Error())
}

func TestDo_Success(t *testing.T) {
	expected := map[string]string{"result": "ok"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(expected)
	}))
	defer server.Close()

	req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	result, err := Do[map[string]string](req, server.Client(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
}

func TestDo_IgnoreBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("raw text"))
	}))
	defer server.Close()

	req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	_, err := Do[IgnoreBody](req, server.Client(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	assert.NoError(t, err)
}

func TestDo_ClientError(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://invalid-url.invalid", nil)

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	_, err := Do[map[string]any](req, http.DefaultClient, logger)
	assert.ErrorContains(t, err, "failed to execute http request")

	output := buf.String()
	assert.Contains(t, output, "failed to execute http request")
	assert.Contains(t, output, "GET")
	assert.Contains(t, output, "http://invalid-url.invalid")
}

func TestDo_StatusError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	req, _ := http.NewRequest(http.MethodGet, server.URL, nil)

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	_, err := Do[map[string]any](req, server.Client(), logger)
	assert.ErrorContains(t, err, "http request failed with status code 400")

	output := buf.String()
	assert.Contains(t, output, "http request encountered an unexpected status code")
	assert.Contains(t, output, "GET")
	assert.Contains(t, output, server.URL)
	assert.Contains(t, output, "400")
}

func TestDo_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	reqPath := "/some/path"
	req, _ := http.NewRequest(http.MethodGet, server.URL+reqPath, nil)

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	_, err := Do[map[string]any](req, server.Client(), logger)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, &NotFoundError{}))

	var notFoundError *NotFoundError
	assert.True(t, errors.As(err, &notFoundError))
	assert.Equal(t, "path", notFoundError.Resource)
	assert.Equal(t, reqPath, notFoundError.Source)
	assert.Equal(t, "[ path ] not found", err.Error())

	output := buf.String()
	assert.Contains(t, output, "http request encountered an unexpected status code")
	assert.Contains(t, output, "GET")
	assert.Contains(t, output, server.URL+reqPath)
	assert.Contains(t, output, "404")
}

func TestDo_DecodeError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{invalid json}"))
	}))
	defer server.Close()

	req, _ := http.NewRequest(http.MethodGet, server.URL, nil)

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	_, err := Do[map[string]any](req, server.Client(), logger)
	assert.ErrorContains(t, err, "failed to decode response body")

	output := buf.String()
	assert.Contains(t, output, "failed to decode response body")
	assert.Contains(t, output, "GET")
	assert.Contains(t, output, server.URL)
}
