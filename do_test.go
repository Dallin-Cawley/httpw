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

	"github.com/stretchr/testify/suite"
)

type DoTestSuite struct {
	suite.Suite
	ctx context.Context
}

func (testSuite *DoTestSuite) SetupTest() {
	testSuite.ctx = context.Background()
}

func TestHttpwSuite(t *testing.T) {
	suite.Run(t, new(DoTestSuite))
}

func (testSuite *DoTestSuite) TestNewJsonRequest_Success() {
	body := map[string]string{"foo": "bar"}
	req, err := NewJsonRequest(testSuite.ctx, http.MethodPost, "http://example.com", body)
	testSuite.NoError(err)
	testSuite.NotNil(req)
	testSuite.Equal(http.MethodPost, req.Method)
	testSuite.Equal("http://example.com", req.URL.String())

	var actualBody map[string]string
	err = json.NewDecoder(req.Body).Decode(&actualBody)
	testSuite.NoError(err)
	testSuite.Equal(body, actualBody)
}

func (testSuite *DoTestSuite) TestNewJsonRequest_MarshalError() {
	// A channel cannot be marshaled to JSON.
	req, err := NewJsonRequest(testSuite.ctx, http.MethodPost, "http://example.com", make(chan int))
	testSuite.Nil(req)
	testSuite.ErrorContains(err, "failed to marshal request body")
}

func (testSuite *DoTestSuite) TestCloseReader_Success() {
	closer := io.NopCloser(bytes.NewReader(nil))
	CloseReader(testSuite.ctx, closer, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

type errorCloser struct{}

func (e errorCloser) Read(_ []byte) (n int, err error) { return 0, io.EOF }
func (e errorCloser) Close() error                     { return errors.New("close error") }

func (testSuite *DoTestSuite) TestCloseReader_Error() {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	err := errors.New("close error")

	CloseReader(testSuite.ctx, errorCloser{}, logger)
	testSuite.Contains(buf.String(), "Failed to close response body")
	testSuite.Contains(buf.String(), err.Error())
}

func (testSuite *DoTestSuite) TestDo_Success() {
	expected := map[string]string{"result": "ok"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(expected)
	}))
	defer server.Close()

	req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	result, err := Do[map[string]string](req, server.Client(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	testSuite.NoError(err)
	testSuite.Equal(expected, result)
}

func (testSuite *DoTestSuite) TestDo_IgnoreBody() {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("raw text"))
	}))
	defer server.Close()

	req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	_, err := Do[IgnoreBody](req, server.Client(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	testSuite.NoError(err)
}

func (testSuite *DoTestSuite) TestDo_ClientError() {
	req, _ := http.NewRequest(http.MethodGet, "http://invalid-url.invalid", nil)

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	_, err := Do[map[string]any](req, http.DefaultClient, logger)
	testSuite.ErrorContains(err, "failed to execute http request")

	output := buf.String()
	testSuite.Contains(output, "failed to execute http request")
	testSuite.Contains(output, "GET")
	testSuite.Contains(output, "http://invalid-url.invalid")
}

func (testSuite *DoTestSuite) TestDo_StatusError() {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	req, _ := http.NewRequest(http.MethodGet, server.URL, nil)

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	_, err := Do[map[string]any](req, server.Client(), logger)
	testSuite.ErrorContains(err, "http request failed with status code 400")

	output := buf.String()
	testSuite.Contains(output, "http request encountered an unexpected status code")
	testSuite.Contains(output, "GET")
	testSuite.Contains(output, server.URL)
	testSuite.Contains(output, "400")
}

func (testSuite *DoTestSuite) TestDo_NotFound() {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	reqPath := "/some/path"
	req, _ := http.NewRequest(http.MethodGet, server.URL+reqPath, nil)

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	_, err := Do[map[string]any](req, server.Client(), logger)
	testSuite.Error(err)
	testSuite.True(errors.Is(err, &NotFoundError{}))

	var notFoundError *NotFoundError
	testSuite.True(errors.As(err, &notFoundError))
	testSuite.Equal("path", notFoundError.Resource)
	testSuite.Equal(reqPath, notFoundError.Source)
	testSuite.Equal("[ path ] not found", err.Error())

	output := buf.String()
	testSuite.Contains(output, "http request encountered an unexpected status code")
	testSuite.Contains(output, "GET")
	testSuite.Contains(output, server.URL+reqPath)
	testSuite.Contains(output, "404")
}

func (testSuite *DoTestSuite) TestDo_DecodeError() {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{invalid json}"))
	}))
	defer server.Close()

	req, _ := http.NewRequest(http.MethodGet, server.URL, nil)

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	_, err := Do[map[string]any](req, server.Client(), logger)
	testSuite.ErrorContains(err, "failed to decode response body")

	output := buf.String()
	testSuite.Contains(output, "failed to decode response body")
	testSuite.Contains(output, "GET")
	testSuite.Contains(output, server.URL)
}
