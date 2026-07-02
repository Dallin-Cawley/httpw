package httpw

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"reflect"
)

// NewJsonRequest creates a new HTTP request with the provided method, URL, and body. The body is
// marshaled to JSON before being set as the request body.
func NewJsonRequest(ctx context.Context, method string, url string, body any) (*http.Request, error) {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	return http.NewRequestWithContext(ctx, method, url, bytes.NewReader(bodyBytes))
}

// IgnoreBody is a placeholder type that can be used to indicate that the response body should be
// ignored. No unmarshaling will be attempted.
type IgnoreBody struct{}

func Do[T any](request *http.Request, client *http.Client, logger *slog.Logger) (T, error) {
	requestLogger := logger.
		WithGroup("request").
		With(
			slog.String("method", request.Method),
			slog.String("url", request.URL.String()),
		)

	requestLogger.LogAttrs(
		request.Context(),
		slog.LevelDebug,
		"Executing HTTP request",
		slog.Any("body", request.Body),
	)

	response, err := client.Do(request)
	if err != nil {
		newError := fmt.Errorf("failed to execute http request: %w", err)
		requestLogger.LogAttrs(request.Context(),
			slog.LevelError,
			newError.Error(),
		)

		return *new(T), newError
	}
	defer CloseReader(request.Context(), response.Body, logger)

	requestLogger.LogAttrs(
		request.Context(),
		slog.LevelDebug,
		"Received HTTP response",
		slog.Int("status_code", response.StatusCode),
	)

	if response.StatusCode >= http.StatusBadRequest {
		newError := fmt.Errorf("http request encountered an unexpected status code: %w", fmt.Errorf("unexpected status code"))
		requestLogger.LogAttrs(request.Context(),
			slog.LevelError,
			newError.Error(),
		)

		if response.StatusCode == http.StatusNotFound {
			return *new(T), NewNotFoundError(path.Base(request.URL.Path), request.URL.Path)
		}

		return *new(T), fmt.Errorf("http request failed with status code %d", response.StatusCode)
	}

	typeOf := reflect.TypeOf(*new(T))
	if typeOf == reflect.TypeOf(IgnoreBody{}) || typeOf == reflect.TypeOf(&IgnoreBody{}) {
		requestLogger.LogAttrs(
			request.Context(),
			slog.LevelDebug,
			"response struct set to IgnoreBody; skipping response body decoding",
		)
		return *new(T), nil
	}

	var responseBody T
	if err = json.NewDecoder(response.Body).Decode(&responseBody); err != nil {
		newError := fmt.Errorf("failed to decode response body: %w", err)
		requestLogger.LogAttrs(
			request.Context(),
			slog.LevelError,
			newError.Error(),
		)

		return *new(T), newError
	}

	requestLogger.LogAttrs(
		request.Context(),
		slog.LevelDebug,
		"Decoded HTTP response",
		slog.Any("body", responseBody),
	)

	return responseBody, nil
}

// CloseReader closes the provided io.ReadCloser and logs an error if present. This is typically used
// with the defer keyword.
//
//	defer CloseReader(responseBody.Body, logger)
func CloseReader(ctx context.Context, closer io.ReadCloser, logger *slog.Logger) {
	if err := closer.Close(); err != nil {
		logger.LogAttrs(ctx, slog.LevelError, fmt.Sprintf("Failed to close response body: %s", err))
	}
}
