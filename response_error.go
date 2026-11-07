package httpw

import (
	"bytes"
	"io"
	"net/http"
)

// Compile-time interface check to ensure ResponseError implements error
var _ error = (*ResponseError)(nil)

// maxErrorBodyBytes bounds how much of an error response's body is kept.
const maxErrorBodyBytes = 1 << 20

// ResponseError is an HTTP response with status code 400 or above. Do returns one for every such response, so callers
// can inspect the response with errors.AsType:
//
//	if responseErr, ok := errors.AsType[*httpw.ResponseError](err); ok && responseErr.StatusCode() == http.StatusForbidden {
//		...
//	}
//
// Its error message is the one of Err, the error it wraps: a *NotFoundError for 404, a plain status error otherwise.
type ResponseError struct {
	// Response is the response. Do closes the original body, so Response.Body reads a buffered copy of it (at most
	// 1 MiB), also available from Body.
	Response *http.Response
	// Err describes the failure.
	Err error

	body []byte
}

// NewResponseError builds a ResponseError for response, reading and closing its body.
func NewResponseError(response *http.Response, err error) *ResponseError {
	body, _ := io.ReadAll(io.LimitReader(response.Body, maxErrorBodyBytes))
	_ = response.Body.Close()
	response.Body = io.NopCloser(bytes.NewReader(body))

	return &ResponseError{Response: response, Err: err, body: body}
}

// Error returns the message of Err.
func (e *ResponseError) Error() string {
	return e.Err.Error()
}

// Unwrap returns Err, so errors.Is and errors.As still find a *NotFoundError.
func (e *ResponseError) Unwrap() error {
	return e.Err
}

// StatusCode returns the response's status code.
func (e *ResponseError) StatusCode() int {
	return e.Response.StatusCode
}

// Body returns the buffered response body (at most 1 MiB).
func (e *ResponseError) Body() []byte {
	return e.body
}
