package httpw

import (
	"errors"
	"fmt"
)

// Compile-time interface check to ensure NotFoundError implements error
var _ error = (*NotFoundError)(nil)

// NotFoundError is an error implementation for HTTP 404 Not Found status code.
type NotFoundError struct {
	Resource string
	Source   string
}

func NewEmptyNotFoundError() *NotFoundError { return &NotFoundError{} }

func NewNotFoundError(resource, source string) *NotFoundError {
	return &NotFoundError{
		Resource: resource,
		Source:   source,
	}
}

// Error returns the error message formatted for a 404 Not Found status.
func (e *NotFoundError) Error() string {
	return fmt.Sprintf("[ %s ] not found", e.Resource)
}

// Is reports whether the target error is a NotFoundError. This allows errors.Is()
// to identify any NotFoundError regardless of its specific message.
func (e *NotFoundError) Is(target error) bool {
	var notFoundError *NotFoundError
	ok := errors.As(target, &notFoundError)
	return ok
}
