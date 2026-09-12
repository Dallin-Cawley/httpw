package httpw

import (
	"errors"
	"testing"

	"github.com/go-openapi/testify/v2/assert"
)

func TestError_ReturnsFormattedMessage(t *testing.T) {
	err := &NotFoundError{Resource: "resource X"}
	assert.Equal(t, "[ resource X ] not found", err.Error())
}

func TestNewEmptyNotFoundError_ReturnsEmptyNotFoundError(t *testing.T) {
	err := NewEmptyNotFoundError()
	assert.Empty(t, err.Resource)
	assert.Empty(t, err.Source)
}

func TestNewNotFoundError_ReturnsPopulatedNotFoundError(t *testing.T) {
	err := NewNotFoundError("resource X", "source Y")
	assert.Equal(t, "resource X", err.Resource)
	assert.Equal(t, "source Y", err.Source)
}

func TestIs_CorrectlyIdentifiesNotFoundError(t *testing.T) {
	err := NewNotFoundError("resource A", "")
	other := NewNotFoundError("resource B", "")

	assert.True(t, errors.Is(err, other))
	assert.True(t, errors.Is(err, &NotFoundError{}))
}

func TestIs_ReturnsFalseForOtherErrors(t *testing.T) {
	err := NewEmptyNotFoundError()
	other := errors.New("some other error")

	assert.False(t, errors.Is(err, other))
}
