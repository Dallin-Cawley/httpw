package httpw

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/suite"
)

type NotFoundErrorTestSuite struct {
	suite.Suite
}

func (testSuite *NotFoundErrorTestSuite) TestError_ReturnsFormattedMessage() {
	err := &NotFoundError{Resource: "resource X"}
	testSuite.Equal("[ resource X ] not found", err.Error())
}

func (testSuite *NotFoundErrorTestSuite) TestNewEmptyNotFoundError_ReturnsEmptyNotFoundError() {
	err := NewEmptyNotFoundError()
	testSuite.Empty(err.Resource)
	testSuite.Empty(err.Source)
}

func (testSuite *NotFoundErrorTestSuite) TestNewNotFoundError_ReturnsPopulatedNotFoundError() {
	err := NewNotFoundError("resource X", "source Y")
	testSuite.Equal("resource X", err.Resource)
	testSuite.Equal("source Y", err.Source)
}

func (testSuite *NotFoundErrorTestSuite) TestIs_CorrectlyIdentifiesNotFoundError() {
	err := NewNotFoundError("resource A", "")
	other := NewNotFoundError("resource B", "")

	testSuite.True(errors.Is(err, other))
	testSuite.True(errors.Is(err, &NotFoundError{}))
}

func (testSuite *NotFoundErrorTestSuite) TestIs_ReturnsFalseForOtherErrors() {
	err := NewEmptyNotFoundError()
	other := errors.New("some other error")

	testSuite.False(errors.Is(err, other))
}

func TestNotFoundErrorTestSuite(t *testing.T) {
	suite.Run(t, new(NotFoundErrorTestSuite))
}
