package decorator

import (
	"errors"
	"net/http"
	"strings"
)

// BasicAuthCredential represents the credentials used for HTTP Basic authentication.
type BasicAuthCredential struct {
	Username string `json:"username" xml:"username"`
	Password string `json:"password" xml:"password"`
}

func NewBasicAuthCredentialFromClientCredential(credential *ClientCredential) *BasicAuthCredential {
	return &BasicAuthCredential{
		Username: credential.ClientID,
		Password: credential.ClientSecret,
	}
}

func (credential *BasicAuthCredential) UnmarshalText(text []byte) error {
	hasKeyVal := false
	for key, val := range parseLines(text) {
		hasKeyVal = true
		switch strings.ToLower(key) {
		case "username", "user":
			credential.Username = val
		case "password", "pass":
			credential.Password = val
		}
	}
	if !hasKeyVal {
		str := strings.TrimSpace(string(text))
		if parts := strings.SplitN(str, ":", 2); len(parts) == 2 {
			credential.Username = strings.TrimSpace(parts[0])
			credential.Password = strings.TrimSpace(parts[1])
		}
	}
	return nil
}

type BasicAuthHttpDecoratorOption func(*BasicAuthHttpDecorator)

type BasicAuthHttpDecorator struct {
	credentials *BasicAuthCredential
}

func NewBasicAuthHttpDecorator(credentials *BasicAuthCredential, options ...BasicAuthHttpDecoratorOption) (*BasicAuthHttpDecorator, error) {
	if credentials == nil {
		return nil, errors.New("basic auth credentials cannot be nil")
	}

	if credentials.Username == "" {
		return nil, errors.New("basic auth credentials must contain Username")
	}

	decorator := &BasicAuthHttpDecorator{
		credentials: credentials,
	}

	for _, option := range options {
		option(decorator)
	}

	return decorator, nil
}

func (decorator *BasicAuthHttpDecorator) Decorate(_ *http.Client, request *http.Request) error {
	if request == nil {
		return errors.New("request cannot be nil")
	}

	request.SetBasicAuth(decorator.credentials.Username, decorator.credentials.Password)
	return nil
}

func (decorator *BasicAuthHttpDecorator) Credentials() *BasicAuthCredential {
	return decorator.credentials
}
