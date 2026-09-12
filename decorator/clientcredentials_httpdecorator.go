package decorator

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Dallin-Cawley/httpw"
)

// ClientCredential represents the credentials used to authenticate with the OAuth 2.0 authorization server.
type ClientCredential struct {
	ClientID     string `json:"client_id" xml:"client_id"`
	ClientSecret string `json:"client_secret" xml:"client_secret"`
	scope        string
}

func NewClientCredential(clientID, clientSecret string) *ClientCredential {
	return &ClientCredential{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
}

// Token represents an OAuth 2.0 token response per RFC 6749 Section 5.1.
type Token struct {
	AccessToken  string    `json:"access_token" xml:"access_token"`
	TokenType    string    `json:"token_type" xml:"token_type"`
	ExpiresIn    int64     `json:"expires_in,omitempty" xml:"expires_in,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty" xml:"refresh_token,omitempty"`
	Scope        string    `json:"scope,omitempty" xml:"scope,omitempty"`
	Expiry       time.Time `json:"-" xml:"-"`
}

type ClientCredentialsHttpDecoratorOption func(*ClientCredentialsHttpDecorator)

func WithLogger(logger *slog.Logger) ClientCredentialsHttpDecoratorOption {
	return func(decorator *ClientCredentialsHttpDecorator) {
		decorator.logger = logger
	}
}

func WithScope(scope string) ClientCredentialsHttpDecoratorOption {
	return func(decorator *ClientCredentialsHttpDecorator) {
		decorator.scopes = []string{scope}
	}
}

func WithScopes(scopes ...string) ClientCredentialsHttpDecoratorOption {
	return func(decorator *ClientCredentialsHttpDecorator) {
		decorator.scopes = scopes
	}
}

func WithHTTPClient(client *http.Client) ClientCredentialsHttpDecoratorOption {
	return func(decorator *ClientCredentialsHttpDecorator) {
		decorator.httpClient = client
	}
}

// WithTokenDecorator is a decorator used to enable token request authentication. An example is a token endoint
// requiring mTLS authentication.
func WithTokenDecorator(tokenDecorator HttpDecorator) ClientCredentialsHttpDecoratorOption {
	return func(decorator *ClientCredentialsHttpDecorator) {
		decorator.tokenDecorator = tokenDecorator
	}
}

type ClientCredentialsHttpDecorator struct {
	mu             sync.RWMutex
	credentials    *ClientCredential
	tokenDecorator HttpDecorator
	token          *Token
	tokenURL       string
	scopes         []string
	httpClient     *http.Client
	logger         *slog.Logger
	now            func() time.Time
}

func NewClientCredentialsHttpDecorator(credentials *ClientCredential, tokenURL string, options ...ClientCredentialsHttpDecoratorOption) (*ClientCredentialsHttpDecorator, error) {
	if credentials == nil {
		return nil, errors.New("client credentials cannot be nil")
	}

	if credentials.ClientID == "" || credentials.ClientSecret == "" {
		return nil, errors.New("client credentials must contain ClientID and ClientSecret")
	}

	decorator := &ClientCredentialsHttpDecorator{
		credentials: credentials,
		tokenURL:    tokenURL,
	}

	for _, option := range options {
		option(decorator)
	}

	if decorator.tokenURL == "" {
		return nil, errors.New("token url is required")
	}

	if decorator.logger == nil {
		decorator.logger = slog.Default()
	}

	if decorator.now == nil {
		decorator.now = time.Now
	}

	return decorator, nil
}

func (decorator *ClientCredentialsHttpDecorator) Decorate(client *http.Client, request *http.Request) error {
	if request == nil {
		return errors.New("request cannot be nil")
	}

	httpClient := decorator.getClient(client)

	token, err := decorator.getToken(httpClient)
	if err != nil {
		return fmt.Errorf("failed to retrieve access token: %w", err)
	}

	tokenType := token.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}

	request.Header.Set("Authorization", fmt.Sprintf("%s %s", tokenType, token.AccessToken))
	return nil
}

func (decorator *ClientCredentialsHttpDecorator) getToken(client *http.Client) (*Token, error) {
	decorator.mu.RLock()
	if !decorator.isTokenValid() {
		decorator.mu.RUnlock()

		decorator.mu.Lock()
		defer decorator.mu.Unlock()

		if err := decorator.retrieveToken(client); err != nil {
			return nil, fmt.Errorf("failed to retrieve access token: %w", err)
		}

		return decorator.token, nil
	}
	decorator.mu.RUnlock()

	return decorator.token, nil
}

func (decorator *ClientCredentialsHttpDecorator) getClient(toDecorate *http.Client) *http.Client {
	httpClient := decorator.httpClient
	if httpClient == nil {
		httpClient = toDecorate
	}

	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	return httpClient
}

func (decorator *ClientCredentialsHttpDecorator) Token() *Token {
	decorator.mu.RLock()
	defer decorator.mu.RUnlock()
	return decorator.token
}

func (decorator *ClientCredentialsHttpDecorator) isTokenValid() bool {
	if decorator.token == nil {
		return false
	}
	if decorator.token.Expiry.IsZero() {
		return true
	}
	return decorator.now().Add(10 * time.Minute).Before(decorator.token.Expiry)
}

func (decorator *ClientCredentialsHttpDecorator) retrieveToken(client *http.Client) error {
	if decorator.token != nil && decorator.token.RefreshToken != "" {
		token, err := decorator.requestToken(client, "refresh_token")
		if err == nil {
			decorator.setToken(token)
			return nil
		}
	}

	token, err := decorator.requestToken(client, "client_credentials")
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}

	decorator.setToken(token)
	return nil
}

func (decorator *ClientCredentialsHttpDecorator) setToken(token *Token) {
	if token.ExpiresIn > 0 {
		token.Expiry = decorator.now().Add(time.Duration(token.ExpiresIn) * time.Second)
	} else {
		token.Expiry = time.Time{}
	}

	decorator.token = token
}

func (decorator *ClientCredentialsHttpDecorator) requestToken(client *http.Client, grantType string) (*Token, error) {
	data := url.Values{}
	data.Set("grant_type", grantType)

	if grantType == "refresh_token" {
		data.Set("refresh_token", decorator.token.RefreshToken)
	}

	scope := strings.Join(decorator.scopes, " ")
	if scope == "" && decorator.credentials.scope != "" {
		scope = decorator.credentials.scope
	}

	if scope != "" {
		data.Set("scope", scope)
	}

	req, err := http.NewRequest(http.MethodPost, decorator.tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	if decorator.tokenDecorator != nil {
		err = decorator.tokenDecorator.Decorate(client, req)
		if err != nil {
			return nil, fmt.Errorf("failed to decorate token request: %w", err)
		}
	}

	basicAuthCredential := NewBasicAuthCredentialFromClientCredential(decorator.credentials)
	basicAuthDecorator, _ := NewBasicAuthHttpDecorator(basicAuthCredential)
	_ = basicAuthDecorator.Decorate(client, req)

	token, err := httpw.Do[*Token](req, client, decorator.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to complete token request: %w", err)
	}

	if token.AccessToken == "" {
		return nil, errors.New("access_token is missing in token response")
	}

	return token, nil
}
