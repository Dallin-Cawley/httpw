package decorator

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/go-openapi/testify/v2/assert"
)

var _ HttpDecorator = (*ClientCredentialsHttpDecorator)(nil)

func WithTimeFunc(now func() time.Time) ClientCredentialsHttpDecoratorOption {
	return func(decorator *ClientCredentialsHttpDecorator) {
		decorator.now = now
	}
}

func TestNewClientCredentialsHttpDecorator_Options(t *testing.T) {
	customClient := &http.Client{}
	nowFixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fixedNowFunc := func() time.Time { return nowFixed }
	logger := slog.Default()
	tokenDecorator := &mockHttpDecorator{}

	creds := &ClientCredential{
		ClientID:     "my_id",
		ClientSecret: "my_secret",
		tokenURL:     "https://auth.example.com/token",
		scope:        "read write",
	}

	dec, err := NewClientCredentialsHttpDecorator(
		creds,
		WithLogger(logger),
		WithScope("single_scope"),
		WithScopes("scope1", "scope2"),
		WithHTTPClient(customClient),
		WithTimeFunc(fixedNowFunc),
		WithTokenDecorator(tokenDecorator),
	)

	assert.NoError(t, err)
	assert.NotNil(t, dec)
	assert.Equal(t, tokenDecorator, dec.tokenDecorator)
}

func TestNewClientCredential(t *testing.T) {
	cred := NewClientCredential("my_client_id", "my_client_secret")
	assert.NotNil(t, cred)
	assert.Equal(t, "my_client_id", cred.ClientID)
	assert.Equal(t, "my_client_secret", cred.ClientSecret)
}

func TestClientCredentials_UnmarshalText(t *testing.T) {
	textData := []byte("# comments are ignored\n\nclient_id = test_client_id\nclient_secret = \"test_client_secret\"\ntoken_url = 'https://text.example.com/token'\nscope=read write\n")
	var creds ClientCredential
	err := creds.UnmarshalText(textData)
	assert.NoError(t, err)
	assert.Equal(t, "test_client_id", creds.ClientID)
	assert.Equal(t, "test_client_secret", creds.ClientSecret)
	assert.Equal(t, "https://text.example.com/token", creds.tokenURL)
	assert.Equal(t, "read write", creds.scope)

	// Direct format test matching client_id=theID\nclient_secret=theSecret
	textData2 := []byte("client_id=theID\nclient_secret=theSecret\n")
	var creds2 ClientCredential
	err = creds2.UnmarshalText(textData2)
	assert.NoError(t, err)
	assert.Equal(t, "theID", creds2.ClientID)
	assert.Equal(t, "theSecret", creds2.ClientSecret)
}

func TestDecorate_NilRequest(t *testing.T) {
	creds := &ClientCredential{ClientID: "id", ClientSecret: "sec", tokenURL: "https://example.com/token"}
	dec, err := NewClientCredentialsHttpDecorator(creds)
	assert.NoError(t, err)
	err = dec.Decorate(&http.Client{}, nil)
	assert.Error(t, err)
	assert.Equal(t, "request cannot be nil", err.Error())
}

func TestNewClientCredentialsHttpDecorator_NilCredentials(t *testing.T) {
	dec, err := NewClientCredentialsHttpDecorator(nil)
	assert.Error(t, err)
	assert.Equal(t, "client credentials cannot be nil", err.Error())
	assert.Nil(t, dec)
}

func TestNewClientCredentialsHttpDecorator_MissingClientIDOrSecret(t *testing.T) {
	t.Run("missing client_id", func(t *testing.T) {
		dec, err := NewClientCredentialsHttpDecorator(
			&ClientCredential{ClientSecret: "sec", tokenURL: "https://example.com/token"},
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "client credentials must contain ClientID and ClientSecret")
		assert.Nil(t, dec)
	})

	t.Run("missing client_secret", func(t *testing.T) {
		dec, err := NewClientCredentialsHttpDecorator(
			&ClientCredential{ClientID: "id", tokenURL: "https://example.com/token"},
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "client credentials must contain ClientID and ClientSecret")
		assert.Nil(t, dec)
	})
}

func TestNewClientCredentialsHttpDecorator_MissingTokenURL(t *testing.T) {
	dec, err := NewClientCredentialsHttpDecorator(
		&ClientCredential{ClientID: "id", ClientSecret: "sec"},
	)
	assert.Error(t, err)
	assert.Equal(t, "token url is required", err.Error())
	assert.Nil(t, dec)
}

func TestDecorate_SuccessfulFlow_And_Reuse(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		assert.Equal(t, "application/json", r.Header.Get("Accept"))

		user, pass, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, "my_client_id", user)
		assert.Equal(t, "my_client_secret", pass)

		err := r.ParseForm()
		assert.NoError(t, err)
		assert.Equal(t, "client_credentials", r.Form.Get("grant_type"))
		assert.Equal(t, "read write", r.Form.Get("scope"))

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		_, _ = w.Write([]byte(`{
			"access_token":"token_abc_123",
			"token_type":"Bearer",
			"expires_in":3600,
			"refresh_token":"ref_xyz_789"
		}`))
	}))
	defer server.Close()

	creds := &ClientCredential{
		ClientID:     "my_client_id",
		ClientSecret: "my_client_secret",
		tokenURL:     server.URL,
		scope:        "read write",
	}
	dec, err := NewClientCredentialsHttpDecorator(creds)
	assert.NoError(t, err)

	req1, err := http.NewRequest(http.MethodGet, "https://api.example.com/data", nil)
	assert.NoError(t, err)

	err = dec.Decorate(server.Client(), req1)
	assert.NoError(t, err)
	assert.Equal(t, "Bearer token_abc_123", req1.Header.Get("Authorization"))
	assert.Equal(t, 1, requestCount)

	cachedToken := dec.Token()
	assert.NotNil(t, cachedToken)
	assert.Equal(t, "token_abc_123", cachedToken.AccessToken)

	// Second call should reuse the cached in-memory token and not hit the server again
	req2, err := http.NewRequest(http.MethodGet, "https://api.example.com/other", nil)
	assert.NoError(t, err)

	err = dec.Decorate(server.Client(), req2)
	assert.NoError(t, err)
	assert.Equal(t, "Bearer token_abc_123", req2.Header.Get("Authorization"))
	assert.Equal(t, 1, requestCount)
}

func TestDecorate_ExpirationAndRefresh(t *testing.T) {
	tokenRequestCount := 0
	refreshRequestCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		assert.NoError(t, err)

		grantType := r.Form.Get("grant_type")
		if grantType == "client_credentials" {
			tokenRequestCount++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"access_token":"initial_access_token",
				"token_type":"example",
				"expires_in":3600,
				"refresh_token":"refresh_token_1"
			}`))
		} else if grantType == "refresh_token" {
			refreshRequestCount++
			assert.Equal(t, "refresh_token_1", r.Form.Get("refresh_token"))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"access_token":"refreshed_access_token",
				"token_type":"example",
				"expires_in":3600
			}`))
		}
	}))
	defer server.Close()

	currentTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	timeFunc := func() time.Time {
		return currentTime
	}

	dec, err := NewClientCredentialsHttpDecorator(
		&ClientCredential{ClientID: "id", ClientSecret: "sec", tokenURL: server.URL},
		WithTimeFunc(timeFunc),
	)
	assert.NoError(t, err)

	// First request: gets initial token
	req1, err := http.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
	assert.NoError(t, err)
	err = dec.Decorate(server.Client(), req1)
	assert.NoError(t, err)
	assert.Equal(t, "example initial_access_token", req1.Header.Get("Authorization"))
	assert.Equal(t, 1, tokenRequestCount)
	assert.Equal(t, 0, refreshRequestCount)

	// Advance time past 3600 seconds
	currentTime = currentTime.Add(3601 * time.Second)

	// Second request: token expired, should trigger refresh_token grant
	req2, err := http.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
	assert.NoError(t, err)
	err = dec.Decorate(server.Client(), req2)
	assert.NoError(t, err)
	assert.Equal(t, "example refreshed_access_token", req2.Header.Get("Authorization"))
	assert.Equal(t, 1, tokenRequestCount)
	assert.Equal(t, 1, refreshRequestCount)
}

func TestDecorate_RefreshFailure_FallbackToClientCredentials(t *testing.T) {
	requests := make([]string, 0)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		assert.NoError(t, err)
		grantType := r.Form.Get("grant_type")
		requests = append(requests, grantType)

		if grantType == "client_credentials" && len(requests) == 1 {
			_, _ = w.Write([]byte(`{
				"access_token":"initial_token",
				"token_type":"Bearer",
				"expires_in":10,
				"refresh_token":"revoked_refresh_token"
			}`))
		} else if grantType == "refresh_token" {
			// Refresh token is rejected
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		} else if grantType == "client_credentials" && len(requests) == 3 {
			// Fallback succeeds
			_, _ = w.Write([]byte(`{
				"access_token":"recovered_token",
				"token_type":"Bearer",
				"expires_in":3600
			}`))
		}
	}))
	defer server.Close()

	currTime := time.Now()
	dec, err := NewClientCredentialsHttpDecorator(
		&ClientCredential{ClientID: "id", ClientSecret: "sec", tokenURL: server.URL},
		WithTimeFunc(func() time.Time { return currTime }),
	)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, "https://api.example.com", nil)
	assert.NoError(t, err)
	err = dec.Decorate(server.Client(), req)
	assert.NoError(t, err)
	assert.Equal(t, "Bearer initial_token", req.Header.Get("Authorization"))

	// Expire token
	currTime = currTime.Add(15 * time.Second)

	req2, err := http.NewRequest(http.MethodGet, "https://api.example.com", nil)
	assert.NoError(t, err)
	err = dec.Decorate(server.Client(), req2)
	assert.NoError(t, err)
	assert.Equal(t, "Bearer recovered_token", req2.Header.Get("Authorization"))
	assert.Equal(t, []string{"client_credentials", "refresh_token", "client_credentials"}, requests)
}

func TestDecorate_NoExpiresIn_CachedIndefinitely(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		_, _ = w.Write([]byte(`{"access_token":"permanent_token","token_type":"Bearer"}`))
	}))
	defer server.Close()

	dec, err := NewClientCredentialsHttpDecorator(
		&ClientCredential{ClientID: "id", ClientSecret: "sec", tokenURL: server.URL},
	)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, "https://api.example.com", nil)
	assert.NoError(t, err)

	err = dec.Decorate(server.Client(), req)
	assert.NoError(t, err)
	assert.Equal(t, "Bearer permanent_token", req.Header.Get("Authorization"))

	// Re-decorate
	err = dec.Decorate(server.Client(), req)
	assert.NoError(t, err)
	assert.Equal(t, 1, callCount)
}

func TestDecorate_DefaultTokenTypeBearer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Response without token_type field
		_, _ = w.Write([]byte(`{"access_token":"token_without_type"}`))
	}))
	defer server.Close()

	dec, err := NewClientCredentialsHttpDecorator(
		&ClientCredential{ClientID: "id", ClientSecret: "sec", tokenURL: server.URL},
	)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, "https://api.example.com", nil)
	assert.NoError(t, err)

	err = dec.Decorate(server.Client(), req)
	assert.NoError(t, err)
	assert.Equal(t, "Bearer token_without_type", req.Header.Get("Authorization"))
}

type errorBodyRoundTripper struct{}

func (e *errorBodyRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(iotest.ErrReader(errors.New("body read error"))),
	}, nil
}

func TestDecorate_TokenResponseBodyReadError(t *testing.T) {
	customClient := &http.Client{
		Transport: &errorBodyRoundTripper{},
	}

	dec, err := NewClientCredentialsHttpDecorator(
		&ClientCredential{ClientID: "id", ClientSecret: "sec", tokenURL: "https://example.com/token"},
		WithHTTPClient(customClient),
	)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, "https://api.example.com", nil)
	assert.NoError(t, err)

	err = dec.Decorate(nil, req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode response body")
}

func TestDecorate_TokenRequestErrors(t *testing.T) {
	t.Run("invalid token url", func(t *testing.T) {
		dec, err := NewClientCredentialsHttpDecorator(
			&ClientCredential{ClientID: "id", ClientSecret: "sec", tokenURL: "http://127.0.0.1:0/invalid"},
		)
		assert.NoError(t, err)
		req, err := http.NewRequest(http.MethodGet, "https://api.example.com", nil)
		assert.NoError(t, err)

		err = dec.Decorate(nil, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to retrieve access token")
	})

	t.Run("server error status code", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
		}))
		defer server.Close()

		dec, err := NewClientCredentialsHttpDecorator(
			&ClientCredential{ClientID: "id", ClientSecret: "sec", tokenURL: server.URL},
		)
		assert.NoError(t, err)
		req, err := http.NewRequest(http.MethodGet, "https://api.example.com", nil)
		assert.NoError(t, err)

		err = dec.Decorate(server.Client(), req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "401")
	})

	t.Run("invalid token json response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{not json`))
		}))
		defer server.Close()

		dec, err := NewClientCredentialsHttpDecorator(
			&ClientCredential{ClientID: "id", ClientSecret: "sec", tokenURL: server.URL},
		)
		assert.NoError(t, err)
		req, err := http.NewRequest(http.MethodGet, "https://api.example.com", nil)
		assert.NoError(t, err)

		err = dec.Decorate(server.Client(), req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode response body")
	})

	t.Run("missing access_token in response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"token_type":"Bearer"}`))
		}))
		defer server.Close()

		dec, err := NewClientCredentialsHttpDecorator(
			&ClientCredential{ClientID: "id", ClientSecret: "sec", tokenURL: server.URL},
		)
		assert.NoError(t, err)
		req, err := http.NewRequest(http.MethodGet, "https://api.example.com", nil)
		assert.NoError(t, err)

		err = dec.Decorate(server.Client(), req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "access_token is missing in token response")
	})

	t.Run("token url invalid scheme request error", func(t *testing.T) {
		dec, err := NewClientCredentialsHttpDecorator(
			&ClientCredential{ClientID: "id", ClientSecret: "sec", tokenURL: "://invalid-url"},
		)
		assert.NoError(t, err)
		req, err := http.NewRequest(http.MethodGet, "https://api.example.com", nil)
		assert.NoError(t, err)

		err = dec.Decorate(nil, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create token request")
	})
}

func TestDecorate_ConcurrentSafety(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		time.Sleep(10 * time.Millisecond)
		_, _ = w.Write([]byte(`{"access_token":"thread_safe_token","token_type":"Bearer","expires_in":3600}`))
	}))
	defer server.Close()

	dec, err := NewClientCredentialsHttpDecorator(
		&ClientCredential{ClientID: "id", ClientSecret: "sec", tokenURL: server.URL},
	)
	assert.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequest(http.MethodGet, "https://api.example.com", nil)
			assert.NoError(t, err)
			err = dec.Decorate(server.Client(), req)
			assert.NoError(t, err)
			assert.Equal(t, "Bearer thread_safe_token", req.Header.Get("Authorization"))
		}()
	}
	wg.Wait()
}

type mockHttpDecorator struct {
	decorateFunc func(client *http.Client, req *http.Request) error
}

func (m *mockHttpDecorator) Decorate(client *http.Client, req *http.Request) error {
	if m.decorateFunc != nil {
		return m.decorateFunc(client, req)
	}
	return nil
}

func TestDecorate_WithTokenDecorator_Success(t *testing.T) {
	tokenServerCalls := 0
	decoratorCalls := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenServerCalls++
		assert.Equal(t, "custom-token-header-value", r.Header.Get("X-Token-Decorator-Header"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"token_with_decorator","token_type":"Bearer","expires_in":3600}`))
	}))
	defer server.Close()

	tokenDec := &mockHttpDecorator{
		decorateFunc: func(client *http.Client, req *http.Request) error {
			decoratorCalls++
			assert.NotNil(t, client)
			assert.NotNil(t, req)
			req.Header.Set("X-Token-Decorator-Header", "custom-token-header-value")
			return nil
		},
	}

	creds := &ClientCredential{
		ClientID:     "my_id",
		ClientSecret: "my_secret",
		tokenURL:     server.URL,
	}

	dec, err := NewClientCredentialsHttpDecorator(
		creds,
		WithTokenDecorator(tokenDec),
	)
	assert.NoError(t, err)
	assert.NotNil(t, dec)
	assert.Equal(t, tokenDec, dec.tokenDecorator)

	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/protected", nil)
	assert.NoError(t, err)

	err = dec.Decorate(server.Client(), req)
	assert.NoError(t, err)
	assert.Equal(t, "Bearer token_with_decorator", req.Header.Get("Authorization"))
	assert.Equal(t, 1, tokenServerCalls)
	assert.Equal(t, 1, decoratorCalls)
}

func TestDecorate_WithTokenDecorator_Error(t *testing.T) {
	expectedErr := errors.New("custom token decorator failed")
	tokenDec := &mockHttpDecorator{
		decorateFunc: func(client *http.Client, req *http.Request) error {
			return expectedErr
		},
	}

	creds := &ClientCredential{
		ClientID:     "my_id",
		ClientSecret: "my_secret",
		tokenURL:     "https://auth.example.com/token",
	}

	dec, err := NewClientCredentialsHttpDecorator(
		creds,
		WithTokenDecorator(tokenDec),
	)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/protected", nil)
	assert.NoError(t, err)

	err = dec.Decorate(http.DefaultClient, req)
	assert.Error(t, err)
	assert.ErrorIs(t, err, expectedErr)
	assert.Contains(t, err.Error(), "failed to decorate token request: custom token decorator failed")
}

func TestDecorate_WithTokenDecorator_RefreshToken(t *testing.T) {
	var decoratedGrants []string
	tokenDec := &mockHttpDecorator{
		decorateFunc: func(client *http.Client, req *http.Request) error {
			req.Header.Set("X-Decorated", "true")
			return nil
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "true", r.Header.Get("X-Decorated"))
		err := r.ParseForm()
		assert.NoError(t, err)
		grantType := r.Form.Get("grant_type")
		decoratedGrants = append(decoratedGrants, grantType)

		if grantType == "client_credentials" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"access_token":"initial_token",
				"token_type":"Bearer",
				"expires_in":10,
				"refresh_token":"ref_123"
			}`))
		} else if grantType == "refresh_token" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"access_token":"refreshed_token",
				"token_type":"Bearer",
				"expires_in":3600,
				"refresh_token":"ref_123"
			}`))
		}
	}))
	defer server.Close()

	currentTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	dec, err := NewClientCredentialsHttpDecorator(
		&ClientCredential{ClientID: "id", ClientSecret: "sec", tokenURL: server.URL},
		WithTokenDecorator(tokenDec),
		WithTimeFunc(func() time.Time { return currentTime }),
	)
	assert.NoError(t, err)

	// First request: client_credentials grant
	req1, err := http.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
	assert.NoError(t, err)
	err = dec.Decorate(server.Client(), req1)
	assert.NoError(t, err)
	assert.Equal(t, "Bearer initial_token", req1.Header.Get("Authorization"))

	// Expire token and trigger refresh_token grant
	currentTime = currentTime.Add(15 * time.Second)
	req2, err := http.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
	assert.NoError(t, err)
	err = dec.Decorate(server.Client(), req2)
	assert.NoError(t, err)
	assert.Equal(t, "Bearer refreshed_token", req2.Header.Get("Authorization"))

	assert.Equal(t, []string{"client_credentials", "refresh_token"}, decoratedGrants)
}

func TestClientCredentials_IsTokenValid_Thresholds(t *testing.T) {
	nowFixed := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	fixedNowFunc := func() time.Time { return nowFixed }

	creds := &ClientCredential{
		ClientID:     "my_id",
		ClientSecret: "my_secret",
		tokenURL:     "https://auth.example.com/token",
	}

	dec, err := NewClientCredentialsHttpDecorator(creds, WithTimeFunc(fixedNowFunc))
	assert.NoError(t, err)

	t.Run("nil token", func(t *testing.T) {
		dec.token = nil
		assert.False(t, dec.isTokenValid())
	})

	t.Run("zero expiry token (indefinite validity)", func(t *testing.T) {
		dec.token = &Token{
			AccessToken: "token_no_expiry",
			Expiry:      time.Time{},
		}
		assert.True(t, dec.isTokenValid())
	})

	t.Run("expiry strictly greater than 10 minutes", func(t *testing.T) {
		dec.token = &Token{
			AccessToken: "valid_token",
			Expiry:      nowFixed.Add(10*time.Minute + time.Second),
		}
		assert.True(t, dec.isTokenValid())
	})

	t.Run("expiry exactly 10 minutes", func(t *testing.T) {
		dec.token = &Token{
			AccessToken: "boundary_token",
			Expiry:      nowFixed.Add(10 * time.Minute),
		}
		assert.False(t, dec.isTokenValid())
	})

	t.Run("expiry less than 10 minutes", func(t *testing.T) {
		dec.token = &Token{
			AccessToken: "near_expiry_token",
			Expiry:      nowFixed.Add(10*time.Minute - time.Second),
		}
		assert.False(t, dec.isTokenValid())
	})

	t.Run("expiry in the past", func(t *testing.T) {
		dec.token = &Token{
			AccessToken: "past_token",
			Expiry:      nowFixed.Add(-1 * time.Minute),
		}
		assert.False(t, dec.isTokenValid())
	})
}

func TestDecorate_TenMinuteValidityThresholdFlow(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"access_token":"token_test",
			"token_type":"Bearer",
			"expires_in":3600
		}`))
	}))
	defer server.Close()

	currentTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	timeFunc := func() time.Time {
		return currentTime
	}

	dec, err := NewClientCredentialsHttpDecorator(
		&ClientCredential{ClientID: "id", ClientSecret: "sec", tokenURL: server.URL},
		WithTimeFunc(timeFunc),
	)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, "https://api.example.com", nil)
	assert.NoError(t, err)

	// First request at t0: retrieves token (expires at t0 + 60m)
	err = dec.Decorate(server.Client(), req)
	assert.NoError(t, err)
	assert.Equal(t, 1, requestCount)

	// Advance time by 49 minutes -> 11 minutes remaining (> 10m threshold), should reuse cached token
	currentTime = currentTime.Add(49 * time.Minute)
	err = dec.Decorate(server.Client(), req)
	assert.NoError(t, err)
	assert.Equal(t, 1, requestCount)

	// Advance time by 1 more minute -> 10 minutes remaining (not > 10m threshold), should retrieve new token
	currentTime = currentTime.Add(1 * time.Minute)
	err = dec.Decorate(server.Client(), req)
	assert.NoError(t, err)
	assert.Equal(t, 2, requestCount)
}

func TestClientCredentials_ConcurrentReadsAndDecorate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"access_token":"concurrent_token",
			"token_type":"Bearer",
			"expires_in":3600
		}`))
	}))
	defer server.Close()

	dec, err := NewClientCredentialsHttpDecorator(
		&ClientCredential{ClientID: "id", ClientSecret: "sec", tokenURL: server.URL},
	)
	assert.NoError(t, err)

	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			req, reqErr := http.NewRequest(http.MethodGet, "https://api.example.com", nil)
			assert.NoError(t, reqErr)
			decErr := dec.Decorate(server.Client(), req)
			assert.NoError(t, decErr)
			assert.Equal(t, "Bearer concurrent_token", req.Header.Get("Authorization"))
		}()

		go func() {
			defer wg.Done()
			token := dec.Token()
			if token != nil {
				assert.Equal(t, "concurrent_token", token.AccessToken)
			}
		}()
	}

	wg.Wait()
	assert.NotNil(t, dec.Token())
	assert.Equal(t, "concurrent_token", dec.Token().AccessToken)
}

func TestDecorate_CustomTokenType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"access_token":"custom_token",
			"token_type":"MAC",
			"expires_in":3600
		}`))
	}))
	defer server.Close()

	dec, err := NewClientCredentialsHttpDecorator(
		&ClientCredential{ClientID: "id", ClientSecret: "sec", tokenURL: server.URL},
	)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, "https://api.example.com", nil)
	assert.NoError(t, err)

	// First call triggers retrieval with custom token type
	err = dec.Decorate(server.Client(), req)
	assert.NoError(t, err)
	assert.Equal(t, "MAC custom_token", req.Header.Get("Authorization"))

	// Subsequent call uses read lock cache with custom token type
	req2, err := http.NewRequest(http.MethodGet, "https://api.example.com", nil)
	assert.NoError(t, err)
	err = dec.Decorate(server.Client(), req2)
	assert.NoError(t, err)
	assert.Equal(t, "MAC custom_token", req2.Header.Get("Authorization"))
}
