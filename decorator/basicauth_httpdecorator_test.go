package decorator

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/Dallin-Cawley/httpw"
	"github.com/Dallin-Cawley/httpw/decorator/deserializer"
	"github.com/go-openapi/testify/v2/assert"
)

var _ HttpDecorator = (*BasicAuthHttpDecorator)(nil)

func TestBasicAuthCredentials_UnmarshalText(t *testing.T) {
	t.Run("standard key-value lines", func(t *testing.T) {
		textData := []byte("username=myuser\npassword=mypassword\n")
		var creds BasicAuthCredential
		err := creds.UnmarshalText(textData)
		assert.NoError(t, err)
		assert.Equal(t, "myuser", creds.Username)
		assert.Equal(t, "mypassword", creds.Password)
	})

	t.Run("user and pass aliases with quotes and comments", func(t *testing.T) {
		textData := []byte("# This is a comment\n\nuser=\"myuser\"\npass='mypassword'\n# Another comment\n")
		var creds BasicAuthCredential
		err := creds.UnmarshalText(textData)
		assert.NoError(t, err)
		assert.Equal(t, "myuser", creds.Username)
		assert.Equal(t, "mypassword", creds.Password)
	})

	t.Run("colon separated user:pass", func(t *testing.T) {
		textData := []byte("myuser:mypassword")
		var creds BasicAuthCredential
		err := creds.UnmarshalText(textData)
		assert.NoError(t, err)
		assert.Equal(t, "myuser", creds.Username)
		assert.Equal(t, "mypassword", creds.Password)
	})
}

func TestNewBasicAuthCredential(t *testing.T) {
	cred := NewBasicAuthCredential("my_user", "my_password")
	assert.NotNil(t, cred)
	assert.Equal(t, "my_user", cred.Username)
	assert.Equal(t, "my_password", cred.Password)
}

func TestNewBasicAuthHttpDecorator(t *testing.T) {
	t.Run("nil credentials error", func(t *testing.T) {
		dec, err := NewBasicAuthHttpDecorator(nil)
		assert.Nil(t, dec)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "basic auth credentials cannot be nil")
	})

	t.Run("empty username error", func(t *testing.T) {
		dec, err := NewBasicAuthHttpDecorator(&BasicAuthCredential{
			Username: "",
			Password: "pwd",
		})
		assert.Nil(t, dec)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "basic auth credentials must contain Username")
	})

	t.Run("valid credentials with empty password", func(t *testing.T) {
		creds := &BasicAuthCredential{
			Username: "admin",
			Password: "",
		}
		dec, err := NewBasicAuthHttpDecorator(creds)
		assert.NoError(t, err)
		assert.NotNil(t, dec)
		assert.Equal(t, creds, dec.Credentials())
	})

	t.Run("valid credentials with option", func(t *testing.T) {
		called := false
		customOption := func(d *BasicAuthHttpDecorator) {
			called = true
		}

		creds := &BasicAuthCredential{
			Username: "admin",
			Password: "pwd",
		}
		dec, err := NewBasicAuthHttpDecorator(creds, customOption)
		assert.NoError(t, err)
		assert.NotNil(t, dec)
		assert.True(t, called)
		assert.Equal(t, creds, dec.Credentials())
	})
}

func TestBasicAuthHttpDecorator_Decorate(t *testing.T) {
	t.Run("nil request error", func(t *testing.T) {
		creds := &BasicAuthCredential{
			Username: "admin",
			Password: "pwd",
		}
		dec, err := NewBasicAuthHttpDecorator(creds)
		assert.NoError(t, err)

		err = dec.Decorate(nil, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "request cannot be nil")
	})

	t.Run("decorates request with basic auth header", func(t *testing.T) {
		creds := &BasicAuthCredential{
			Username: "admin",
			Password: "secretpassword",
		}
		dec, err := NewBasicAuthHttpDecorator(creds)
		assert.NoError(t, err)

		req, err := http.NewRequest(http.MethodGet, "https://example.com/api", nil)
		assert.NoError(t, err)

		err = dec.Decorate(nil, req)
		assert.NoError(t, err)

		user, pass, ok := req.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, "admin", user)
		assert.Equal(t, "secretpassword", pass)
	})

	t.Run("server receives valid basic auth", func(t *testing.T) {
		var receivedUser, receivedPass string
		var authOk bool

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedUser, receivedPass, authOk = r.BasicAuth()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		}))
		defer server.Close()

		creds := &BasicAuthCredential{
			Username: "my_user",
			Password: "my_password",
		}
		dec, err := NewBasicAuthHttpDecorator(creds)
		assert.NoError(t, err)

		req, err := http.NewRequest(http.MethodGet, server.URL, nil)
		assert.NoError(t, err)

		err = dec.Decorate(server.Client(), req)
		assert.NoError(t, err)

		type responseBody struct {
			Status string `json:"status"`
		}

		resp, err := httpw.Do[responseBody](req, server.Client(), slog.Default())
		assert.NoError(t, err)
		assert.Equal(t, "ok", resp.Status)
		assert.True(t, authOk)
		assert.Equal(t, "my_user", receivedUser)
		assert.Equal(t, "my_password", receivedPass)
	})

	t.Run("concurrent decoration safety", func(t *testing.T) {
		creds := &BasicAuthCredential{
			Username: "concurrent_user",
			Password: "concurrent_password",
		}
		dec, err := NewBasicAuthHttpDecorator(creds)
		assert.NoError(t, err)

		var wg sync.WaitGroup
		for range 20 {
			wg.Go(func() {
				req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
				assert.NoError(t, err)

				err = dec.Decorate(http.DefaultClient, req)
				assert.NoError(t, err)

				user, pass, ok := req.BasicAuth()
				assert.True(t, ok)
				assert.Equal(t, "concurrent_user", user)
				assert.Equal(t, "concurrent_password", pass)
			})
		}
		wg.Wait()
	})
}

func TestBasicAuthCredentials_WithBasicDeserializer(t *testing.T) {
	d := deserializer.NewBasicDeserializer[BasicAuthCredential]()

	t.Run("deserialize Text", func(t *testing.T) {
		data := []byte("username=text_user\npassword=text_pass")
		res, err := d.Deserialize(data)
		assert.NoError(t, err)
		assert.Equal(t, "text_user", res.Username)
		assert.Equal(t, "text_pass", res.Password)
	})
}
