package decorator

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-openapi/testify/v2/assert"
)

var _ HttpDecorator = (*MtlsHttpDecorator)(nil)

type errorReadCloser struct {
	closed bool
}

func (e *errorReadCloser) Read(_ []byte) (n int, err error) {
	return 0, errors.New("read error")
}

func (e *errorReadCloser) Close() error {
	e.closed = true
	return nil
}

type trackingReadCloser struct {
	io.Reader
	closed bool
}

func newTrackingReadCloser(b []byte) *trackingReadCloser {
	return &trackingReadCloser{Reader: bytes.NewReader(b)}
}

func (t *trackingReadCloser) Close() error {
	t.closed = true
	return nil
}

func toReadCloser(b []byte) io.ReadCloser {
	return io.NopCloser(bytes.NewReader(b))
}

type mtlsTestContext struct {
	caPEM        []byte
	clientPEM    []byte
	clientKeyPEM []byte
	serverCert   tls.Certificate
}

func setupMTLS(t *testing.T) *mtlsTestContext {
	// 1. Generate Root CA
	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Root CA Org"},
			CommonName:   "Test Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPrivKey.PublicKey, caPrivKey)
	assert.NoError(t, err)
	caCert, err := x509.ParseCertificate(caCertDER)
	assert.NoError(t, err)

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	// 2. Generate Server Certificate
	serverPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Server Org"},
			CommonName:   "127.0.0.1",
		},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverPrivKey.PublicKey, caPrivKey)
	assert.NoError(t, err)
	serverPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER})
	serverKeyDER, err := x509.MarshalECPrivateKey(serverPrivKey)
	assert.NoError(t, err)
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER})
	serverCert, err := tls.X509KeyPair(serverPEM, serverKeyPEM)
	assert.NoError(t, err)

	// 3. Generate Client Certificate
	clientPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization: []string{"Test Client Org"},
			CommonName:   "Test Client",
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientPrivKey.PublicKey, caPrivKey)
	assert.NoError(t, err)
	clientPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER})

	clientKeyDER, err := x509.MarshalECPrivateKey(clientPrivKey)
	assert.NoError(t, err)
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyDER})

	return &mtlsTestContext{
		caPEM:        caPEM,
		clientPEM:    clientPEM,
		clientKeyPEM: clientKeyPEM,
		serverCert:   serverCert,
	}
}

func TestDecorate_Success_MtlsHandshake(t *testing.T) {
	ctx := setupMTLS(t)

	// Setup mTLS test server
	serverCertPool := x509.NewCertPool()
	serverCertPool.AppendCertsFromPEM(ctx.caPEM)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NotNil(t, r.TLS)
		assert.NotEmpty(t, r.TLS.PeerCertificates)
		assert.Equal(t, "Test Client", r.TLS.PeerCertificates[0].Subject.CommonName)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("mtls success"))
	}))

	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{ctx.serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    serverCertPool,
	}
	server.StartTLS()
	defer server.Close()

	// Decorate client
	d, err := NewMtlsHttpDecorator(
		toReadCloser(ctx.caPEM),
		toReadCloser(ctx.clientPEM),
		toReadCloser(ctx.clientKeyPEM),
	)
	assert.NoError(t, err)
	client := &http.Client{}
	err = d.Decorate(client, nil)
	assert.NoError(t, err)

	// Make request with decorated client
	resp, err := client.Get(server.URL)
	assert.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Decorate second client to verify decorator can be reused multiple times
	client2 := &http.Client{}
	err = d.Decorate(client2, nil)
	assert.NoError(t, err)
	resp2, err := client2.Get(server.URL)
	assert.NoError(t, err)
	defer func() {
		_ = resp2.Body.Close()
	}()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	// Unauthenticated client should fail
	unauthClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	_, err = unauthClient.Get(server.URL)
	assert.Error(t, err)
}

func TestDecorate_NilClient(t *testing.T) {
	ctx := setupMTLS(t)
	d, err := NewMtlsHttpDecorator(
		toReadCloser(ctx.caPEM),
		toReadCloser(ctx.clientPEM),
		toReadCloser(ctx.clientKeyPEM),
	)
	assert.NoError(t, err)
	err = d.Decorate(nil, nil)
	assert.ErrorContains(t, err, "client cannot be nil")
}

func TestNewMtlsHttpDecorator_ClientCertReadError(t *testing.T) {
	ctx := setupMTLS(t)
	d, err := NewMtlsHttpDecorator(
		toReadCloser(ctx.caPEM),
		&errorReadCloser{},
		toReadCloser(ctx.clientKeyPEM),
	)
	assert.Nil(t, d)
	assert.ErrorContains(t, err, "failed to read client certificate")
}

func TestNewMtlsHttpDecorator_ClientKeyReadError(t *testing.T) {
	ctx := setupMTLS(t)
	d, err := NewMtlsHttpDecorator(
		toReadCloser(ctx.caPEM),
		toReadCloser(ctx.clientPEM),
		&errorReadCloser{},
	)
	assert.Nil(t, d)
	assert.ErrorContains(t, err, "failed to read client key")
}

func TestNewMtlsHttpDecorator_InvalidClientKeyPair(t *testing.T) {
	ctx := setupMTLS(t)
	d, err := NewMtlsHttpDecorator(
		toReadCloser(ctx.caPEM),
		toReadCloser([]byte("invalid cert")),
		toReadCloser(ctx.clientKeyPEM),
	)
	assert.Nil(t, d)
	assert.ErrorContains(t, err, "failed to build client x509 key pair")
}

func TestNewMtlsHttpDecorator_CACertReadError(t *testing.T) {
	ctx := setupMTLS(t)
	d, err := NewMtlsHttpDecorator(
		&errorReadCloser{},
		toReadCloser(ctx.clientPEM),
		toReadCloser(ctx.clientKeyPEM),
	)
	assert.Nil(t, d)
	assert.ErrorContains(t, err, "failed to read ca certificate")
}

func TestNewMtlsHttpDecorator_InvalidCACertPEM(t *testing.T) {
	ctx := setupMTLS(t)

	t.Run("not pem", func(t *testing.T) {
		d, err := NewMtlsHttpDecorator(
			toReadCloser([]byte("not a pem certificate")),
			toReadCloser(ctx.clientPEM),
			toReadCloser(ctx.clientKeyPEM),
		)
		assert.Nil(t, d)
		assert.ErrorContains(t, err, "failed to append ca certificate to pool")
	})

	t.Run("wrong pem block type", func(t *testing.T) {
		wrongBlockPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("some key")})
		d, err := NewMtlsHttpDecorator(
			toReadCloser(wrongBlockPEM),
			toReadCloser(ctx.clientPEM),
			toReadCloser(ctx.clientKeyPEM),
		)
		assert.Nil(t, d)
		assert.ErrorContains(t, err, "failed to append ca certificate to pool")
	})

	t.Run("invalid der bytes in certificate block", func(t *testing.T) {
		invalidDERPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid der bytes")})
		d, err := NewMtlsHttpDecorator(
			toReadCloser(invalidDERPEM),
			toReadCloser(ctx.clientPEM),
			toReadCloser(ctx.clientKeyPEM),
		)
		assert.Nil(t, d)
		assert.ErrorContains(t, err, "failed to append ca certificate to pool")
	})
}

func TestNewMtlsHttpDecorator_NilCACert(t *testing.T) {
	ctx := setupMTLS(t)
	d, err := NewMtlsHttpDecorator(
		nil,
		toReadCloser(ctx.clientPEM),
		toReadCloser(ctx.clientKeyPEM),
	)
	assert.Nil(t, d)
	assert.ErrorContains(t, err, "ca certificate reader cannot be nil")
}

func TestNewMtlsHttpDecorator_NilClientCert(t *testing.T) {
	ctx := setupMTLS(t)
	d, err := NewMtlsHttpDecorator(
		toReadCloser(ctx.caPEM),
		nil,
		toReadCloser(ctx.clientKeyPEM),
	)
	assert.Nil(t, d)
	assert.ErrorContains(t, err, "client certificate reader cannot be nil")
}

func TestNewMtlsHttpDecorator_NilClientKey(t *testing.T) {
	ctx := setupMTLS(t)
	d, err := NewMtlsHttpDecorator(
		toReadCloser(ctx.caPEM),
		toReadCloser(ctx.clientPEM),
		nil,
	)
	assert.Nil(t, d)
	assert.ErrorContains(t, err, "client key reader cannot be nil")
}

func TestDecorate_PreservesExistingTransportConfig(t *testing.T) {
	ctx := setupMTLS(t)
	customTimeout := 42 * time.Second
	existingTransport := &http.Transport{
		ResponseHeaderTimeout: customTimeout,
		TLSClientConfig: &tls.Config{
			ServerName: "custom-server-name",
		},
	}
	client := &http.Client{
		Transport: existingTransport,
	}

	d, err := NewMtlsHttpDecorator(
		toReadCloser(ctx.caPEM),
		toReadCloser(ctx.clientPEM),
		toReadCloser(ctx.clientKeyPEM),
	)
	assert.NoError(t, err)
	err = d.Decorate(client, nil)
	assert.NoError(t, err)

	transport, ok := client.Transport.(*http.Transport)
	assert.True(t, ok)
	assert.Equal(t, customTimeout, transport.ResponseHeaderTimeout)
	assert.Equal(t, "custom-server-name", transport.TLSClientConfig.ServerName)
	assert.Len(t, transport.TLSClientConfig.Certificates, 1)
	assert.NotNil(t, transport.TLSClientConfig.RootCAs)
}

func TestDecorate_NilTLSClientConfig(t *testing.T) {
	ctx := setupMTLS(t)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: nil,
		},
	}

	d, err := NewMtlsHttpDecorator(
		toReadCloser(ctx.caPEM),
		toReadCloser(ctx.clientPEM),
		toReadCloser(ctx.clientKeyPEM),
	)
	assert.NoError(t, err)
	err = d.Decorate(client, nil)
	assert.NoError(t, err)

	transport, ok := client.Transport.(*http.Transport)
	assert.True(t, ok)
	assert.NotNil(t, transport.TLSClientConfig)
	assert.Len(t, transport.TLSClientConfig.Certificates, 1)
	assert.NotNil(t, transport.TLSClientConfig.RootCAs)
}

type dummyRoundTripper struct{}

func (d *dummyRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, nil
}

func TestDecorate_UnsupportedTransport(t *testing.T) {
	ctx := setupMTLS(t)
	client := &http.Client{
		Transport: &dummyRoundTripper{},
	}

	d, err := NewMtlsHttpDecorator(
		toReadCloser(ctx.caPEM),
		toReadCloser(ctx.clientPEM),
		toReadCloser(ctx.clientKeyPEM),
	)
	assert.NoError(t, err)
	err = d.Decorate(client, nil)
	assert.ErrorContains(t, err, "client transport is not an *http.Transport")
}

func TestDecorate_RepeatedCalls_NoDuplicateCertificatesOrOverwrittenRootCAs(t *testing.T) {
	ctx := setupMTLS(t)
	client := &http.Client{}

	d, err := NewMtlsHttpDecorator(
		toReadCloser(ctx.caPEM),
		toReadCloser(ctx.clientPEM),
		toReadCloser(ctx.clientKeyPEM),
	)
	assert.NoError(t, err)

	var initialRootCAs *x509.CertPool
	// Call Decorate 5 times
	for i := 0; i < 5; i++ {
		err = d.Decorate(client, nil)
		assert.NoError(t, err)

		transport, ok := client.Transport.(*http.Transport)
		assert.True(t, ok)
		assert.Len(t, transport.TLSClientConfig.Certificates, 1)
		if i == 0 {
			initialRootCAs = transport.TLSClientConfig.RootCAs
		} else {
			assert.Same(t, initialRootCAs, transport.TLSClientConfig.RootCAs)
		}
	}
}

func TestDecorate_PreservesExistingRootCAs(t *testing.T) {
	ctx := setupMTLS(t)

	// Create a separate custom Root CA
	customCAPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)
	customCATemplate := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject: pkix.Name{
			Organization: []string{"Existing Custom CA Org"},
			CommonName:   "Existing Custom CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	customCACertDER, err := x509.CreateCertificate(rand.Reader, customCATemplate, customCATemplate, &customCAPrivKey.PublicKey, customCAPrivKey)
	assert.NoError(t, err)
	customCACert, err := x509.ParseCertificate(customCACertDER)
	assert.NoError(t, err)

	customRootCAs := x509.NewCertPool()
	customRootCAs.AddCert(customCACert)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: customRootCAs,
			},
		},
	}

	d, err := NewMtlsHttpDecorator(
		toReadCloser(ctx.caPEM),
		toReadCloser(ctx.clientPEM),
		toReadCloser(ctx.clientKeyPEM),
	)
	assert.NoError(t, err)

	err = d.Decorate(client, nil)
	assert.NoError(t, err)

	transport, ok := client.Transport.(*http.Transport)
	assert.True(t, ok)
	// Must not replace the existing RootCAs instance
	assert.Same(t, customRootCAs, transport.TLSClientConfig.RootCAs)
	assert.Len(t, transport.TLSClientConfig.Certificates, 1)

	expectedPool := x509.NewCertPool()
	expectedPool.AddCert(customCACert)
	expectedPool.AddCert(d.caCert)
	assert.True(t, transport.TLSClientConfig.RootCAs.Equal(expectedPool))

	// Calling Decorate again should not duplicate any CA certs
	err = d.Decorate(client, nil)
	assert.NoError(t, err)
	assert.True(t, transport.TLSClientConfig.RootCAs.Equal(expectedPool))
}

func TestDecorate_AppendsDifferentCertificate(t *testing.T) {
	ctx := setupMTLS(t)
	otherCert := ctx.serverCert // A different certificate
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{otherCert},
			},
		},
	}

	d, err := NewMtlsHttpDecorator(
		toReadCloser(ctx.caPEM),
		toReadCloser(ctx.clientPEM),
		toReadCloser(ctx.clientKeyPEM),
	)
	assert.NoError(t, err)

	err = d.Decorate(client, nil)
	assert.NoError(t, err)

	transport, ok := client.Transport.(*http.Transport)
	assert.True(t, ok)
	assert.Len(t, transport.TLSClientConfig.Certificates, 2)
}

func Test_CertificateEquals(t *testing.T) {
	certA := tls.Certificate{Certificate: [][]byte{[]byte("cert1"), []byte("cert2")}}
	certB := tls.Certificate{Certificate: [][]byte{[]byte("cert1"), []byte("cert2")}}
	certDiffLen := tls.Certificate{Certificate: [][]byte{[]byte("cert1")}}
	certDiffContent := tls.Certificate{Certificate: [][]byte{[]byte("cert1"), []byte("cert3")}}

	assert.True(t, certificateEquals(certA, certB))
	assert.False(t, certificateEquals(certA, certDiffLen))
	assert.False(t, certificateEquals(certA, certDiffContent))
}

func TestNewMtlsHttpDecorator_ClosesReaders(t *testing.T) {
	ctx := setupMTLS(t)

	t.Run("closes all readers on success", func(t *testing.T) {
		ca := newTrackingReadCloser(ctx.caPEM)
		clientCert := newTrackingReadCloser(ctx.clientPEM)
		clientKey := newTrackingReadCloser(ctx.clientKeyPEM)

		d, err := NewMtlsHttpDecorator(ca, clientCert, clientKey)
		assert.NoError(t, err)
		assert.NotNil(t, d)
		assert.True(t, ca.closed, "ca cert reader should be closed")
		assert.True(t, clientCert.closed, "client cert reader should be closed")
		assert.True(t, clientKey.closed, "client key reader should be closed")
	})

	t.Run("closes open readers when client key is nil", func(t *testing.T) {
		ca := newTrackingReadCloser(ctx.caPEM)
		clientCert := newTrackingReadCloser(ctx.clientPEM)

		d, err := NewMtlsHttpDecorator(ca, clientCert, nil)
		assert.Error(t, err)
		assert.Nil(t, d)
		assert.True(t, ca.closed, "ca cert reader should be closed")
		assert.True(t, clientCert.closed, "client cert reader should be closed")
	})

	t.Run("closes open readers when client cert is nil", func(t *testing.T) {
		ca := newTrackingReadCloser(ctx.caPEM)

		d, err := NewMtlsHttpDecorator(ca, nil, nil)
		assert.Error(t, err)
		assert.Nil(t, d)
		assert.True(t, ca.closed, "ca cert reader should be closed")
	})

	t.Run("closes all readers on read/decode errors", func(t *testing.T) {
		ca := newTrackingReadCloser([]byte("invalid pem"))
		clientCert := newTrackingReadCloser(ctx.clientPEM)
		clientKey := newTrackingReadCloser(ctx.clientKeyPEM)

		d, err := NewMtlsHttpDecorator(ca, clientCert, clientKey)
		assert.Error(t, err)
		assert.Nil(t, d)
		assert.True(t, ca.closed, "ca cert reader should be closed")
		assert.True(t, clientCert.closed, "client cert reader should be closed")
		assert.True(t, clientKey.closed, "client key reader should be closed")
	})
}
