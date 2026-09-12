package decorator

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
)

type MtlsHttpDecorator struct {
	keyPair tls.Certificate
	caCert  *x509.Certificate
}

func NewMtlsHttpDecorator(caCert, clientCert, clientKey io.Reader) (*MtlsHttpDecorator, error) {
	if caCert == nil {
		return nil, errors.New("ca certificate reader cannot be nil for mTLS decoration")
	}

	if clientCert == nil {
		return nil, errors.New("client certificate reader cannot be nil for mTLS decoration")
	}

	if clientKey == nil {
		return nil, errors.New("client key reader cannot be nil for mTLS decoration")
	}

	clientCertBytes, err := io.ReadAll(clientCert)
	if err != nil {
		return nil, fmt.Errorf("failed to read client certificate: %w", err)
	}

	clientKeyBytes, err := io.ReadAll(clientKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read client key: %w", err)
	}

	keyPair, err := tls.X509KeyPair(clientCertBytes, clientKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to build client x509 key pair: %w", err)
	}

	caCertBytes, err := io.ReadAll(caCert)
	if err != nil {
		return nil, fmt.Errorf("failed to read ca certificate: %w", err)
	}

	caBlock, _ := pem.Decode(caCertBytes)
	if caBlock == nil || caBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to append ca certificate to pool: failed to decode ca certificate")
	}

	caCertificate, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to append ca certificate to pool: %w", err)
	}

	return &MtlsHttpDecorator{
		keyPair: keyPair,
		caCert:  caCertificate,
	}, nil
}

func (decorator *MtlsHttpDecorator) Decorate(client *http.Client, _ *http.Request) error {
	if client == nil {
		return errors.New("client cannot be nil")
	}

	transport, err := decorator.getTransport(client)
	if err != nil {
		return fmt.Errorf("failed to get transport: %w", err)
	}

	if !decorator.hasCertificate(transport.TLSClientConfig.Certificates, decorator.keyPair) {
		transport.TLSClientConfig.Certificates = append(transport.TLSClientConfig.Certificates, decorator.keyPair)
	}

	if transport.TLSClientConfig.RootCAs == nil {
		transport.TLSClientConfig.RootCAs = x509.NewCertPool()
	}

	transport.TLSClientConfig.RootCAs.AddCert(decorator.caCert)

	client.Transport = transport

	return nil
}

func (decorator *MtlsHttpDecorator) hasCertificate(certs []tls.Certificate, target tls.Certificate) bool {
	for _, cert := range certs {
		if certificateEquals(cert, target) {
			return true
		}
	}

	return false
}

func certificateEquals(lhs, rhs tls.Certificate) bool {
	if len(lhs.Certificate) != len(rhs.Certificate) {
		return false
	}

	for i := range lhs.Certificate {
		if !bytes.Equal(lhs.Certificate[i], rhs.Certificate[i]) {
			return false
		}
	}

	return true
}

func (decorator *MtlsHttpDecorator) getTransport(client *http.Client) (*http.Transport, error) {
	if client.Transport == nil {
		return http.DefaultTransport.(*http.Transport).Clone(), nil
	} else if existingTransport, ok := client.Transport.(*http.Transport); ok {
		return existingTransport.Clone(), nil
	}

	return nil, fmt.Errorf("client transport is not an *http.Transport: %T", client.Transport)
}
