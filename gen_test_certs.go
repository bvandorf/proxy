//go:build tools
// +build tools

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

// This is a utility script to generate self-signed certificates for testing purposes
// Run with: go run gen_test_certs.go

func main() {
	if err := generateCertificates(); err != nil {
		log.Fatalf("Failed to generate certificates: %v", err)
	}
	fmt.Println("Successfully generated server.key, server.crt, client.key, client.crt, and ca.crt")
}

func generateCertificates() error {
	// Generate CA certificate first
	caKey, caCert, err := generateCA()
	if err != nil {
		return fmt.Errorf("failed to generate CA: %w", err)
	}

	// Write CA certificate to file
	if err := writeCertToFile(caCert, "ca.crt"); err != nil {
		return err
	}

	// Generate server certificate
	if err := generateServerCertificate(caKey, caCert); err != nil {
		return fmt.Errorf("failed to generate server certificate: %w", err)
	}

	// Generate client certificate
	if err := generateClientCertificate(caKey, caCert); err != nil {
		return fmt.Errorf("failed to generate client certificate: %w", err)
	}

	return nil
}

func generateCA() (*rsa.PrivateKey, []byte, error) {
	// Generate private key for CA
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CA private key: %w", err)
	}

	// Create a template for the CA certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"TCP/TLS Proxy Test CA"},
			CommonName:   "TCP/TLS Proxy Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create the CA certificate
	caCertDER, err := x509.CreateCertificate(
		rand.Reader,
		&caTemplate,
		&caTemplate,
		&caKey.PublicKey,
		caKey,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	return caKey, caCertDER, nil
}

func generateServerCertificate(caKey *rsa.PrivateKey, caCertDER []byte) error {
	// Load the CA certificate
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Generate private key for server
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate server private key: %w", err)
	}

	// Create a template for the server certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	serverTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"TCP/TLS Proxy Test"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Create the server certificate
	serverCertDER, err := x509.CreateCertificate(
		rand.Reader,
		&serverTemplate,
		caCert,
		&serverKey.PublicKey,
		caKey,
	)
	if err != nil {
		return fmt.Errorf("failed to create server certificate: %w", err)
	}

	// Write the server certificate and key to files
	if err := writeCertToFile(serverCertDER, "server.crt"); err != nil {
		return err
	}

	if err := writeKeyToFile(serverKey, "server.key"); err != nil {
		return err
	}

	return nil
}

func generateClientCertificate(caKey *rsa.PrivateKey, caCertDER []byte) error {
	// Load the CA certificate
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Generate private key for client
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate client private key: %w", err)
	}

	// Create a template for the client certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	clientTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"TCP/TLS Proxy Test Client"},
			CommonName:   "client",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Create the client certificate
	clientCertDER, err := x509.CreateCertificate(
		rand.Reader,
		&clientTemplate,
		caCert,
		&clientKey.PublicKey,
		caKey,
	)
	if err != nil {
		return fmt.Errorf("failed to create client certificate: %w", err)
	}

	// Write the client certificate and key to files
	if err := writeCertToFile(clientCertDER, "client.crt"); err != nil {
		return err
	}

	if err := writeKeyToFile(clientKey, "client.key"); err != nil {
		return err
	}

	return nil
}

func writeCertToFile(certDER []byte, filename string) error {
	certFile, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create certificate file %s: %w", filename, err)
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}); err != nil {
		return fmt.Errorf("failed to encode certificate: %w", err)
	}

	return nil
}

func writeKeyToFile(key *rsa.PrivateKey, filename string) error {
	keyFile, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create key file %s: %w", filename, err)
	}
	defer keyFile.Close()

	if err := pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}); err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	return nil
}
