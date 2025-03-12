package proxy

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// generateSelfSignedCert creates a self-signed certificate for testing TLS
func generateSelfSignedCert(t *testing.T) (tls.Certificate, error) {
	t.Helper()

	// Generate a private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Create a template for the certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Create the certificate
	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Encode the certificate and private key to PEM format
	certPEM := &bytes.Buffer{}
	pem.Encode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyPEM := &bytes.Buffer{}
	pem.Encode(keyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Parse certificate and private key
	cert, err := tls.X509KeyPair(certPEM.Bytes(), keyPEM.Bytes())
	if err != nil {
		return tls.Certificate{}, err
	}

	return cert, nil
}

// loadOrGenerateCert attempts to load certificates from files, or generates them if needed
func loadOrGenerateCert(t *testing.T) (tls.Certificate, error) {
	t.Helper()

	// Try to load existing certificates
	certFile := "server.crt"
	keyFile := "server.key"

	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			// Both files exist, try to load them
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err == nil {
				t.Logf("Using existing certificate files: %s, %s", certFile, keyFile)
				return cert, nil
			}
			t.Logf("Failed to load existing certificates, will generate new ones: %v", err)
		}
	}

	// Generate new certificates
	t.Logf("Generating new test certificate")
	return generateSelfSignedCert(t)
}

// startTestServer starts a simple TCP or TLS server for testing
func startTestServer(t *testing.T, useTLS bool) (string, func(), []byte) {
	t.Helper()

	// Data to echo back
	testData := []byte("Hello, proxy!")

	// Stop function to close server
	var stopFunc func()
	var listener net.Listener
	var err error

	if useTLS {
		// Load or generate certificate
		cert, err := loadOrGenerateCert(t)
		if err != nil {
			t.Fatalf("Failed to prepare certificate: %v", err)
		}

		// Create TLS config
		config := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		// Start TLS server
		listener, err = tls.Listen("tcp", "127.0.0.1:0", config)
		if err != nil {
			t.Fatalf("Failed to create TLS listener: %v", err)
		}
	} else {
		// Start TCP server
		listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Failed to create TCP listener: %v", err)
		}
	}

	// Create stop function
	stopFunc = func() {
		listener.Close()
	}

	// Run server in goroutine
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()

		for {
			conn, err := listener.Accept()
			if err != nil {
				return // Listener closed, exit
			}

			go func(c net.Conn) {
				defer c.Close()

				// Read data
				buf := make([]byte, 1024)
				n, err := c.Read(buf)
				if err != nil && err != io.EOF {
					t.Logf("Server read error: %v", err)
					return
				}

				// Echo received data + test data
				_, err = c.Write(append(buf[:n], testData...))
				if err != nil {
					t.Logf("Server write error: %v", err)
					return
				}
			}(conn)
		}
	}()

	return listener.Addr().String(), stopFunc, testData
}

// TestProxy tests the basic TCP proxy functionality
func TestProxy(t *testing.T) {
	// Start a test server
	serverAddr, stopServer, testData := startTestServer(t, false)
	defer stopServer()

	// Create a proxy
	proxyAddr := "127.0.0.1:0" // Automatically assign port
	proxy := NewProxy(proxyAddr, serverAddr)

	// Start the proxy
	listener, err := net.Listen("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Failed to create proxy listener: %v", err)
	}
	proxy.ListenAddr = listener.Addr().String()

	go func() {
		err := proxy.Start()
		if err != nil {
			t.Logf("Proxy exited with error: %v", err)
		}
	}()

	// Connect to the proxy
	conn, err := net.Dial("tcp", proxy.ListenAddr)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	// Send a message
	testMessage := []byte("Test message")
	_, err = conn.Write(testMessage)
	if err != nil {
		t.Fatalf("Failed to write to proxy: %v", err)
	}

	// Read the response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		t.Fatalf("Failed to read from proxy: %v", err)
	}

	// Verify the response
	expectedResponse := append(testMessage, testData...)
	if !bytes.Equal(response[:n], expectedResponse) {
		t.Errorf("Unexpected response: got %q, want %q", response[:n], expectedResponse)
	}
}

// TestProxyTLS tests the TLS proxy functionality
func TestProxyTLS(t *testing.T) {
	// Check if we can load/generate certificates
	cert, err := loadOrGenerateCert(t)
	if err != nil {
		t.Skip("Skipping TLS test due to certificate issues:", err)
	}

	// Start a test TLS server
	serverAddr, stopServer, testData := startTestServer(t, true)
	defer stopServer()

	// Create a TLS config that accepts any certificate (for testing)
	clientTLSConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	// Create a proxy
	proxyAddr := "127.0.0.1:0" // Automatically assign port
	proxy := NewProxy(proxyAddr, serverAddr)

	// Set TLS config for proxy
	proxy.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// Start the proxy with a custom listener
	listener, err := net.Listen("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Failed to create proxy listener: %v", err)
	}
	proxy.ListenAddr = listener.Addr().String()

	// Close the temporary listener as we'll use tls.Listen in StartTLS
	listener.Close()

	// Start the TLS proxy
	go func() {
		err := proxy.StartTLS()
		if err != nil {
			t.Logf("TLS Proxy exited with error: %v", err)
		}
	}()

	// Allow time for proxy to start
	time.Sleep(100 * time.Millisecond)

	// Connect to the proxy with TLS
	conn, err := tls.Dial("tcp", proxy.ListenAddr, clientTLSConfig)
	if err != nil {
		t.Fatalf("Failed to connect to TLS proxy: %v", err)
	}
	defer conn.Close()

	// Send a message
	testMessage := []byte("TLS test message")
	_, err = conn.Write(testMessage)
	if err != nil {
		t.Fatalf("Failed to write to TLS proxy: %v", err)
	}

	// Read the response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		t.Fatalf("Failed to read from TLS proxy: %v", err)
	}

	// Verify the response
	expectedResponse := append(testMessage, testData...)
	if !bytes.Equal(response[:n], expectedResponse) {
		t.Errorf("Unexpected TLS response: got %q, want %q", response[:n], expectedResponse)
	}
}

// TestProxyDataTransformation tests the data transformation handlers
func TestProxyDataTransformation(t *testing.T) {
	// Start a test server
	serverAddr, stopServer, _ := startTestServer(t, false)
	defer stopServer()

	// Create a proxy with custom data handlers
	proxyAddr := "127.0.0.1:0" // Automatically assign port
	proxy := NewProxy(proxyAddr, serverAddr)

	// Set up transformation handlers
	proxy.ClientToServerHandler = func(data []byte) ([]byte, bool) {
		// Convert client data to uppercase
		return bytes.ToUpper(data), true
	}

	proxy.ServerToClientHandler = func(data []byte) ([]byte, bool) {
		// Skip the original message part and add prefix to server response
		for i, b := range data {
			if b == 'H' && i+5 < len(data) && string(data[i:i+5]) == "Hello" {
				return append([]byte("TRANSFORMED: "), data[i:]...), true
			}
		}
		return data, true
	}

	// Start the proxy
	listener, err := net.Listen("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Failed to create proxy listener: %v", err)
	}
	proxy.ListenAddr = listener.Addr().String()

	go func() {
		err := proxy.Start()
		if err != nil {
			t.Logf("Proxy exited with error: %v", err)
		}
	}()

	// Connect to the proxy
	conn, err := net.Dial("tcp", proxy.ListenAddr)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	// Send a message (should be transformed to uppercase)
	testMessage := []byte("test transformation")
	_, err = conn.Write(testMessage)
	if err != nil {
		t.Fatalf("Failed to write to proxy: %v", err)
	}

	// Read the response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		t.Fatalf("Failed to read from proxy: %v", err)
	}

	// Verify response contains the transformed prefix
	if !bytes.Contains(response[:n], []byte("TRANSFORMED: ")) {
		t.Errorf("Server->Client transformation failed, response: %s", response[:n])
	}

	// The client's message should have been transformed to uppercase as received by the server
	upperMessage := bytes.ToUpper(testMessage)
	if !bytes.Contains(response[:n], upperMessage) {
		t.Errorf("Client->Server transformation failed, expected %s in response", upperMessage)
	}
}

// TestTLSConfigError tests that StartTLS returns an error when TLSConfig is nil
func TestTLSConfigError(t *testing.T) {
	proxy := NewProxy("127.0.0.1:0", "127.0.0.1:8080")

	// TLSConfig is nil, should return error
	err := proxy.StartTLS()

	if err == nil {
		t.Error("Expected error when TLSConfig is nil, got nil")
	}

	// Verify error message
	if err.Error() != "TLS configuration is missing" {
		t.Errorf("Unexpected error message: %v", err)
	}
}
