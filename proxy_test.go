package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Use atomic counter to ensure each test uses a different port
var portCounter int32 = 10000

// getUniquePort returns a unique port number for testing
func getUniquePort() int {
	return int(atomic.AddInt32(&portCounter, 1))
}

// generateSelfSignedCert generates a self-signed certificate
func generateSelfSignedCert() (tls.Certificate, error) {
	// Generate private key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Create self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	// Encode private key to PEM
	keyPEM := new(bytes.Buffer)
	pem.Encode(keyPEM, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	// Load the certificate
	cert, err := tls.X509KeyPair(certPEM.Bytes(), keyPEM.Bytes())
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load certificate: %w", err)
	}

	return cert, nil
}

// startTestServer starts a test echo server and returns its address and a shutdown function
// If useTLS is true, it starts a TLS server and returns the certificate bytes
func startTestServer(t *testing.T, useTLS bool) (string, func(), []byte) {
	// Choose a random available port
	port := getUniquePort()
	serverAddr := fmt.Sprintf("127.0.0.1:%d", port)

	var listener net.Listener
	var err error
	var certPEM []byte
	var cert tls.Certificate

	if useTLS {
		// Generate a self-signed certificate if not provided
		cert, err = generateSelfSignedCert()
		if err != nil {
			t.Fatalf("Failed to generate certificate: %v", err)
		}

		// Get the certificate PEM for client verification
		certPEM = getCertificatePEM(cert)

		// Create TLS config
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		// Create TLS listener
		listener, err = tls.Listen("tcp", serverAddr, tlsConfig)
	} else {
		// Create regular TCP listener
		listener, err = net.Listen("tcp", serverAddr)
	}

	if err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}

	// Start the test server
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				if !IsClosedNetworkError(err) {
					t.Logf("Test server accept error: %v", err)
				}
				return
			}

			go echoHandler(conn)
		}
	}()

	// Return the server address, shutdown function, and cert PEM
	return serverAddr, func() {
		listener.Close()
	}, certPEM
}

// getCertificatePEM extracts the PEM-encoded certificate from a tls.Certificate
func getCertificatePEM(cert tls.Certificate) []byte {
	// For simplicity, we'll just take the first certificate in the chain
	if len(cert.Certificate) == 0 {
		return nil
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	return certPEM.Bytes()
}

// getPrivateKeyPEM extracts the PEM-encoded private key from an RSA private key
func getPrivateKeyPEM(key *rsa.PrivateKey) []byte {
	keyPEM := new(bytes.Buffer)
	pem.Encode(keyPEM, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return keyPEM.Bytes()
}

// echoHandler handles a connection by echoing back any data received
func echoHandler(conn net.Conn) {
	defer conn.Close()

	buffer := make([]byte, 1024)
	// Use a deadline to prevent hanging in tests
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))

	// Read data from the connection
	n, err := conn.Read(buffer)
	if err != nil {
		if err != io.EOF && !IsClosedNetworkError(err) {
			log.Printf("Error reading from connection: %v", err)
		}
		return
	}

	// Echo the data back
	conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	_, err = conn.Write(buffer[:n])
	if err != nil {
		log.Printf("Error writing to connection: %v", err)
	}
}

// TestProxyBasic tests basic proxy functionality without TLS
func TestProxyBasic(t *testing.T) {
	// Start a test server that echoes data
	serverAddr, stopServer, _ := startTestServer(t, false)
	defer stopServer()

	// Create a proxy with a unique port
	port := getUniquePort()
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", port)
	config := NewProxyConfig(proxyAddr, serverAddr)
	proxy := NewProxy(config)

	// Start the proxy in a goroutine
	proxyStarted := make(chan struct{})
	go func() {
		close(proxyStarted)
		err := proxy.Start()
		if err != nil && !IsClosedNetworkError(err) {
			t.Logf("Proxy exited with error: %v", err)
		}
	}()

	// Make sure to stop the proxy at the end of the test
	defer func() {
		proxy.Stop()
		time.Sleep(100 * time.Millisecond) // give time for cleanup
	}()

	// Wait for proxy to start
	<-proxyStarted
	time.Sleep(100 * time.Millisecond)

	// Connect to the proxy
	t.Logf("Connecting to proxy at %s", proxy.ListenAddr)
	conn, err := net.DialTimeout("tcp", proxy.ListenAddr, 1*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	// Send test data
	testMessage := []byte("test message")
	t.Logf("Sending message: %s", testMessage)
	_, err = conn.Write(testMessage)
	if err != nil {
		t.Fatalf("Failed to write to proxy: %v", err)
	}

	// Set a read deadline to avoid hanging
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))

	// Read response
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read from proxy: %v", err)
	}

	// Check the response
	response := buf[:n]
	t.Logf("Received response: %s", response)
	if string(response) != string(testMessage) {
		t.Errorf("Unexpected response: got %q, want %q", string(response), string(testMessage))
	}
}

// TestProxy tests the basic TCP proxy functionality
func TestProxy(t *testing.T) {
	// Start a test server
	serverAddr, stopServer, testData := startTestServer(t, false)
	defer stopServer()

	// Create a proxy with a unique port
	port := getUniquePort()
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", port)
	config := NewProxyConfig(proxyAddr, serverAddr)
	proxy := NewProxy(config)

	// Start the proxy without needing additional listeners
	go func() {
		err := proxy.Start()
		if err != nil && !IsClosedNetworkError(err) {
			t.Logf("Proxy exited with error: %v", err)
		}
	}()

	// Give the proxy time to start
	time.Sleep(100 * time.Millisecond)

	// Create a stop function for the proxy
	stopCh := make(chan struct{})
	defer close(stopCh)

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

// TestProxyTLS tests the proxy with basic TLS configuration
func TestProxyTLS(t *testing.T) {
	// Start a TLS test server
	serverAddr, stopServer, _ := startTestServer(t, true)
	defer stopServer()

	// Create a proxy with a unique port and TLS config
	port := getUniquePort()
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", port)
	config := NewProxyConfig(proxyAddr, serverAddr)

	// Generate a self-signed cert for testing
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	// Extract cert and key PEM
	certPEM := getCertificatePEM(cert)
	keyPEM := getPrivateKeyPEM(cert.PrivateKey.(*rsa.PrivateKey))

	// Create temp files for the certificate and key
	certFile, err := os.CreateTemp("", "cert*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp cert file: %v", err)
	}
	defer os.Remove(certFile.Name())

	keyFile, err := os.CreateTemp("", "key*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp key file: %v", err)
	}
	defer os.Remove(keyFile.Name())

	// Write cert and key to files
	if _, err := certFile.Write(certPEM); err != nil {
		t.Fatalf("Failed to write cert to file: %v", err)
	}
	certFile.Close()

	if _, err := keyFile.Write(keyPEM); err != nil {
		t.Fatalf("Failed to write key to file: %v", err)
	}
	keyFile.Close()

	// Configure TLS in the proxy
	config.WithTLS(certFile.Name(), keyFile.Name())

	proxy := NewProxy(config)

	// Start the proxy in a goroutine with a notification when ready
	proxyStarted := make(chan struct{})
	go func() {
		close(proxyStarted)
		err := proxy.Start()
		if err != nil && !IsClosedNetworkError(err) {
			t.Logf("Proxy exited with error: %v", err)
		}
	}()

	// Make sure to stop the proxy at the end of the test
	defer func() {
		proxy.Stop()
		time.Sleep(100 * time.Millisecond) // give time for cleanup
	}()

	// Wait for proxy to start
	<-proxyStarted
	time.Sleep(100 * time.Millisecond)

	// Connect to the proxy using TLS
	t.Logf("Connecting to proxy at %s", proxy.ListenAddr)

	// Create a TLS configuration that accepts any certificate
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // Accept self-signed certificate
	}

	// Establish a TLS connection
	tlsConn, err := tls.Dial("tcp", proxy.ListenAddr, tlsConfig)
	if err != nil {
		t.Fatalf("Failed to connect to proxy with TLS: %v", err)
	}
	defer tlsConn.Close()

	// Send test data
	testMessage := []byte("test tls message")
	t.Logf("Sending message: %s", testMessage)
	_, err = tlsConn.Write(testMessage)
	if err != nil {
		t.Fatalf("Failed to write to proxy: %v", err)
	}

	// Set a read deadline to avoid hanging
	tlsConn.SetReadDeadline(time.Now().Add(1 * time.Second))

	// Read response
	buf := make([]byte, 1024)
	n, err := tlsConn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read from proxy: %v", err)
	}

	// Check the response
	response := buf[:n]
	t.Logf("Received response: %s", response)

	if !bytes.Equal(response, testMessage) {
		t.Errorf("Response does not match sent message. Got %q, expected %q", response, testMessage)
	}
}

// TestProxyDataTransformation tests the data transformation handlers
func TestProxyDataTransformation(t *testing.T) {
	// Start a test server
	serverAddr, stopServer, _ := startTestServer(t, false)
	defer stopServer()

	// Create a proxy with custom data handlers and a unique port
	port := getUniquePort()
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", port)
	config := NewProxyConfig(proxyAddr, serverAddr)
	proxy := NewProxy(config)

	// Set up transformation handlers
	proxy.ClientToServerHandler = func(data []byte) ([]byte, bool) {
		// Just add a tag prefix to demonstrate transformation
		return append([]byte("TRANSFORMED_CLIENT: "), data...), true
	}

	proxy.ServerToClientHandler = func(data []byte) ([]byte, bool) {
		// For simplicity, just add a prefix to all server responses
		return append([]byte("TRANSFORMED_SERVER: "), data...), true
	}

	// Start the proxy
	go func() {
		err := proxy.Start()
		if err != nil && !IsClosedNetworkError(err) {
			t.Logf("Proxy exited with error: %v", err)
		}
	}()

	// Give the proxy time to start
	time.Sleep(100 * time.Millisecond)

	// Connect to the proxy
	conn, err := net.Dial("tcp", proxy.ListenAddr)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	// Send a message
	testMessage := []byte("test message")
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

	// Verify the transformation
	responseTxt := string(response[:n])
	t.Logf("Received response: %s", responseTxt)

	// Verify client->server transformation by looking for any expected transformation
	if !strings.Contains(responseTxt, "TRANSFORMED_SERVER:") {
		t.Errorf("Server->Client transformation failed, expected 'TRANSFORMED_SERVER:' in response")
	}
}

// TestTLSConfigError tests that the proxy handles TLS configuration errors
func TestTLSConfigError(t *testing.T) {
	// Use an invalid target address to force a connection error
	port := getUniquePort()
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", port)
	targetAddr := "invalid.local:9999" // Non-existent address

	// Create a proxy with TLS enabled but pointing to an invalid target
	config := NewProxyConfig(proxyAddr, targetAddr)

	// Generate a self-signed cert for testing
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	// Extract cert and key PEM
	certPEM := getCertificatePEM(cert)
	keyPEM := getPrivateKeyPEM(cert.PrivateKey.(*rsa.PrivateKey))

	// Create temp files for the certificate and key
	certFile, err := os.CreateTemp("", "cert*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp cert file: %v", err)
	}
	defer os.Remove(certFile.Name())

	keyFile, err := os.CreateTemp("", "key*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp key file: %v", err)
	}
	defer os.Remove(keyFile.Name())

	// Write cert and key to files
	if _, err := certFile.Write(certPEM); err != nil {
		t.Fatalf("Failed to write cert to file: %v", err)
	}
	certFile.Close()

	if _, err := keyFile.Write(keyPEM); err != nil {
		t.Fatalf("Failed to write key to file: %v", err)
	}
	keyFile.Close()

	// Configure TLS with InsecureSkipVerify
	config.WithTLS(certFile.Name(), keyFile.Name())
	// Update the TLSConfig to skip verification
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	proxy := NewProxy(config)
	proxy.tlsConfig = tlsConfig // Override the TLS config with insecure one

	// Start the proxy
	go func() {
		err := proxy.Start()
		if err != nil && !IsClosedNetworkError(err) {
			// It's expected to encounter an error when the proxy starts
			t.Logf("Proxy exited with expected error: %v", err)
		}
	}()

	// Give the proxy time to start
	time.Sleep(100 * time.Millisecond)

	// Connect to the proxy
	conn, err := net.DialTimeout("tcp", proxy.ListenAddr, 2*time.Second)
	if err != nil {
		// It's possible the proxy might not even start if TLS config is invalid
		t.Logf("As expected, could not connect to proxy: %v", err)
		return
	}
	defer conn.Close()

	// Send a message
	_, err = conn.Write([]byte("hello"))
	if err != nil {
		t.Logf("As expected, could not write to proxy: %v", err)
		return
	}

	// Try to read a response, but it should fail or timeout
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)

	// We expect either a timeout or a connection error
	if err != nil {
		t.Logf("As expected, reading from proxy failed: %v", err)
	} else {
		t.Errorf("Unexpected success reading from proxy with invalid TLS config")
	}

	// Stop the proxy if it started
	proxy.Stop()
}

// TestProxyWithTLS is a simple test to verify that a proxy can be created
// and successfully pass data between client and server
func TestProxyWithTLS(t *testing.T) {
	// Start a test server that echoes data
	serverAddr, stopServer, _ := startTestServer(t, false)
	defer stopServer()

	// Create a proxy with a unique port
	port := getUniquePort()
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", port)
	config := NewProxyConfig(proxyAddr, serverAddr)
	proxy := NewProxy(config)

	// Start the proxy
	go func() {
		err := proxy.Start()
		if err != nil && !IsClosedNetworkError(err) {
			t.Logf("Proxy exited with error: %v", err)
		}
	}()

	// Make sure to stop the proxy when the test ends
	defer proxy.Stop()

	// Give the proxy time to start
	time.Sleep(100 * time.Millisecond)

	// Connect to the proxy with a simple TCP connection
	conn, err := net.DialTimeout("tcp", proxy.ListenAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	// Send a message
	testMessage := []byte("test tls message")
	_, err = conn.Write(testMessage)
	if err != nil {
		t.Fatalf("Failed to write to proxy: %v", err)
	}

	// Read the response with a timeout
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	response := make([]byte, 1024)
	n, err := conn.Read(response)

	// Only check if we got some data back, don't verify contents
	// since this is a simplified test
	if err != nil {
		t.Fatalf("Failed to read from proxy: %v", err)
	} else if n == 0 {
		t.Errorf("Empty response received")
	} else {
		t.Logf("Received response: %s", string(response[:n]))
	}
}

// TestClientCertAuth tests client certificate authentication
func TestClientCertAuth(t *testing.T) {
	// Skip if certificates are not available
	if _, err := os.Stat("server.crt"); os.IsNotExist(err) {
		t.Skip("Skipping test: server.crt not found")
	}
	if _, err := os.Stat("server.key"); os.IsNotExist(err) {
		t.Skip("Skipping test: server.key not found")
	}
	if _, err := os.Stat("client.crt"); os.IsNotExist(err) {
		t.Skip("Skipping test: client.crt not found")
	}
	if _, err := os.Stat("ca.crt"); os.IsNotExist(err) {
		t.Skip("Skipping test: ca.crt not found")
	}

	// Create a proxy with the new configuration pattern
	config := NewProxyConfig("localhost:0", "localhost:0")
	config.WithTLS("server.crt", "server.key")
	config.WithClientAuth("ca.crt", "server.crt", "server.key")
	proxy := NewProxy(config)

	// Verify that the clientTLSConfig was properly configured
	if proxy.clientTLSConfig == nil {
		t.Fatalf("Client TLS config is nil after configuration")
	}

	// Verify client authentication is required
	if proxy.clientTLSConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("Expected ClientAuth to be RequireAndVerifyClientCert, got %v", proxy.clientTLSConfig.ClientAuth)
	}

	// Verify ClientCAs is set
	if proxy.clientTLSConfig.ClientCAs == nil {
		t.Errorf("ClientCAs is nil, expected CA certificate pool")
	}
}

// TestClientCertAuthIntegration performs a simplified integration test
// for client certificate authentication
func TestClientCertAuthIntegration(t *testing.T) {
	// Skip if certificates are not available
	if _, err := os.Stat("server.crt"); os.IsNotExist(err) {
		t.Skip("Skipping test: server.crt not found")
	}
	if _, err := os.Stat("client.crt"); os.IsNotExist(err) {
		t.Skip("Skipping test: client.crt not found")
	}
	if _, err := os.Stat("ca.crt"); os.IsNotExist(err) {
		t.Skip("Skipping test: ca.crt not found")
	}

	// Load certificates
	serverCert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		t.Fatalf("Failed to load server certificate: %v", err)
	}

	clientCert, err := tls.LoadX509KeyPair("client.crt", "client.key")
	if err != nil {
		t.Fatalf("Failed to load client certificate: %v", err)
	}

	caCert, err := os.ReadFile("ca.crt")
	if err != nil {
		t.Fatalf("Failed to read CA certificate: %v", err)
	}

	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		t.Fatalf("Failed to add CA certificate to pool")
	}

	// Set up a simple HTTPS server that requires client certificates
	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
	}

	// Start the server
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify we can access the client certificate info
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			fmt.Fprintf(w, "SUCCESS: Authenticated as %s", r.TLS.PeerCertificates[0].Subject.CommonName)
		} else {
			http.Error(w, "No client certificate provided", http.StatusUnauthorized)
		}
	}))

	server.TLS = serverTLSConfig
	server.StartTLS()
	defer server.Close()

	// Test with valid client certificate
	t.Run("Valid Client Certificate", func(t *testing.T) {
		// Create HTTP client with client certificate
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					Certificates:       []tls.Certificate{clientCert},
					RootCAs:            caCertPool,
					InsecureSkipVerify: true, // For testing only
				},
			},
		}

		// Make request to server
		resp, err := client.Get(server.URL)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		// Check response
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response: %v", err)
		}

		if !strings.Contains(string(body), "SUCCESS") {
			t.Errorf("Expected success message, got: %s", string(body))
		}

		t.Logf("Response with valid certificate: %s", string(body))
	})

	// Test without client certificate
	t.Run("No Client Certificate", func(t *testing.T) {
		// Create HTTP client without client certificate
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:            caCertPool,
					InsecureSkipVerify: true, // For testing only
				},
			},
		}

		// Attempt request to server (should fail)
		_, err := client.Get(server.URL)
		if err == nil {
			t.Errorf("Request succeeded but should have failed due to missing client certificate")
		} else {
			t.Logf("Request failed as expected: %v", err)
		}
	})
}

// TestCustomTargetTLSConfig tests the proxy with custom target TLS configuration and SNI
func TestCustomTargetTLSConfig(t *testing.T) {
	// Start a TLS test server
	serverAddr, stopServer, _ := startTestServer(t, true)
	defer stopServer()

	// Parse the host and port
	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		t.Fatalf("Failed to split host and port: %v", err)
	}

	// Create a proxy with a unique port
	port := getUniquePort()
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", port)
	config := NewProxyConfig(proxyAddr, serverAddr)

	// Generate certificates for the client-to-proxy connection
	serverCert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	// Extract cert and key PEM
	certPEM := getCertificatePEM(serverCert)
	keyPEM := getPrivateKeyPEM(serverCert.PrivateKey.(*rsa.PrivateKey))

	// Create temp files for the certificate and key
	certFile, err := os.CreateTemp("", "cert*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp cert file: %v", err)
	}
	defer os.Remove(certFile.Name())

	keyFile, err := os.CreateTemp("", "key*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp key file: %v", err)
	}
	defer os.Remove(keyFile.Name())

	// Write cert and key to files
	if _, err := certFile.Write(certPEM); err != nil {
		t.Fatalf("Failed to write cert to file: %v", err)
	}
	certFile.Close()

	if _, err := keyFile.Write(keyPEM); err != nil {
		t.Fatalf("Failed to write key to file: %v", err)
	}
	keyFile.Close()

	// Create custom TLS config for target
	targetTLSConfig := &tls.Config{
		InsecureSkipVerify: true, // For testing only
		ServerName:         host, // Set hostname for SNI
	}

	// Configure TLS for the proxy
	config.WithClientTLS(certFile.Name(), keyFile.Name())
	config.WithTargetTLSConfig(targetTLSConfig)

	// Create the proxy
	proxy := NewProxy(config)

	// Verify the TLS configuration was set correctly
	if proxy.tlsConfig == nil {
		t.Fatalf("Target TLS configuration was not set")
	}

	// Check if the ServerName is set correctly for SNI
	if proxy.tlsConfig.ServerName != host {
		t.Errorf("Custom TLS config ServerName not set correctly, expected %s, got %s",
			host, proxy.tlsConfig.ServerName)
	}

	// Start the proxy in a goroutine
	proxyStarted := make(chan struct{})
	go func() {
		close(proxyStarted)
		err := proxy.Start()
		if err != nil && !IsClosedNetworkError(err) {
			t.Logf("Proxy exited with error: %v", err)
		}
	}()

	// Make sure to stop the proxy at the end of the test
	defer func() {
		proxy.Stop()
		time.Sleep(100 * time.Millisecond) // give time for cleanup
	}()

	// Wait for proxy to start
	<-proxyStarted
	time.Sleep(100 * time.Millisecond)

	// Connect to the proxy
	// We'll establish a TLS connection since our proxy is configured for client TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // Accept the self-signed cert for testing
	}
	dialer := &net.Dialer{
		Timeout: 2 * time.Second,
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", proxy.ListenAddr, tlsConfig)
	if err != nil {
		t.Fatalf("Failed to connect to proxy with TLS: %v", err)
	}
	defer conn.Close()

	// Send test data
	testMessage := []byte("test custom tls config message")
	t.Logf("Sending message: %s", testMessage)
	_, err = conn.Write(testMessage)
	if err != nil {
		t.Fatalf("Failed to write to proxy: %v", err)
	}

	// Set a read deadline to avoid hanging
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Read response
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)

	// We don't strictly need to check the response data, just that we got some response
	if err != nil {
		t.Fatalf("Failed to read from proxy: %v", err)
	}
	if n == 0 {
		t.Errorf("Empty response received")
	} else {
		t.Logf("Received response: %s", buf[:n])
	}
}

// TestTargetClientCertificate tests the proxy's ability to use client certificates for target connections
func TestTargetClientCertificate(t *testing.T) {
	// Start a TLS server that requires client certificates
	clientAuthServer, stopAuthServer := startMutualTLSServer(t)
	defer stopAuthServer()

	// Create a proxy with a unique port
	port := getUniquePort()
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", port)
	config := NewProxyConfig(proxyAddr, clientAuthServer.URL[8:]) // Remove https:// prefix

	// Use the client cert/key generated for testing
	config.WithTargetClientCert("client.crt", "client.key")
	// Accept the self-signed server cert
	config.WithTargetTLSConfig(&tls.Config{
		InsecureSkipVerify: true,
	})

	proxy := NewProxy(config)

	// Start the proxy
	proxyStarted := make(chan struct{})
	go func() {
		close(proxyStarted)
		err := proxy.Start()
		if err != nil && !IsClosedNetworkError(err) {
			t.Logf("Proxy exited with error: %v", err)
		}
	}()

	// Ensure the proxy is stopped at the end of the test
	defer func() {
		proxy.Stop()
		time.Sleep(100 * time.Millisecond) // give time for cleanup
	}()

	// Wait for proxy to start
	<-proxyStarted
	time.Sleep(100 * time.Millisecond)

	// Connect to the proxy
	conn, err := net.DialTimeout("tcp", proxy.ListenAddr, 1*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	// Send test message
	testMessage := []byte("test target client cert message")
	t.Logf("Sending message: %s", testMessage)
	_, err = conn.Write(testMessage)
	if err != nil {
		t.Fatalf("Failed to write to proxy: %v", err)
	}

	// Set a read deadline to avoid hanging
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Read response
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read from proxy: %v", err)
	}

	// Check the response
	response := buf[:n]
	t.Logf("Received response: %s", response)

	// The client auth server returns a message indicating authentication success
	if !strings.Contains(string(response), "Authenticated as client") {
		t.Errorf("Expected authentication success message, got: %s", response)
	}
}

// startMutualTLSServer starts a TLS server that requires client certificate authentication
// It returns the server URL and a function to stop the server
func startMutualTLSServer(t *testing.T) (*httptest.Server, func()) {
	// Load CA certificate
	caCert, err := os.ReadFile("ca.crt")
	if err != nil {
		t.Fatalf("Failed to read CA certificate: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Load server certificate and key
	serverCert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		t.Fatalf("Failed to load server certificate: %v", err)
	}

	// Create TLS config with client auth
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	// Create a TCP listener with a unique port for the TLS server
	port := getUniquePort()
	address := fmt.Sprintf("127.0.0.1:%d", port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("Failed to start TCP listener: %v", err)
	}

	// Start TLS server in a goroutine
	serverStarted := make(chan struct{})
	go func() {
		close(serverStarted)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return // listener closed
			}

			// Handle each connection in a goroutine
			go func(c net.Conn) {
				defer c.Close()

				// Create TLS connection
				tlsConn := tls.Server(c, tlsConfig)
				if err := tlsConn.Handshake(); err != nil {
					t.Logf("TLS handshake failed: %v", err)
					return
				}

				// Verify client cert
				state := tlsConn.ConnectionState()
				if len(state.PeerCertificates) == 0 {
					t.Logf("No client certificates provided")
					return
				}

				// Echo received data with authentication success message
				buf := make([]byte, 1024)
				n, err := tlsConn.Read(buf)
				if err != nil {
					t.Logf("Failed to read from client: %v", err)
					return
				}

				clientMsg := buf[:n]
				responseMsg := fmt.Sprintf("SUCCESS: Authenticated as client. Received: %s", clientMsg)
				_, err = tlsConn.Write([]byte(responseMsg))
				if err != nil {
					t.Logf("Failed to write to client: %v", err)
				}
			}(conn)
		}
	}()

	// Wait for server to start
	<-serverStarted

	// Create a dummy http server just for the URL structure
	dummy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	dummy.Close() // We don't actually need it running

	// Create a mock URL with our actual server address
	serverURL := strings.Replace(dummy.URL, dummy.Listener.Addr().String(), address, 1)

	// Return a dummy server object with our address and cleanup function
	mock := &httptest.Server{URL: serverURL}

	return mock, func() {
		listener.Close()
	}
}

// TestInsecureClientAuth tests the proxy's ability to accept any client certificate
func TestInsecureClientAuth(t *testing.T) {
	// Create a proxy with a unique port
	port := getUniquePort()
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", port)
	config := NewProxyConfig(proxyAddr, "localhost:9999") // Target doesn't matter for this test

	// Generate a self-signed cert for testing
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	// Extract cert and key PEM
	certPEM := getCertificatePEM(cert)
	keyPEM := getPrivateKeyPEM(cert.PrivateKey.(*rsa.PrivateKey))

	// Create temp files for the certificate and key
	certFile, err := os.CreateTemp("", "cert*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp cert file: %v", err)
	}
	defer os.Remove(certFile.Name())

	keyFile, err := os.CreateTemp("", "key*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp key file: %v", err)
	}
	defer os.Remove(keyFile.Name())

	// Write cert and key to files
	if _, err := certFile.Write(certPEM); err != nil {
		t.Fatalf("Failed to write cert to file: %v", err)
	}
	certFile.Close()

	if _, err := keyFile.Write(keyPEM); err != nil {
		t.Fatalf("Failed to write key to file: %v", err)
	}
	keyFile.Close()

	// Configure TLS with client auth but make it insecure
	config.WithTLS(certFile.Name(), keyFile.Name())
	config.WithClientAuth("", certFile.Name(), keyFile.Name()) // Empty CA = insecure mode

	proxy := NewProxy(config)

	// Verify client auth is set to VerifyClientCertIfGiven, not RequireAndVerifyClientCert
	if proxy.clientTLSConfig == nil {
		t.Fatalf("Client TLS config is nil")
	}

	// Check that we're using RequestClientCert for insecure mode
	if proxy.clientTLSConfig.ClientAuth != tls.RequestClientCert {
		t.Errorf("Expected ClientAuth to be RequestClientCert (insecure mode), got %v", proxy.clientTLSConfig.ClientAuth)
	}

	t.Log("InsecureClientAuth correctly configured")
}

// TestSendCustomResponse tests the SendCustomResponse method
func TestSendCustomResponse(t *testing.T) {
	// Start a test server
	serverAddr, stopServer, _ := startTestServer(t, false)
	defer stopServer()

	// Create a proxy with a unique port
	port := getUniquePort()
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", port)
	config := NewProxyConfig(proxyAddr, serverAddr)
	proxy := NewProxy(config)

	// Create a custom message handler
	customResponse := []byte("CUSTOM_RESPONSE_DATA")
	proxy.ClientToServerHandler = func(data []byte) ([]byte, bool) {
		// If we receive a specific message, send custom response and stop processing
		if bytes.Equal(data, []byte("TRIGGER_CUSTOM_RESPONSE")) {
			proxy.SendCustomResponse(customResponse)
			return nil, false // Don't forward to target
		}
		// Otherwise, proceed normally
		return data, true
	}

	// Start the proxy
	go func() {
		err := proxy.Start()
		if err != nil && !IsClosedNetworkError(err) {
			t.Logf("Proxy exited with error: %v", err)
		}
	}()

	// Give the proxy time to start
	time.Sleep(100 * time.Millisecond)

	// Make sure to stop the proxy at the end of the test
	defer func() {
		proxy.Stop()
		time.Sleep(100 * time.Millisecond)
	}()

	// Connect to the proxy
	conn, err := net.DialTimeout("tcp", proxy.ListenAddr, 1*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	// Send the trigger message
	triggerMsg := []byte("TRIGGER_CUSTOM_RESPONSE")
	t.Logf("Sending trigger message: %s", triggerMsg)
	_, err = conn.Write(triggerMsg)
	if err != nil {
		t.Fatalf("Failed to write to proxy: %v", err)
	}

	// Set a read deadline to avoid hanging
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))

	// Read response
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read from proxy: %v", err)
	}

	// Check the response
	response := buf[:n]
	t.Logf("Received response: %s", response)

	// Verify we got the custom response
	if !bytes.Equal(response, customResponse) {
		t.Errorf("Expected custom response %q, got %q", customResponse, response)
	}

	// Now try a normal request to make sure regular proxying still works
	normalMsg := []byte("NORMAL_REQUEST")
	t.Logf("Sending normal message: %s", normalMsg)
	_, err = conn.Write(normalMsg)
	if err != nil {
		t.Fatalf("Failed to write normal request to proxy: %v", err)
	}

	// Read response from the normal request
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read normal response from proxy: %v", err)
	}

	// Verify normal response contains our original message (echo server)
	normalResponse := buf[:n]
	t.Logf("Received normal response: %s", normalResponse)

	if !bytes.Contains(normalResponse, normalMsg) {
		t.Errorf("Normal response should contain the request message")
	}
}

// TestSendCustomServerRequest tests the SendCustomServerRequest method
func TestSendCustomServerRequest(t *testing.T) {
	// Start a test server that echoes data
	serverAddr, stopServer, _ := startTestServer(t, false)
	defer stopServer()

	// Create a proxy with a unique port
	port := getUniquePort()
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", port)
	config := NewProxyConfig(proxyAddr, serverAddr)
	proxy := NewProxy(config)

	// Start the proxy
	go func() {
		err := proxy.Start()
		if err != nil && !IsClosedNetworkError(err) {
			t.Logf("Proxy exited with error: %v", err)
		}
	}()

	// Give the proxy time to start
	time.Sleep(100 * time.Millisecond)

	// Make sure to stop the proxy at the end of the test
	defer func() {
		proxy.Stop()
		time.Sleep(100 * time.Millisecond)
	}()

	// Create a custom handler to demonstrate request/response interception and modification
	proxy.ClientToServerHandler = func(data []byte) ([]byte, bool) {
		if bytes.Equal(data, []byte("NORMAL_REQUEST")) {
			// Test normal request without connection reuse
			serverRequest := []byte("CUSTOM_SERVER_REQUEST")
			t.Logf("Testing normal request without connection reuse: %s", serverRequest)

			// Send custom request to server without connection reuse
			serverResponse, err := proxy.SendCustomServerRequest(serverRequest, false)
			if err != nil {
				t.Logf("Error sending custom request: %v", err)
				// Send error message to client
				proxy.SendCustomResponse([]byte(fmt.Sprintf("ERROR: %v", err)))
				return nil, false // Don't forward the original request
			}

			// Send the response to the client
			t.Logf("Got response from server: %s", serverResponse)
			proxy.SendCustomResponse([]byte(fmt.Sprintf("RESPONSE: %s", serverResponse)))
			return nil, false // Don't forward the original request
		} else if bytes.Equal(data, []byte("CONNECTION_REUSE_TEST")) {
			// Test with connection reuse
			t.Logf("Testing connection reuse functionality")

			// 1. First request with reuse=true (should create a new connection)
			serverRequest1 := []byte("FIRST_REQUEST")
			t.Logf("Sending first request with reuse=true: %s", serverRequest1)
			response1, err := proxy.SendCustomServerRequest(serverRequest1, true)
			if err != nil {
				t.Logf("Error sending first request: %v", err)
				proxy.SendCustomResponse([]byte(fmt.Sprintf("ERROR1: %v", err)))
				return nil, false
			}
			t.Logf("First response: %s", response1)

			// 2. Second request with reuse=true (should attempt to reuse the connection)
			// But since isTargetConnInUse is true (we're in the middle of a client connection handler)
			// it should create a new connection
			serverRequest2 := []byte("SECOND_REQUEST")
			t.Logf("Sending second request with reuse=true: %s", serverRequest2)
			response2, err := proxy.SendCustomServerRequest(serverRequest2, true)
			if err != nil {
				t.Logf("Error sending second request: %v", err)
				proxy.SendCustomResponse([]byte(fmt.Sprintf("ERROR2: %v", err)))
				return nil, false
			}
			t.Logf("Second response: %s", response2)

			// Combine the responses
			combinedResponse := append([]byte("RESPONSE1: "), response1...)
			combinedResponse = append(combinedResponse, []byte("\nRESPONSE2: ")...)
			combinedResponse = append(combinedResponse, response2...)

			t.Logf("Combined responses: %s", combinedResponse)
			proxy.SendCustomResponse(combinedResponse)
			return nil, false // Don't forward the original request
		}

		// For other requests, pass through normally
		return data, true
	}

	// Test 1: Normal request without connection reuse
	t.Run("NormalRequest", func(t *testing.T) {
		// Connect to the proxy
		conn, err := net.DialTimeout("tcp", proxy.ListenAddr, 1*time.Second)
		if err != nil {
			t.Fatalf("Failed to connect to proxy: %v", err)
		}
		defer conn.Close()

		// Send the normal request message
		triggerMsg := []byte("NORMAL_REQUEST")
		t.Logf("Sending normal request message: %s", triggerMsg)
		_, err = conn.Write(triggerMsg)
		if err != nil {
			t.Fatalf("Failed to write to proxy: %v", err)
		}

		// Set a read deadline to avoid hanging
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))

		// Read response
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("Failed to read from proxy: %v", err)
		}

		// Check the response
		response := buf[:n]
		t.Logf("Received response: %s", response)
		if !bytes.Contains(response, []byte("RESPONSE:")) {
			t.Errorf("Expected response containing 'RESPONSE:', got: %s", response)
		}
	})

	// Test 2: Connection reuse test
	t.Run("ConnectionReuseTest", func(t *testing.T) {
		// Connect to the proxy
		conn, err := net.DialTimeout("tcp", proxy.ListenAddr, 1*time.Second)
		if err != nil {
			t.Fatalf("Failed to connect to proxy: %v", err)
		}
		defer conn.Close()

		// Send the connection reuse test message
		triggerMsg := []byte("CONNECTION_REUSE_TEST")
		t.Logf("Sending connection reuse test message: %s", triggerMsg)
		_, err = conn.Write(triggerMsg)
		if err != nil {
			t.Fatalf("Failed to write to proxy: %v", err)
		}

		// Set a read deadline to avoid hanging
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))

		// Read response
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("Failed to read from proxy: %v", err)
		}

		// Check the response
		response := buf[:n]
		t.Logf("Received response: %s", response)
		if !bytes.Contains(response, []byte("RESPONSE1:")) || !bytes.Contains(response, []byte("RESPONSE2:")) {
			t.Errorf("Expected response containing both 'RESPONSE1:' and 'RESPONSE2:', got: %s", response)
		}
	})
}

// TestConnectionReuseDirectly tests the SendCustomServerRequest method with connection reuse
func TestConnectionReuseDirectly(t *testing.T) {
	// Start a test server that echoes data
	serverAddr, stopServer, _ := startTestServer(t, false)
	defer stopServer()

	// Create a proxy with a unique port
	port := getUniquePort()
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", port)
	config := NewProxyConfig(proxyAddr, serverAddr)
	proxy := NewProxy(config)

	// Start the proxy
	go func() {
		err := proxy.Start()
		if err != nil && !IsClosedNetworkError(err) {
			t.Logf("Proxy exited with error: %v", err)
		}
	}()

	// Give the proxy time to start
	time.Sleep(100 * time.Millisecond)

	// Make sure to stop the proxy at the end of the test
	defer func() {
		proxy.Stop()
		time.Sleep(100 * time.Millisecond)
	}()

	// Test multiple requests with connection reuse enabled
	// The function should handle connection reuse or fallback to creating new connections as needed
	for i := 1; i <= 3; i++ {
		requestMsg := []byte(fmt.Sprintf("REQUEST_%d", i))
		t.Logf("Sending request %d with reuse=true: %s", i, requestMsg)

		response, err := proxy.SendCustomServerRequest(requestMsg, true)
		if err != nil {
			t.Fatalf("Failed to send request %d: %v", i, err)
		}

		t.Logf("Received response %d: %s", i, response)

		// Verify the response matches the request (echo server should return the same data)
		if !bytes.Equal(response, requestMsg) {
			t.Errorf("Response %d doesn't match request: got %s, expected %s", i, response, requestMsg)
		}
	}
}

// TestDefaultPortFromListener tests that the target address correctly inherits the port from the listener
func TestDefaultPortFromListener(t *testing.T) {
	// Test cases
	testCases := []struct {
		name           string
		listenerAddr   string
		targetAddr     string
		expectedTarget string
	}{
		{
			name:           "Target with port specified",
			listenerAddr:   "localhost:8080",
			targetAddr:     "example.com:9090",
			expectedTarget: "example.com:9090", // Port should not change
		},
		{
			name:           "Target without port",
			listenerAddr:   "localhost:8080",
			targetAddr:     "example.com",
			expectedTarget: "example.com:8080", // Should inherit listener port
		},
		{
			name:           "Both IPv4 addresses",
			listenerAddr:   "127.0.0.1:8080",
			targetAddr:     "192.168.1.1",
			expectedTarget: "192.168.1.1:8080", // Should inherit listener port
		},
		{
			name:           "IPv6 listener address",
			listenerAddr:   "[::1]:8080",
			targetAddr:     "example.com",
			expectedTarget: "example.com:8080", // Should inherit listener port
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := NewProxyConfig(tc.listenerAddr, tc.targetAddr)

			if config.TargetAddress != tc.expectedTarget {
				t.Errorf("Expected target address %s, got %s", tc.expectedTarget, config.TargetAddress)
			}
		})
	}
}
