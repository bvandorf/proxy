package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ProxyConfig contains configuration options for the proxy
type ProxyConfig struct {
	// Basic connection settings
	ListenerAddress string // Address to listen on (e.g., "localhost:8080")
	TargetAddress   string // Address to forward traffic to (e.g., "example.com:443")

	// Connection type settings
	ClientTLS bool // Whether clients should use TLS to connect to proxy
	TargetTLS bool // Whether the proxy should use TLS to connect to target

	// TLS configuration for client-to-proxy connections
	ServerCertFile string // Path to server certificate file for client-proxy TLS
	ServerKeyFile  string // Path to server key file for client-proxy TLS
	CACertFile     string // Path to CA certificate file for client verification

	// TLS configuration for proxy-to-target connections
	TargetTLSConfig      *tls.Config // Custom TLS configuration for proxy-to-target
	TargetClientCertFile string      // Path to client certificate file for proxy-target TLS
	TargetClientKeyFile  string      // Path to client key file for proxy-target TLS

	// Client authentication
	ClientAuth bool // Whether client certificate authentication is required

	// Timeouts
	DialTimeout time.Duration // Timeout for establishing connections to target
}

// NewProxyConfig creates a default proxy configuration
func NewProxyConfig(listenerAddr, targetAddr string) *ProxyConfig {
	// Check if target address has a port specified
	host, _, err := net.SplitHostPort(targetAddr)
	if err != nil {
		// If there's an error, it might be because no port was specified
		// Check if the error indicates missing port
		if strings.Contains(err.Error(), "missing port") {
			// No port specified, use the host as is
			host = targetAddr

			// Extract port from listener address
			_, listenerPort, listenerErr := net.SplitHostPort(listenerAddr)
			if listenerErr == nil {
				// Use the listener port for the target
				targetAddr = net.JoinHostPort(host, listenerPort)
				log.Printf("No port specified in target address. Using listener port %s -> %s", host, targetAddr)
			} else {
				log.Printf("Warning: Could not determine port from listener address: %v", listenerErr)
			}
		} else {
			// Some other error occurred
			log.Printf("Warning: Invalid target address format: %v", err)
		}
	}

	return &ProxyConfig{
		ListenerAddress: listenerAddr,
		TargetAddress:   targetAddr,
		ClientTLS:       false,
		TargetTLS:       false,
		ClientAuth:      false,
		DialTimeout:     10 * time.Second,
	}
}

// WithClientTLS configures the proxy to use TLS for client-to-proxy connections
func (c *ProxyConfig) WithClientTLS(serverCertFile, serverKeyFile string) *ProxyConfig {
	c.ClientTLS = true
	c.ServerCertFile = serverCertFile
	c.ServerKeyFile = serverKeyFile
	return c
}

// WithTargetTLS configures the proxy to use TLS for proxy-to-target connections
func (c *ProxyConfig) WithTargetTLS() *ProxyConfig {
	c.TargetTLS = true
	return c
}

// WithTargetTLSConfig configures the proxy to use a specific TLS configuration
// for proxy-to-target connections
func (c *ProxyConfig) WithTargetTLSConfig(config *tls.Config) *ProxyConfig {
	c.TargetTLS = true
	c.TargetTLSConfig = config
	return c
}

// WithTargetClientCert configures the proxy to use a client certificate when connecting to the target server
// This is useful when the target server requires client certificate authentication
func (c *ProxyConfig) WithTargetClientCert(certFile, keyFile string) *ProxyConfig {
	c.TargetTLS = true
	c.TargetClientCertFile = certFile
	c.TargetClientKeyFile = keyFile
	return c
}

// WithTLS configures the proxy to use TLS for both client-to-proxy and proxy-to-target connections
func (c *ProxyConfig) WithTLS(serverCertFile, serverKeyFile string) *ProxyConfig {
	c.WithClientTLS(serverCertFile, serverKeyFile)
	c.WithTargetTLS()
	return c
}

// WithClientAuth configures the proxy to require client certificate authentication
func (c *ProxyConfig) WithClientAuth(caCertFile, serverCertFile, serverKeyFile string) *ProxyConfig {
	c.ClientAuth = true
	c.CACertFile = caCertFile
	c.ServerCertFile = serverCertFile
	c.ServerKeyFile = serverKeyFile
	return c
}

// WithInsecureClientAuth configures the proxy to require client certificates but accept any certificate
// This is useful for testing but should not be used in production
func (c *ProxyConfig) WithInsecureClientAuth(serverCertFile, serverKeyFile string) *ProxyConfig {
	c.ClientAuth = true
	c.CACertFile = "" // No CA cert means we won't validate against a specific CA
	c.ServerCertFile = serverCertFile
	c.ServerKeyFile = serverKeyFile
	return c
}

// WithDialTimeout sets the timeout for establishing connections to the target
func (c *ProxyConfig) WithDialTimeout(timeout time.Duration) *ProxyConfig {
	c.DialTimeout = timeout
	return c
}

// Proxy represents a TCP proxy that can optionally support TLS
type Proxy struct {
	ListenAddr            string
	TargetAddr            string
	ClientToServerHandler func([]byte) ([]byte, bool)
	ServerToClientHandler func([]byte) ([]byte, bool)
	TLSConfig             *tls.Config // TLS config for StartTLS method

	// Internal fields for connection management
	config          *ProxyConfig
	listener        net.Listener
	active          atomic.Bool
	wg              sync.WaitGroup
	tlsConfig       *tls.Config // TLS config for proxy-to-server
	clientTLSConfig *tls.Config // TLS config for client-to-proxy

	// For custom response handling
	currentClientConn net.Conn
	currentTargetConn net.Conn   // Track current target connection for possible reuse
	isTargetConnInUse bool       // Flag indicating if the target connection is being used for proxying
	connMutex         sync.Mutex // Mutex for safe access to connections
}

// NewProxy creates a new proxy instance with the given configuration
func NewProxy(config *ProxyConfig) *Proxy {
	proxy := &Proxy{
		ListenAddr: config.ListenerAddress,
		TargetAddr: config.TargetAddress,
		config:     config,
		ClientToServerHandler: func(data []byte) ([]byte, bool) {
			return data, true // Default passthrough mode
		},
		ServerToClientHandler: func(data []byte) ([]byte, bool) {
			return data, true // Default passthrough mode
		},
	}

	// Apply target TLS configuration if specified
	if config.TargetTLS {
		// Use custom TLS config if provided, otherwise create a default one
		var targetTLSConfig *tls.Config

		if config.TargetTLSConfig != nil {
			targetTLSConfig = config.TargetTLSConfig.Clone()
		} else {
			// Configure proxy-to-target TLS with a default config
			targetTLSConfig = &tls.Config{
				InsecureSkipVerify: true, // Note: In production, this should be false
			}
		}

		// If target client certificates are provided, load and add them
		if config.TargetClientCertFile != "" && config.TargetClientKeyFile != "" {
			// Load client certificate
			clientCert, err := tls.LoadX509KeyPair(config.TargetClientCertFile, config.TargetClientKeyFile)
			if err != nil {
				log.Printf("Warning: Failed to load target client certificate: %v", err)
			} else {
				// Add the client certificate to the config
				targetTLSConfig.Certificates = append(targetTLSConfig.Certificates, clientCert)
				log.Printf("Target client certificate loaded successfully for proxy-to-target authentication")
			}
		}

		proxy.tlsConfig = targetTLSConfig
	}

	// Apply client TLS and authentication settings if specified
	if config.ClientTLS || config.ClientAuth {
		err := proxy.setupClientTLS()
		if err != nil {
			log.Printf("Warning: Failed to set up client TLS: %v", err)
		}
	}

	return proxy
}

// setupClientTLS configures TLS for client-to-proxy connections
func (p *Proxy) setupClientTLS() error {
	// Check if we have the server certificate and key
	if p.config.ServerCertFile == "" || p.config.ServerKeyFile == "" {
		return fmt.Errorf("missing server certificate or key file for client TLS")
	}

	// Load server certificate
	serverCert, err := tls.LoadX509KeyPair(p.config.ServerCertFile, p.config.ServerKeyFile)
	if err != nil {
		return fmt.Errorf("failed to load server certificate: %w", err)
	}

	// Create basic TLS config
	clientTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	// If client authentication is required, set it up
	if p.config.ClientAuth {
		if p.config.CACertFile == "" {
			// Insecure mode - require client cert but don't verify it against a CA
			log.Printf("Warning: Using insecure client authentication mode - client certificates will be requested but not verified")
			clientTLSConfig.ClientAuth = tls.RequestClientCert
		} else {
			// Secure mode - require and verify client cert against CA
			// Read CA certificate for client verification
			caCert, err := os.ReadFile(p.config.CACertFile)
			if err != nil {
				return fmt.Errorf("failed to read CA certificate: %w", err)
			}

			// Create CA certificate pool and add our CA certificate
			caCertPool := x509.NewCertPool()
			if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
				return fmt.Errorf("failed to add CA certificate to pool")
			}

			// Configure client authentication
			clientTLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
			clientTLSConfig.ClientCAs = caCertPool
		}
	}

	// Apply the configuration
	p.clientTLSConfig = clientTLSConfig

	return nil
}

// Start begins accepting connections and proxying them
func (p *Proxy) Start() error {
	// Set the active flag
	p.active.Store(true)

	// Create listener - regular TCP or TLS based on configuration
	var listener net.Listener
	var err error

	if p.config.ClientTLS {
		// Set up TLS listener for client connections
		if p.clientTLSConfig == nil {
			return fmt.Errorf("client TLS configuration is missing")
		}
		listener, err = tls.Listen("tcp", p.ListenAddr, p.clientTLSConfig)
	} else {
		// Regular TCP listener
		listener, err = net.Listen("tcp", p.ListenAddr)
	}

	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}
	p.listener = listener

	// Accept connections
	for p.active.Load() {
		conn, err := p.listener.Accept()
		if err != nil {
			if IsClosedNetworkError(err) {
				return nil // Listener was closed, exit gracefully
			}
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		p.wg.Add(1)
		go func(clientConn net.Conn) {
			defer p.wg.Done()
			defer clientConn.Close()

			if err := p.handleConnection(clientConn); err != nil {
				fmt.Printf("Error handling client connection: %v\n", err)
			}
		}(conn)
	}

	return nil
}

// IsClosedNetworkError checks if an error is due to a closed network connection
func IsClosedNetworkError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "use of closed network connection") ||
		strings.Contains(err.Error(), "accept tcp: use of closed network connection")
}

// StartTLS begins accepting TLS connections and proxying them
func (p *Proxy) StartTLS() error {
	if p.TLSConfig == nil {
		return &ProxyError{message: "TLS configuration is missing"}
	}

	listener, err := tls.Listen("tcp", p.ListenAddr, p.TLSConfig)
	if err != nil {
		return err
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go p.handleConnection(conn)
	}
}

// handleConnection manages the proxy between client and server
func (p *Proxy) handleConnection(clientConn net.Conn) error {
	// Store the client connection for potential custom responses
	p.connMutex.Lock()
	p.currentClientConn = clientConn
	p.currentTargetConn = nil // Reset target connection at start of new client connection
	p.connMutex.Unlock()

	// Make sure to clear the client connection reference when we're done
	defer func() {
		p.connMutex.Lock()
		if p.currentClientConn == clientConn {
			p.currentClientConn = nil
		}
		p.connMutex.Unlock()
	}()

	// Connect to target
	var targetConn net.Conn
	var err error

	// Create a dialer with the configured timeout
	dialer := &net.Dialer{
		Timeout: p.config.DialTimeout,
	}

	// Extract hostname from target address for SNI if needed
	host, _, err := net.SplitHostPort(p.TargetAddr)
	if err != nil {
		// If splitting fails, use the whole target address
		host = p.TargetAddr
	}

	// If using TLS to connect to target
	if p.tlsConfig != nil {
		// Create a copy of the TLS config to ensure we don't modify the original
		tlsConfig := p.tlsConfig.Clone()

		// Set the ServerName for SNI if not already set
		if tlsConfig.ServerName == "" {
			tlsConfig.ServerName = host
		}

		// Establish TLS connection to target
		targetConn, err = tls.DialWithDialer(dialer, "tcp", p.TargetAddr, tlsConfig)
	} else {
		targetConn, err = dialer.Dial("tcp", p.TargetAddr)
	}

	if err != nil {
		return fmt.Errorf("failed to connect to target: %w", err)
	}
	defer targetConn.Close()

	// Store the target connection for potential reuse
	p.connMutex.Lock()
	p.currentTargetConn = targetConn
	p.isTargetConnInUse = true // Mark connection as in use for proxying
	p.connMutex.Unlock()

	// Make sure to clear the target connection when done
	defer func() {
		p.connMutex.Lock()
		if p.currentTargetConn == targetConn {
			p.currentTargetConn = nil
			p.isTargetConnInUse = false // Mark as no longer in use
		}
		p.connMutex.Unlock()
	}()

	// Create wait group to wait for both directions to complete
	var wg sync.WaitGroup
	wg.Add(2)

	// Client to server goroutine
	go func() {
		defer wg.Done()
		p.proxyData(clientConn, targetConn, p.ClientToServerHandler)
	}()

	// Server to client goroutine
	go func() {
		defer wg.Done()
		p.proxyData(targetConn, clientConn, p.ServerToClientHandler)
	}()

	// Wait for both directions to complete
	wg.Wait()

	return nil
}

// proxyData handles the actual data transfer with transformation
func (p *Proxy) proxyData(src, dst net.Conn, handler func([]byte) ([]byte, bool)) {
	buffer := make([]byte, 4096)

	for {
		n, err := src.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Printf("Read error: %v", err)
			}
			break
		}

		if n > 0 {
			data := buffer[:n]

			// Apply handler to transform data
			transformedData, forward := handler(data)
			if !forward {
				// Handler indicated not to forward this data
				continue
			}

			_, err := dst.Write(transformedData)
			if err != nil {
				log.Printf("Write error: %v", err)
				break
			}
		}
	}
}

// EnableTLS configures the proxy to use TLS for the connections
// serverConfig is for proxy-to-server connection
// clientConfig is for client-to-proxy connection
func (p *Proxy) EnableTLS(serverConfig *tls.Config, clientConfig *tls.Config) {
	p.tlsConfig = serverConfig
	p.clientTLSConfig = clientConfig
}

// EnableClientCertAuth configures the proxy to require and verify client certificates
// caFile is the path to the CA certificate used to verify client certificates
func (p *Proxy) EnableClientCertAuth(caFile string) error {
	// Read the CA certificate
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}

	// Create a certificate pool and add the CA certificate
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		return fmt.Errorf("failed to append CA certificate to pool")
	}

	// If no client TLS config exists yet, create one
	if p.clientTLSConfig == nil {
		// Need at least one server certificate
		cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
		if err != nil {
			return fmt.Errorf("failed to load server certificate: %w", err)
		}

		p.clientTLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	}

	// Configure client authentication
	p.clientTLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
	p.clientTLSConfig.ClientCAs = caCertPool

	return nil
}

// Stop gracefully stops the proxy server
func (p *Proxy) Stop() {
	if p.active.CompareAndSwap(true, false) {
		if p.listener != nil {
			p.listener.Close()
		}
		p.wg.Wait()
	}
}

// ProxyError represents an error that occurred in the proxy
type ProxyError struct {
	message string
}

func (e *ProxyError) Error() string {
	return e.message
}

// SendCustomResponse sends a custom response directly to the client
// This is useful for intercepting requests and providing custom responses
// without forwarding to the target server.
func (p *Proxy) SendCustomResponse(data []byte) error {
	// Get the current client connection
	p.connMutex.Lock()
	defer p.connMutex.Unlock()

	if p.currentClientConn == nil {
		return fmt.Errorf("no active client connection")
	}

	// Send the custom response directly to the client
	_, err := p.currentClientConn.Write(data)
	return err
}

// SendCustomServerRequest sends a custom request to the target server
// and returns the response. If reuseConnection is true, it will try to reuse
// an existing connection if available and not already in use by the proxy.
func (p *Proxy) SendCustomServerRequest(request []byte, reuseConnection bool) ([]byte, error) {
	var targetConn net.Conn
	var err error
	var ownConnection bool = false

	// Check if we can reuse an existing connection
	if reuseConnection {
		p.connMutex.Lock()
		if p.currentTargetConn != nil && !p.isTargetConnInUse {
			// We can reuse the existing connection
			targetConn = p.currentTargetConn
			log.Println("Reusing existing target connection for custom request")
		}
		p.connMutex.Unlock()

		// Verify the connection is still valid if we're trying to reuse it
		if targetConn != nil {
			// Send a test write with a short timeout to see if the connection is still alive
			err = targetConn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
			if err != nil {
				log.Println("Failed to set write deadline on reused connection, creating new one:", err)
				targetConn = nil // Reset to create a new connection
			} else {
				// Try to write 0 bytes as a quick connection test
				_, err = targetConn.Write([]byte{})
				if err != nil {
					log.Println("Reused connection appears to be invalid, creating new one:", err)
					targetConn = nil // Reset to create a new connection
				}
			}
		}
	}

	// If we don't have a connection yet, create a new one
	if targetConn == nil {
		// Connect to target
		ownConnection = true
		log.Println("Creating new target connection for custom request")

		// Create a dialer with the configured timeout
		dialer := &net.Dialer{
			Timeout: p.config.DialTimeout,
		}

		// Extract hostname from target address for SNI if needed
		host, _, err := net.SplitHostPort(p.TargetAddr)
		if err != nil {
			// If splitting fails, use the whole target address
			host = p.TargetAddr
		}

		// If using TLS to connect to target
		if p.tlsConfig != nil {
			// Create a copy of the TLS config to ensure we don't modify the original
			tlsConfig := p.tlsConfig.Clone()

			// Set the ServerName for SNI if not already set
			if tlsConfig.ServerName == "" {
				tlsConfig.ServerName = host
			}

			// Establish TLS connection to target
			targetConn, err = tls.DialWithDialer(dialer, "tcp", p.TargetAddr, tlsConfig)
		} else {
			targetConn, err = dialer.Dial("tcp", p.TargetAddr)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to connect to target for custom request: %w", err)
		}

		// Close the connection when we're done if we created it
		if ownConnection {
			defer targetConn.Close()
		}
	}

	// Send request to target
	_, err = targetConn.Write(request)
	if err != nil {
		if !ownConnection {
			// If we're reusing a connection and the write fails, try once more with a new connection
			log.Println("Write to reused connection failed, retrying with new connection:", err)

			// Create a new connection and try again
			var newConn net.Conn
			if p.tlsConfig != nil {
				newConn, err = tls.Dial("tcp", p.TargetAddr, p.tlsConfig)
			} else {
				newConn, err = net.Dial("tcp", p.TargetAddr)
			}

			if err != nil {
				return nil, fmt.Errorf("failed to create new connection after write failure: %w", err)
			}
			defer newConn.Close()

			// Try the write again
			_, err = newConn.Write(request)
			if err != nil {
				return nil, fmt.Errorf("failed to send request on new connection: %w", err)
			}

			// Use the new connection for reading the response
			targetConn = newConn
		} else {
			return nil, fmt.Errorf("failed to send request to target: %w", err)
		}
	}

	// Read response from target
	responseBuffer := bytes.NewBuffer(nil)
	buffer := make([]byte, 4096)

	for {
		// Set a read deadline to avoid waiting forever
		err = targetConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if err != nil {
			return nil, fmt.Errorf("failed to set read deadline: %w", err)
		}

		n, err := targetConn.Read(buffer)
		if err != nil {
			if err == io.EOF {
				break
			}
			// If a timeout occurred and we have some data, we can return it
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() && responseBuffer.Len() > 0 {
				log.Println("Read timeout occurred, but we have some data to return")
				break
			}

			// If we're reusing a connection and the read fails, try once more with a new connection
			if !ownConnection && responseBuffer.Len() == 0 {
				log.Println("Read from reused connection failed, retrying with new connection:", err)

				// Create a new connection and try again
				var newConn net.Conn
				if p.tlsConfig != nil {
					newConn, err = tls.Dial("tcp", p.TargetAddr, p.tlsConfig)
				} else {
					newConn, err = net.Dial("tcp", p.TargetAddr)
				}

				if err != nil {
					return nil, fmt.Errorf("failed to create new connection after read failure: %w", err)
				}
				defer newConn.Close()

				// Try the write again
				_, err = newConn.Write(request)
				if err != nil {
					return nil, fmt.Errorf("failed to send request on new connection: %w", err)
				}

				// Read the response from the new connection
				n, err = newConn.Read(buffer)
				if err != nil && err != io.EOF {
					return nil, fmt.Errorf("failed to read from new connection: %w", err)
				}

				responseBuffer.Write(buffer[:n])
				break
			}

			return nil, fmt.Errorf("failed to read response from target server: %w", err)
		}

		responseBuffer.Write(buffer[:n])

		// For non-streaming protocols like HTTP, we might want to detect when a response is complete
		// This is a simple implementation that assumes the entire response comes in a single read
		// For HTTP, parsing the Content-Length header would be more accurate
		if n < len(buffer) {
			break
		}
	}

	return responseBuffer.Bytes(), nil
}
