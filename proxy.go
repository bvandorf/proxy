package main

import (
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

	// TLS configuration
	ServerCertFile string // Path to server certificate file for client-proxy TLS
	ServerKeyFile  string // Path to server key file for client-proxy TLS
	CACertFile     string // Path to CA certificate file for client verification

	// Client authentication
	ClientAuth bool // Whether client certificate authentication is required

	// Timeouts
	DialTimeout time.Duration // Timeout for establishing connections to target
}

// NewProxyConfig creates a default proxy configuration
func NewProxyConfig(listenerAddr, targetAddr string) *ProxyConfig {
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
		// Configure proxy-to-target TLS
		targetTLSConfig := &tls.Config{
			InsecureSkipVerify: true, // Note: In production, this should be false
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
			return fmt.Errorf("missing CA certificate file for client authentication")
		}

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
	// Connect to target
	var targetConn net.Conn
	var err error

	// Create a dialer with the configured timeout
	dialer := &net.Dialer{
		Timeout: p.config.DialTimeout,
	}

	// If using TLS to connect to target
	if p.tlsConfig != nil {
		targetConn, err = tls.DialWithDialer(dialer, "tcp", p.TargetAddr, p.tlsConfig)
	} else {
		targetConn, err = dialer.Dial("tcp", p.TargetAddr)
	}

	if err != nil {
		return fmt.Errorf("failed to connect to target: %w", err)
	}
	defer targetConn.Close()

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
