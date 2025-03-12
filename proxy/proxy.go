package proxy

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"sync"
)

// Proxy represents a TCP proxy that can optionally support TLS
type Proxy struct {
	ListenAddr            string
	TargetAddr            string
	ClientToServerHandler func([]byte) ([]byte, bool)
	ServerToClientHandler func([]byte) ([]byte, bool)
	TLSConfig             *tls.Config
}

// NewProxy creates a new proxy instance with default handlers
func NewProxy(listenAddr, targetAddr string) *Proxy {
	return &Proxy{
		ListenAddr: listenAddr,
		TargetAddr: targetAddr,
		ClientToServerHandler: func(data []byte) ([]byte, bool) {
			return data, true // Default passthrough mode
		},
		ServerToClientHandler: func(data []byte) ([]byte, bool) {
			return data, true // Default passthrough mode
		},
	}
}

// Start begins accepting TCP connections and proxying them
func (p *Proxy) Start() error {
	listener, err := net.Listen("tcp", p.ListenAddr)
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
func (p *Proxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	serverConn, err := net.Dial("tcp", p.TargetAddr)
	if err != nil {
		log.Printf("Failed to connect to target: %v", err)
		return
	}
	defer serverConn.Close()

	// Create wait group to wait for both directions to complete
	var wg sync.WaitGroup
	wg.Add(2)

	// Client to server goroutine
	go func() {
		defer wg.Done()
		p.proxyData(clientConn, serverConn, p.ClientToServerHandler)
	}()

	// Server to client goroutine
	go func() {
		defer wg.Done()
		p.proxyData(serverConn, clientConn, p.ServerToClientHandler)
	}()

	// Wait for both directions to complete
	wg.Wait()
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

// ProxyError represents an error that occurred in the proxy
type ProxyError struct {
	message string
}

func (e *ProxyError) Error() string {
	return e.message
}
