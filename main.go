package main

import (
	"flag"
	"log"
	"os"
)

func main() {
	// Setup logging
	log.SetOutput(os.Stdout)
	log.SetPrefix("[TCP/TLS Proxy] ")

	// Command line flags
	verbose := flag.Bool("v", false, "Verbose logging of data")
	requireClientCert := flag.Bool("client-auth", false, "Require client certificate authentication")
	caFile := flag.String("ca-cert", "ca.crt", "CA certificate file for client authentication")
	serverCert := flag.String("server-cert", "server.crt", "Server certificate file")
	serverKey := flag.String("server-key", "server.key", "Server key file")
	targetUseTLS := flag.Bool("target-tls", false, "Whether the target server uses TLS")
	flag.Parse()

	// Fixed configuration for TCP proxy
	tcpListenAddr := ":8416"
	tcpTargetAddr := "localhost:8080" // Default target, adjust as needed

	// Fixed configuration for TLS proxy
	tlsListenAddr := ":8450"
	tlsTargetAddr := "localhost:8080" // Default target, adjust as needed

	log.Printf("Starting TCP proxy: %s -> %s", tcpListenAddr, tcpTargetAddr)
	log.Printf("Starting TLS proxy: %s -> %s (Target TLS: %v)", tlsListenAddr, tlsTargetAddr, *targetUseTLS)

	// Create the TCP proxy with default passthrough mode
	tcpProxyConfig := NewProxyConfig(tcpListenAddr, tcpTargetAddr)
	tcpProxy := NewProxy(tcpProxyConfig)

	// Create the TLS proxy with TLS configuration
	tlsProxyConfig := NewProxyConfig(tlsListenAddr, tlsTargetAddr)

	// Configure client-side TLS (client to proxy)
	tlsProxyConfig.WithClientTLS(*serverCert, *serverKey)

	// Configure target-side TLS if specified (proxy to target server)
	if *targetUseTLS {
		log.Printf("Enabling TLS for connection to target server")
		tlsProxyConfig.WithTargetTLS()
	}

	// Set up client certificate authentication if requested
	if *requireClientCert {
		log.Printf("Enabling client certificate authentication using CA: %s", *caFile)
		tlsProxyConfig.WithClientAuth(*caFile, *serverCert, *serverKey)
	}

	// Create the TLS proxy with the configuration
	tlsProxy := NewProxy(tlsProxyConfig)

	// Add verbose logging if requested
	if *verbose {
		log.Println("Verbose logging enabled")
		tcpProxy.ClientToServerHandler = func(data []byte) ([]byte, bool) {
			log.Printf("TCP -> Client to server: %d bytes", len(data))
			return data, true
		}
		tcpProxy.ServerToClientHandler = func(data []byte) ([]byte, bool) {
			log.Printf("TCP -> Server to client: %d bytes", len(data))
			return data, true
		}

		tlsProxy.ClientToServerHandler = func(data []byte) ([]byte, bool) {
			log.Printf("TLS -> Client to server: %d bytes", len(data))
			return data, true
		}
		tlsProxy.ServerToClientHandler = func(data []byte) ([]byte, bool) {
			log.Printf("TLS -> Server to client: %d bytes", len(data))
			return data, true
		}
	}

	// Start the TCP proxy in a goroutine
	go func() {
		if err := tcpProxy.Start(); err != nil {
			log.Fatalf("TCP proxy error: %v", err)
		}
	}()

	// Start the TLS proxy in the main thread
	log.Println("Starting TLS proxy...")
	if err := tlsProxy.Start(); err != nil {
		log.Fatalf("TLS proxy error: %v", err)
	}
}
