package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	// Setup logging
	log.SetOutput(os.Stdout)
	log.SetPrefix("[TCP/TLS Proxy] ")

	// Custom usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "TCP/TLS Proxy - A flexible TCP proxy with TLS support\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")

		// Print all flags with help text
		flag.PrintDefaults()

		// Example usage
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Basic usage - Proxy to Google with default settings\n")
		fmt.Fprintf(os.Stderr, "  %s\n\n", os.Args[0])

		fmt.Fprintf(os.Stderr, "  # Connect to a different target website\n")
		fmt.Fprintf(os.Stderr, "  %s -target-host example.com\n\n", os.Args[0])

		fmt.Fprintf(os.Stderr, "  # Enable client TLS (require TLS from clients)\n")
		fmt.Fprintf(os.Stderr, "  %s -client-tls -server-cert mycert.crt -server-key mykey.key\n\n", os.Args[0])

		fmt.Fprintf(os.Stderr, "  # Production-ready secure configuration\n")
		fmt.Fprintf(os.Stderr, "  %s -target-host api.example.com -insecure=false -client-tls -client-auth -ca-cert ca.crt -server-cert server.crt -server-key server.key\n\n", os.Args[0])

		fmt.Fprintf(os.Stderr, "  # Verbose logging mode\n")
		fmt.Fprintf(os.Stderr, "  %s -v\n\n", os.Args[0])

		fmt.Fprintf(os.Stderr, "Proxy ports:\n")
		fmt.Fprintf(os.Stderr, "  • TCP Proxy: :8416 (plain TCP listener)\n")
		fmt.Fprintf(os.Stderr, "  • TLS Proxy: :8450 (optionally requires TLS from clients)\n\n")

		fmt.Fprintf(os.Stderr, "For more details and advanced configuration, visit: https://github.com/yourusername/tcp-override-proxy\n")
	}

	// Command line flags
	verbose := flag.Bool("v", false, "Enable verbose logging of data transfers and connection details")
	requireClientCert := flag.Bool("client-auth", false, "Require client certificate authentication (mutual TLS)")
	caFile := flag.String("ca-cert", "ca.crt", "CA certificate file for verifying client certificates")
	serverCert := flag.String("server-cert", "server.crt", "Server certificate file for TLS connections")
	serverKey := flag.String("server-key", "server.key", "Server private key file for TLS connections")
	targetUseTLS := flag.Bool("target-tls", true, "Use TLS when connecting to target server (set to false for plain TCP targets)")
	insecureSkipVerify := flag.Bool("insecure", true, "Skip verification of target server TLS certificates (set to false in production)")
	targetHost := flag.String("target-host", "www.google.com", "Target hostname to connect to (used for both connection and SNI)")
	useClientTLS := flag.Bool("client-tls", false, "Require clients to use TLS when connecting to the proxy")
	flag.Parse()

	// Fixed configuration for TCP proxy
	tcpListenAddr := ":8416"
	tcpTargetAddr := *targetHost + ":443" // Default target, using the target host from flags

	// Fixed configuration for TLS proxy
	tlsListenAddr := ":8450"
	tlsTargetAddr := *targetHost + ":443" // Default target, using the target host from flags

	log.Printf("Starting TCP proxy: %s -> %s", tcpListenAddr, tcpTargetAddr)
	log.Printf("Starting TLS proxy: %s -> %s (Target TLS: %v)", tlsListenAddr, tlsTargetAddr, *targetUseTLS)

	// Create reusable TLS configuration for target connections
	targetTLSConfig := &tls.Config{
		InsecureSkipVerify: *insecureSkipVerify, // Based on command line flag
		ServerName:         *targetHost,         // Use target hostname for SNI
	}

	// Create the TCP proxy with default passthrough mode
	tcpProxyConfig := NewProxyConfig(tcpListenAddr, tcpTargetAddr)

	// Configure the TCP proxy to use TLS for target connections if needed
	if *targetUseTLS {
		log.Printf("Enabling TLS for TCP proxy connecting to %s", tcpTargetAddr)
		tcpProxyConfig.WithTargetTLSConfig(targetTLSConfig)
	}

	tcpProxy := NewProxy(tcpProxyConfig)

	// Create the TLS proxy with TLS configuration
	tlsProxyConfig := NewProxyConfig(tlsListenAddr, tlsTargetAddr)

	// Configure client-side TLS only if requested
	if *useClientTLS {
		log.Printf("Configuring TLS proxy to use TLS for client connections with certificates: %s, %s", *serverCert, *serverKey)
		tlsProxyConfig.WithClientTLS(*serverCert, *serverKey)
	} else {
		log.Printf("TLS proxy will accept plain TCP connections from clients")
	}

	// Configure target-side TLS if specified (proxy to target server)
	if *targetUseTLS {
		log.Printf("Enabling TLS for TLS proxy connecting to target server: %s", tlsTargetAddr)
		tlsProxyConfig.WithTargetTLSConfig(targetTLSConfig)
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
