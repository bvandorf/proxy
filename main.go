package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

// setupLogging configures logging to write to both stdout and a log file if specified
func setupLogging(logFile string) (*os.File, error) {
	// Always set prefix for consistent logging
	log.SetPrefix("[TCP/TLS Proxy] ")

	if logFile == "" {
		// If no log file specified, just log to stdout
		log.SetOutput(os.Stdout)
		return nil, nil
	}

	// Open the log file (create if doesn't exist, append if it does)
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %v", err)
	}

	// Create a multi-writer to write to both stdout and the file
	multiWriter := io.MultiWriter(os.Stdout, file)
	log.SetOutput(multiWriter)

	return file, nil
}

func main() {
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

		fmt.Fprintf(os.Stderr, "  # Connect to a different target with custom port\n")
		fmt.Fprintf(os.Stderr, "  %s -target-host example.com:8443 -port 8080 -log-file proxy.log\n\n", os.Args[0])

		fmt.Fprintf(os.Stderr, "  # Connect to a target using same port as listener (port inheritance)\n")
		fmt.Fprintf(os.Stderr, "  %s -target-host example.com -port 8080 # Will connect to example.com:8080\n\n", os.Args[0])

		fmt.Fprintf(os.Stderr, "  # Enable client TLS with verbose logging to file\n")
		fmt.Fprintf(os.Stderr, "  %s -client-tls -server-cert mycert.crt -server-key mykey.key -log-file verbose.log\n\n", os.Args[0])

		fmt.Fprintf(os.Stderr, "  # Client authentication with insecure mode\n")
		fmt.Fprintf(os.Stderr, "  %s -client-tls -client-auth -insecure-client -ca-cert ca.crt -server-cert server.crt -server-key server.key\n\n", os.Args[0])

		fmt.Fprintf(os.Stderr, "  # Using client certificate for target server authentication (mutual TLS with target)\n")
		fmt.Fprintf(os.Stderr, "  %s -target-client-cert client.crt -target-client-key client.key -target-host secure-api.example.com\n\n", os.Args[0])

		fmt.Fprintf(os.Stderr, "  # Production-ready secure configuration with logging\n")
		fmt.Fprintf(os.Stderr, "  %s -target-host api.example.com -insecure=false -client-tls -client-auth -ca-cert ca.crt -server-cert server.crt -server-key server.key -log-file prod.log\n\n", os.Args[0])
	}

	// Command line flags
	port := flag.Int("port", 8080, "Port to listen on for proxy connections")
	requireClientCert := flag.Bool("client-auth", false, "Require client certificate authentication (mutual TLS)")
	insecureClient := flag.Bool("insecure-client", false, "Accept any client certificate when client authentication is enabled")
	caFile := flag.String("ca-cert", "ca.crt", "CA certificate file for verifying client certificates")
	serverCert := flag.String("server-cert", "server.crt", "Server certificate file for TLS connections")
	serverKey := flag.String("server-key", "server.key", "Server private key file for TLS connections")
	targetUseTLS := flag.Bool("target-tls", true, "Use TLS when connecting to target server (set to false for plain TCP targets)")
	insecureSkipVerify := flag.Bool("insecure", true, "Skip verification of target server TLS certificates (set to false in production)")
	targetHost := flag.String("target-host", "www.google.com", "Target hostname to connect to (with optional port, e.g., 'example.com:443')")
	targetClientCert := flag.String("target-client-cert", "", "Client certificate file to use when connecting to the target server (for mutual TLS)")
	targetClientKey := flag.String("target-client-key", "", "Client key file to use when connecting to the target server (for mutual TLS)")
	useClientTLS := flag.Bool("client-tls", false, "Require clients to use TLS when connecting to the proxy")
	logFile := flag.String("log-file", "output.log", "File to write logs to (in addition to stdout)")
	verbose := flag.Bool("v", false, "Enable verbose logging to console")
	flag.Parse()

	// Setup logging
	logFileHandle, err := setupLogging(*logFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error setting up logging: %v\n", err)
		os.Exit(1)
	}

	// Close log file when the program exits
	if logFileHandle != nil {
		defer logFileHandle.Close()
		log.Printf("Logging to file: %s", *logFile)
	}

	// Configure proxy
	listenAddr := fmt.Sprintf(":%d", *port)

	// Check if targetHost already contains a port
	// Let the ProxyConfig handle assigning the default port based on the listener
	targetAddr := *targetHost

	// If no port specified and using HTTPS, add the default HTTPS port
	if !strings.Contains(*targetHost, ":") && *targetUseTLS {
		targetAddr = *targetHost + ":443" // Default HTTPS port if not specified and TLS is enabled
	}

	log.Printf("Starting proxy: %s -> %s", listenAddr, targetAddr)
	log.Printf("Target TLS: %v, Client TLS: %v", *targetUseTLS, *useClientTLS)

	// Create reusable TLS configuration for target connections
	targetTLSConfig := &tls.Config{
		InsecureSkipVerify: *insecureSkipVerify, // Based on command line flag
		ServerName:         *targetHost,         // Use target hostname for SNI
	}

	// Create the proxy with configuration
	proxyConfig := NewProxyConfig(listenAddr, targetAddr)

	// Configure target-side TLS if specified
	if *targetUseTLS {
		log.Printf("Enabling TLS for connecting to target server: %s", targetAddr)
		proxyConfig.WithTargetTLSConfig(targetTLSConfig)

		// If target client certificates are provided, configure them
		if *targetClientCert != "" && *targetClientKey != "" {
			log.Printf("Using client certificate for target server authentication: %s", *targetClientCert)
			proxyConfig.WithTargetClientCert(*targetClientCert, *targetClientKey)
		}
	}

	// Configure client-side TLS if requested
	if *useClientTLS {
		log.Printf("Configuring proxy to use TLS for client connections with certificates: %s, %s", *serverCert, *serverKey)
		proxyConfig.WithClientTLS(*serverCert, *serverKey)

		// Configure client certificate authentication if requested
		if *requireClientCert {
			if *insecureClient {
				log.Printf("Enabling insecure client certificate authentication (accepting any client cert)")
				proxyConfig.WithInsecureClientAuth(*serverCert, *serverKey)
			} else {
				log.Printf("Enabling client certificate authentication using CA: %s", *caFile)
				proxyConfig.WithClientAuth(*caFile, *serverCert, *serverKey)
			}
		}
	} else {
		log.Printf("Proxy will accept plain TCP connections from clients")
	}

	// Create the proxy with the configuration
	proxy := NewProxy(proxyConfig)

	// Set up data logging handlers if a log file is specified
	if *logFile != "" {
		log.Println("Data logging enabled for log file:", *logFile)

		// Data logging
		proxy.ClientToServerHandler = func(data []byte) ([]byte, bool) {
			log.Printf("Client to server: %d bytes\nData: %s\nHex: %x\n",
				len(data), string(data), data)

			// Example of how to intercept a request and respond with custom data
			// This checks if the request contains "GET /intercept" and responds with custom data
			if len(data) >= 12 && strings.HasPrefix(string(data), "GET /inter") {
				log.Printf("Intercepting request and sending custom response")

				// Create a custom HTTP response
				customResponse := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 28\r\n\r\nThis is a custom response!\r\n")

				// Send the response directly to the client
				err := proxy.SendCustomResponse(customResponse)
				if err != nil {
					log.Printf("Failed to send custom response: %v", err)
				}

				// Return false to prevent forwarding to the server
				return nil, false
			}

			return data, true
		}

		proxy.ServerToClientHandler = func(data []byte) ([]byte, bool) {
			log.Printf("Server to client: %d bytes\nData: %s\nHex: %x\n",
				len(data), string(data), data)
			return data, true
		}
	}

	// Add verbose console logging if requested
	if *verbose && *logFile == "" {
		log.Println("Verbose console logging enabled")
		proxy.ClientToServerHandler = func(data []byte) ([]byte, bool) {
			log.Printf("Client to server: %d bytes", len(data))
			return data, true
		}
		proxy.ServerToClientHandler = func(data []byte) ([]byte, bool) {
			log.Printf("Server to client: %d bytes", len(data))
			return data, true
		}
	}

	// Start the proxy in the main thread
	log.Printf("Starting proxy on port %d...", *port)
	if err := proxy.Start(); err != nil {
		log.Fatalf("Proxy error: %v", err)
	}
}
