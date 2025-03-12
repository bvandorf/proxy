# TCP/TLS Proxy

A flexible TCP and TLS proxy server that can intercept, inspect, modify, and customize traffic between clients and servers.

## Features

- TCP proxy for plain HTTP/TCP traffic
- TLS proxy for HTTPS/secure traffic with TLS termination
- Client certificate authentication support (mutual TLS)
- Target-side client certificate authentication for mutual TLS with targets
- Smart port handling with listener port inheritance
- Connection reuse capabilities for performance optimization  
- Customizable data transformation handlers for both directions
- Custom response capabilities for traffic interception
- Verbose logging options for debugging

## Prerequisites

- Go 1.16 or later
- OpenSSL (optional, for certificate generation)
- Administrative privileges (if binding to privileged ports)

## Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd tcp_override_proxy
   ```

2. Build the proxy:
   ```
   go build
   ```

3. Generate TLS certificates (for testing purposes):
   ```
   go run gen_test_certs.go
   ```
   This will create the following certificates in the current directory:
   - `server.crt` and `server.key`: Server certificate and private key
   - `client.crt` and `client.key`: Client certificate and private key
   - `ca.crt`: Certificate Authority certificate used to sign both server and client certificates

## Quick Start

Run the proxy with default settings:

```
./tcp-proxy
```

This starts a proxy on port 8080 that forwards to www.google.com (default target) using TLS.

## Command Line Options

The proxy supports numerous configuration options:

```
Usage: ./tcp-proxy [options]

Options:
  -ca-cert string
        CA certificate file for verifying client certificates (default "ca.crt")
  -client-auth
        Require client certificate authentication (mutual TLS)
  -client-tls
        Require clients to use TLS when connecting to the proxy
  -insecure
        Skip verification of target server TLS certificates (set to false in production) (default true)
  -insecure-client
        Accept any client certificate when client authentication is enabled
  -log-file string
        File to write logs to (in addition to stdout) (default "output.log")
  -port int
        Port to listen on for proxy connections (default 8080)
  -server-cert string
        Server certificate file for TLS connections (default "server.crt")
  -server-key string
        Server private key file for TLS connections (default "server.key")
  -target-client-cert string
        Client certificate file to use when connecting to the target server (for mutual TLS)
  -target-client-key string
        Client key file to use when connecting to the target server (for mutual TLS)
  -target-host string
        Target hostname to connect to (with optional port, e.g., 'example.com:443') (default "www.google.com")
  -target-tls
        Use TLS when connecting to target server (set to false for plain TCP targets) (default true)
  -v    Enable verbose logging to console
```

## Usage Examples

### Basic Usage

```
# Basic proxy on port 8080 targeting Google
./tcp-proxy
```

### Custom Target and Port

```
# Proxy on port 8080 targeting example.com on port 8443
./tcp-proxy -target-host example.com:8443 -port 8080
```

### Port Inheritance

```
# Proxy on port 8080 targeting example.com on the same port (8080)
./tcp-proxy -target-host example.com -port 8080
```

### Client TLS

```
# Require clients to connect via TLS
./tcp-proxy -client-tls -server-cert server.crt -server-key server.key
```

### Client Certificate Authentication

```
# Require client certificate authentication
./tcp-proxy -client-tls -client-auth -ca-cert ca.crt -server-cert server.crt -server-key server.key
```

### Insecure Client Authentication

```
# Accept any client certificate without CA verification
./tcp-proxy -client-tls -client-auth -insecure-client -server-cert server.crt -server-key server.key
```

### Mutual TLS with Target

```
# Use client certificate when connecting to target server
./tcp-proxy -target-client-cert client.crt -target-client-key client.key -target-host secure-api.example.com
```

### Production Configuration

```
# Secure configuration with proper certificate verification
./tcp-proxy -target-host api.example.com -insecure=false -client-tls -client-auth -ca-cert ca.crt -server-cert server.crt -server-key server.key
```

## Testing

Run the tests:

```
./run_tests.ps1
```

This will generate test certificates, execute all tests, and save the output to `test_output.txt`.

Options for the test script:
- `-Verbose`: Show verbose output
- `-Coverage`: Generate test coverage metrics
- `-SetupCerts`: Generate certificates for testing (default is true)
- `-RunOneByOne`: Run tests individually for better isolation (default is true)

## Advanced Features

### Customizing Data Handling

You can customize how the proxy handles data in both directions:

```go
proxy := NewProxy(proxyConfig)

// Modify client to server traffic
proxy.ClientToServerHandler = func(data []byte) ([]byte, bool) {
    // Modify the data as needed
    modifiedData := someTransformation(data)
    
    // Return modified data and true to forward, or any data and false to block
    return modifiedData, true
}

// Modify server to client traffic
proxy.ServerToClientHandler = func(data []byte) ([]byte, bool) {
    // Transform server responses
    return modifiedData, true
}
```

### Custom Responses

The proxy can intercept requests and send custom responses:

```go
proxy.ClientToServerHandler = func(data []byte) ([]byte, bool) {
    if bytes.Contains(data, []byte("specific-pattern")) {
        // Create custom response
        customResponse := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nCustom response!")
        
        // Send directly to client
        proxy.SendCustomResponse(customResponse)
        
        // Return nil and false to block original request
        return nil, false
    }
    return data, true
}
```

### Custom Server Requests

The proxy can send custom requests to the target server:

```go
// Send a custom request to the server and get the response
serverRequest := []byte("GET /custom-endpoint HTTP/1.1\r\nHost: example.com\r\n\r\n")
serverResponse, err := proxy.SendCustomServerRequest(serverRequest, false)
if err != nil {
    log.Printf("Error: %v", err)
} else {
    log.Printf("Server response: %s", serverResponse)
}
```

### Connection Reuse

For better performance, you can reuse connections:

```go
// First request with connection reuse enabled
response1, err := proxy.SendCustomServerRequest(request1, true)

// Second request that may reuse the connection if available
response2, err := proxy.SendCustomServerRequest(request2, true)
```

## License

This project is licensed under the MIT License - see the LICENSE file for details. 