# TCP/TLS Proxy

A simple TCP and TLS proxy server that can intercept, inspect, and optionally modify traffic between clients and servers.

## Features

- TCP proxy for HTTP traffic
- TLS proxy for HTTPS traffic with TLS termination
- Client certificate authentication support (mutual TLS)
- Customizable data transformation handlers for both directions
- Verbose logging option for debugging

## Prerequisites

- Go 1.16 or later

## Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd tcp_override_proxy
   ```

2. Generate TLS certificates (for testing purposes):
   ```
   go run gen_test_certs.go
   ```
   This will create the following certificates in the current directory:
   - `server.crt` and `server.key`: Server certificate and private key
   - `client.crt` and `client.key`: Client certificate and private key
   - `ca.crt`: Certificate Authority certificate used to sign both server and client certificates

## Usage

Run the proxy:

```
go run *.go [-v] [-client-auth] [-ca-cert=path/to/ca.crt]
```

Options:
- `-v`: Enable verbose logging of data transmitted through the proxy
- `-client-auth`: Enable client certificate authentication
- `-ca-cert`: Specify the CA certificate to use for client authentication (default: ca.crt)

## Default Configuration

- TCP proxy listens on port 8416 and forwards to localhost:80
- TLS proxy listens on port 8450 and forwards to localhost:443

## Client Certificate Authentication

When client certificate authentication is enabled, clients must present a valid certificate signed by the trusted CA to connect to the proxy. This provides an additional layer of security beyond basic TLS encryption.

To use a client certificate with curl:

```
curl --cert client.crt --key client.key https://localhost:8450
```

## Testing

Run the tests:

```
./run_tests.ps1
```

This will execute all tests and save the output to `test_output.txt`.

## Customizing the Proxy

You can modify the proxy behavior by implementing custom handlers:

```go
proxy := NewProxy(listenAddr, targetAddr)

// Modify client to server traffic
proxy.ClientToServerHandler = func(data []byte) ([]byte, bool) {
    // Transform data or inspect it
    // Return modified data and true to forward, or any data and false to drop
    return modifiedData, true
}

// Modify server to client traffic
proxy.ServerToClientHandler = func(data []byte) ([]byte, bool) {
    // Transform response data
    return modifiedData, true
}

// Enable client certificate authentication
if err := proxy.EnableClientCertAuth("ca.crt"); err != nil {
    log.Fatalf("Failed to enable client certificate authentication: %v", err)
}
```

## License

This project is licensed under the MIT License - see the LICENSE file for details. 