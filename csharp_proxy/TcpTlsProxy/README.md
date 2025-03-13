# TCP/TLS Proxy in C#

A flexible TCP proxy with TLS support for intercepting and modifying TCP traffic. This implementation is a Windows-only port of the original Golang version to C#, using Windows Certificate Store for certificate management.

## Features

- Proxy TCP connections with or without TLS
- Support for client-side TLS (client to proxy)
- Support for target-side TLS (proxy to target)
- Support for mutual TLS authentication (client authentication)
- Support for client certificates when connecting to target servers
- Exclusive integration with Windows certificate store (no file-based certificates)
- Data processing and interception capabilities
- Detailed logging

## Prerequisites

- .NET 6.0 SDK or later
- Windows operating system (required for certificate store access)
- Required certificates installed in the Windows certificate store

## Building the Project

```bash
# Navigate to the project directory
cd TcpTlsProxy

# Build the project
dotnet build
```

## Running the Proxy

```bash
# Navigate to the build output directory
cd bin/Debug/net6.0

# Run the proxy with default settings (listen on port 8080, connect to Google)
./TcpTlsProxy

# Run with custom configuration (example)
./TcpTlsProxy --port 8443 --target-host api.example.com --client-tls --server-cert-subject "My Server Certificate"
```

## Command-Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `--port` | 8080 | Port to listen on for proxy connections |
| `--client-auth` | false | Require client certificate authentication (mutual TLS) |
| `--insecure-client` | false | Accept any client certificate when client authentication is enabled |
| `--ca-cert-subject` | "" | CA certificate subject name from Windows certificate store for verifying client certificates |
| `--ca-cert-store` | Root | Windows certificate store name for CA certificate (e.g., Root, My, TrustedPeople) |
| `--ca-cert-location` | CurrentUser | Windows certificate store location for CA certificate (e.g., CurrentUser, LocalMachine) |
| `--server-cert-subject` | "" | Server certificate subject name from Windows certificate store for TLS connections |
| `--server-cert-store` | My | Windows certificate store name for server certificate (e.g., My, TrustedPeople) |
| `--server-cert-location` | CurrentUser | Windows certificate store location for server certificate (e.g., CurrentUser, LocalMachine) |
| `--target-tls` | true | Use TLS when connecting to target server (set to false for plain TCP targets) |
| `--insecure-target` | true | Skip verification of target server TLS certificates (set to false in production) |
| `--target-host` | www.google.com | Target hostname to connect to (with optional port, e.g., 'example.com:443') |
| `--client-cert-subject` | "" | Client certificate subject name from Windows certificate store for target server authentication |
| `--client-cert-store` | My | Windows certificate store name for client certificate (e.g., My, TrustedPeople) |
| `--client-cert-location` | CurrentUser | Windows certificate store location for client certificate (e.g., CurrentUser, LocalMachine) |
| `--client-tls` | false | Require clients to use TLS when connecting to the proxy |
| `--log-file` | output.log | File to write logs to (in addition to stdout) |
| `--v` | false | Enable verbose logging to console |

## Usage Examples

### Basic Usage

```bash
# Simple proxy to Google
./TcpTlsProxy
```

### Proxy to a Different Target

```bash
# Connect to a different target on a custom port
./TcpTlsProxy --target-host example.com:8443 --port 8080 --log-file proxy.log
```

### Enable Client TLS

```bash
# Require clients to use TLS when connecting to the proxy
./TcpTlsProxy --client-tls --server-cert-subject "My Server Certificate"
```

### Client Authentication

```bash
# Require client certificates for authentication
./TcpTlsProxy --client-tls --client-auth --ca-cert-subject "My CA Certificate" --server-cert-subject "My Server Certificate"
```

### Using Client Certificate for Target Server

```bash
# Use a client certificate when connecting to the target server
./TcpTlsProxy --client-cert-subject "My Client Certificate" --target-host secure-api.example.com
```

### Using Certificates from LocalMachine Store

```bash
# Use certificates from LocalMachine store
./TcpTlsProxy --server-cert-subject "My Server Certificate" --server-cert-location LocalMachine --client-cert-subject "My Client Certificate" --client-cert-location LocalMachine
```

### Secure Mode for Production

```bash
# Disable insecure TLS settings for production use
./TcpTlsProxy --target-host api.example.com --insecure-target false --insecure-client false
```

## Working with Windows Certificate Store

### Viewing Certificates

You can view certificates in the Windows certificate store using the Certificate Manager MMC snap-in:

1. Press `Win+R` and type `certmgr.msc` to open the Certificate Manager for the current user
2. For machine certificates, use `certlm.msc` (requires administrator privileges)

### Importing Certificates

To import a certificate into the Windows certificate store:

```powershell
# Import a certificate into the current user's personal store
Import-PfxCertificate -FilePath "certificate.pfx" -CertStoreLocation Cert:\CurrentUser\My -Password (ConvertTo-SecureString -String "password" -Force -AsPlainText)

# Import a certificate into the local machine's personal store (requires admin)
Import-PfxCertificate -FilePath "certificate.pfx" -CertStoreLocation Cert:\LocalMachine\My -Password (ConvertTo-SecureString -String "password" -Force -AsPlainText)
```

### Creating Self-Signed Certificates

For testing purposes, you can create self-signed certificates using PowerShell:

```powershell
# Create a self-signed certificate and add it to the current user's personal store
New-SelfSignedCertificate -Subject "CN=My Server Certificate" -CertStoreLocation Cert:\CurrentUser\My -KeyUsage KeyEncipherment,DigitalSignature -KeySpec KeyExchange
```

## License

MIT 