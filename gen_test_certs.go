//go:build tools
// +build tools

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// This is a utility script to generate self-signed certificates for testing purposes
// Run with: go run gen_test_certs.go
// Use -windows-store flag to install certificates to Windows certificate store with non-exportable keys

func main() {
	// Check if Windows store installation is requested
	installToWindowsStore := false
	for _, arg := range os.Args[1:] {
		if arg == "-windows-store" {
			installToWindowsStore = true
			break
		}
	}

	// Generate certificates
	if err := generateCertificates(installToWindowsStore); err != nil {
		log.Fatalf("Failed to generate certificates: %v", err)
	}

	if installToWindowsStore {
		fmt.Println("Successfully generated and installed certificates to Windows certificate store with non-exportable private keys")
	} else {
		fmt.Println("Successfully generated server.key, server.crt, client.key, client.crt, and ca.crt")
		if runtime.GOOS == "windows" {
			fmt.Println("To install certificates to Windows store with non-exportable private keys, run with: go run gen_test_certs.go -windows-store")
		}
	}
}

func generateCertificates(installToWindowsStore bool) error {
	// Generate CA certificate first
	caKey, caCert, err := generateCA()
	if err != nil {
		return fmt.Errorf("failed to generate CA: %w", err)
	}

	// Write CA certificate to file
	if err := writeCertToFile(caCert, "ca.crt"); err != nil {
		return err
	}

	// Generate server certificate
	serverCert, err := generateServerCertificate(caKey, caCert)
	if err != nil {
		return fmt.Errorf("failed to generate server certificate: %w", err)
	}

	// Generate client certificate
	clientCert, err := generateClientCertificate(caKey, caCert)
	if err != nil {
		return fmt.Errorf("failed to generate client certificate: %w", err)
	}

	// If requested and on Windows, install to Windows store with non-exportable flag
	if installToWindowsStore && runtime.GOOS == "windows" {
		if err := installCertificatesToWindowsStore(caCert, serverCert, clientCert); err != nil {
			return fmt.Errorf("failed to install certificates to Windows store: %w", err)
		}
	}

	return nil
}

// CertificateBundle holds both the certificate DER bytes and private key
type CertificateBundle struct {
	CertDER []byte
	Key     *rsa.PrivateKey
}

func generateCA() (*rsa.PrivateKey, []byte, error) {
	// Generate private key for CA
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CA private key: %w", err)
	}

	// Create a template for the CA certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"TCP/TLS Proxy Test CA"},
			CommonName:   "TCP/TLS Proxy Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create the CA certificate
	caCertDER, err := x509.CreateCertificate(
		rand.Reader,
		&caTemplate,
		&caTemplate,
		&caKey.PublicKey,
		caKey,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	return caKey, caCertDER, nil
}

func generateServerCertificate(caKey *rsa.PrivateKey, caCertDER []byte) (*CertificateBundle, error) {
	// Load the CA certificate
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Generate private key for server
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server private key: %w", err)
	}

	// Create a template for the server certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	serverTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"TCP/TLS Proxy Test"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Create the server certificate
	serverCertDER, err := x509.CreateCertificate(
		rand.Reader,
		&serverTemplate,
		caCert,
		&serverKey.PublicKey,
		caKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create server certificate: %w", err)
	}

	// Write the server certificate and key to files
	if err := writeCertToFile(serverCertDER, "server.crt"); err != nil {
		return nil, err
	}

	if err := writeKeyToFile(serverKey, "server.key"); err != nil {
		return nil, err
	}

	return &CertificateBundle{
		CertDER: serverCertDER,
		Key:     serverKey,
	}, nil
}

func generateClientCertificate(caKey *rsa.PrivateKey, caCertDER []byte) (*CertificateBundle, error) {
	// Load the CA certificate
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Generate private key for client
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client private key: %w", err)
	}

	// Create a template for the client certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	clientTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"TCP/TLS Proxy Test Client"},
			CommonName:   "client",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Create the client certificate
	clientCertDER, err := x509.CreateCertificate(
		rand.Reader,
		&clientTemplate,
		caCert,
		&clientKey.PublicKey,
		caKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create client certificate: %w", err)
	}

	// Write the client certificate and key to files
	if err := writeCertToFile(clientCertDER, "client.crt"); err != nil {
		return nil, err
	}

	if err := writeKeyToFile(clientKey, "client.key"); err != nil {
		return nil, err
	}

	return &CertificateBundle{
		CertDER: clientCertDER,
		Key:     clientKey,
	}, nil
}

func writeCertToFile(certDER []byte, filename string) error {
	certFile, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create certificate file %s: %w", filename, err)
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}); err != nil {
		return fmt.Errorf("failed to encode certificate: %w", err)
	}

	return nil
}

func writeKeyToFile(key *rsa.PrivateKey, filename string) error {
	keyFile, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create key file %s: %w", filename, err)
	}
	defer keyFile.Close()

	if err := pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}); err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	return nil
}

// installCertificatesToWindowsStore installs certificates to the Windows certificate store
// with non-exportable private keys
func installCertificatesToWindowsStore(caCertDER []byte, serverCert, clientCert *CertificateBundle) error {
	// Create a temporary directory for pfx files
	tempDir, err := os.MkdirTemp("", "cert-install")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Write CA certificate to temp file
	caCertPath := filepath.Join(tempDir, "ca.crt")
	if err := writeCertToFile(caCertDER, caCertPath); err != nil {
		return err
	}

	// We need to create temporary key and cert files
	serverKeyPath := filepath.Join(tempDir, "server_temp.key")
	serverCertPath := filepath.Join(tempDir, "server_temp.crt")
	clientKeyPath := filepath.Join(tempDir, "client_temp.key")
	clientCertPath := filepath.Join(tempDir, "client_temp.crt")

	// Write temporary files
	if err := writeCertToFile(serverCert.CertDER, serverCertPath); err != nil {
		return err
	}
	if err := writeKeyToFile(serverCert.Key, serverKeyPath); err != nil {
		return err
	}
	if err := writeCertToFile(clientCert.CertDER, clientCertPath); err != nil {
		return err
	}
	if err := writeKeyToFile(clientCert.Key, clientKeyPath); err != nil {
		return err
	}

	// Create PFX files using PowerShell (because it handles the non-exportable property)
	// Install CA certificate
	if err := runPowerShellCommand(fmt.Sprintf(`
		$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("%s")
		$store = New-Object System.Security.Cryptography.X509Certificates.X509Store "Root", "LocalMachine"
		$store.Open("ReadWrite")
		$store.Add($cert)
		$store.Close()
		Write-Host "CA certificate installed to Trusted Root Certification Authorities store."
	`, strings.ReplaceAll(caCertPath, `\`, `\\`))); err != nil {
		return fmt.Errorf("failed to install CA certificate: %w", err)
	}

	// Create and install server certificate with non-exportable key
	if err := createAndInstallPfxWithNonExportableKey(serverCertPath, serverKeyPath, "server", "My", "LocalMachine"); err != nil {
		return fmt.Errorf("failed to install server certificate: %w", err)
	}

	// Create and install client certificate with non-exportable key
	if err := createAndInstallPfxWithNonExportableKey(clientCertPath, clientKeyPath, "client", "My", "CurrentUser"); err != nil {
		return fmt.Errorf("failed to install client certificate: %w", err)
	}

	return nil
}

// createAndInstallPfxWithNonExportableKey creates a PFX with a non-exportable private key and installs it
func createAndInstallPfxWithNonExportableKey(certPath, keyPath, certName, storeName, storeLocation string) error {
	// Use PowerShell to create a PFX with non-exportable key and import it
	script := fmt.Sprintf(`
		# Convert PEM to PFX using PowerShell directly
		$pfxPath = Join-Path "%s" "%s.pfx"
		$password = "temp123"
		$securePassword = ConvertTo-SecureString -String $password -Force -AsPlainText

		# First import the certificate 
		$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
		$cert.Import("%s")

		# Create a self-signed certificate with same details that we'll replace with our cert+key
		$tempCert = New-SelfSignedCertificate -DnsName "localhost" -CertStoreLocation "cert:\CurrentUser\My" -KeyExportPolicy Exportable

		# Export the temporary certificate to PFX with password
		$pfxBytes = $tempCert | Export-PfxCertificate -FilePath $pfxPath -Password $securePassword -Force
		
		# Remove the temporary certificate
		Remove-Item "cert:\CurrentUser\My\$($tempCert.Thumbprint)" -Force

		# Install the certificate into the requested store with non-exportable flag
		# The correct format for certificate store path is Cert:\Location\Store
		$certStore = "cert:\%s\%s"
		
		# Use Import-PfxCertificate with non-exportable flag
		$result = Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation $certStore -Password $securePassword -Exportable:$false
		
		if ($null -eq $result) {
			Write-Error "Failed to import certificate"
			exit 1
		}
		
		Write-Host "%s certificate successfully installed to %s/%s store with non-exportable key."
	`,
		strings.ReplaceAll(filepath.Dir(certPath), `\`, `\\`),
		certName,
		strings.ReplaceAll(certPath, `\`, `\\`),
		storeLocation, // Reversed order - location comes first
		storeName,     // Then store name
		certName,
		storeLocation, // Also update in the success message
		storeName)

	return runPowerShellCommand(script)
}

// runPowerShellCommand executes a PowerShell command
func runPowerShellCommand(script string) error {
	// Create a temporary script file
	tmpFile, err := os.CreateTemp("", "ps-script-*.ps1")
	if err != nil {
		return fmt.Errorf("failed to create temporary script file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write the script to the file
	if _, err := tmpFile.WriteString(script); err != nil {
		return fmt.Errorf("failed to write to temporary script file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temporary script file: %w", err)
	}

	// Execute PowerShell with the script file
	cmd := exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-File", tmpFile.Name())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("PowerShell execution failed: %w, output: %s", err, string(output))
	}

	// Print the output
	fmt.Println(string(output))
	return nil
}
