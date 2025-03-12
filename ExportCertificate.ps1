#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Searches for and exports certificates from the Windows Certificate Store
.DESCRIPTION
    This script allows you to search for certificates in the Windows Certificate Store
    and export them to PEM format for use with applications that require separate
    certificate and key files (like the TCP/TLS Proxy).
.EXAMPLE
    .\ExportCertificate.ps1 -SearchTerm "example.com"
    Searches for certificates containing "example.com" in the subject and exports the selected one
.EXAMPLE
    .\ExportCertificate.ps1 -Thumbprint "1234567890ABCDEF1234567890ABCDEF12345678"
    Exports the certificate with the specified thumbprint
.PARAMETER SearchTerm
    Text to search for in certificate subjects or common names
.PARAMETER Thumbprint
    The specific thumbprint of the certificate to export
.PARAMETER OutputPath
    Directory where certificate files will be saved (default: current directory)
.PARAMETER OpenSSLPath
    Path to OpenSSL executable (tries to find it automatically if not specified)
.NOTES
    Requires administrative privileges to access the certificate store
    Requires OpenSSL to be installed for PEM conversion
#>

param (
    [Parameter(Mandatory=$false, Position=0)]
    [ValidateSet("help", "search", "thumbprint")]
    [string]$Action = "help",
    
    [Parameter(Mandatory=$false, Position=1)]
    [string]$Value = "",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".",
    
    [Parameter(Mandatory=$false)]
    [string]$OpenSSLPath
)

# Handle the help/info action
if ($Action -eq "help") {
    Write-Host "TCP/TLS Proxy Certificate Export Tool" -ForegroundColor Cyan
    Write-Host "--------------------------------------" -ForegroundColor Cyan
    Write-Host "This script exports certificates from the Windows Certificate Store to PEM format for use with the TCP/TLS Proxy."
    Write-Host
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\ExportCertificate.ps1 [help]"
    Write-Host "  .\ExportCertificate.ps1 search [SearchTerm] [-OutputPath <path>] [-OpenSSLPath <path>]"
    Write-Host "  .\ExportCertificate.ps1 thumbprint <ThumbprintValue> [-OutputPath <path>] [-OpenSSLPath <path>]"
    Write-Host 
    Write-Host "Examples:" -ForegroundColor Yellow
    Write-Host "  # Show this help information:"
    Write-Host "  .\ExportCertificate.ps1 help"
    Write-Host
    Write-Host "  # List all certificates in your personal store:"
    Write-Host "  .\ExportCertificate.ps1 search"
    Write-Host
    Write-Host "  # Search for certificates by name:"
    Write-Host "  .\ExportCertificate.ps1 search example.com"
    Write-Host
    Write-Host "  # Export a specific certificate by thumbprint:"
    Write-Host "  .\ExportCertificate.ps1 thumbprint 1234567890ABCDEF1234567890ABCDEF12345678"
    Write-Host
    Write-Host "  # Export to a specific path:"
    Write-Host "  .\ExportCertificate.ps1 search example.com -OutputPath C:\Certs"
    Write-Host
    Write-Host "For detailed help:"
    Write-Host "  Get-Help .\ExportCertificate.ps1 -Full"
    Write-Host
    exit 0
}

#region Helper Functions
function Find-OpenSSL {
    $opensslPaths = @(
        "C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
        "C:\Program Files (x86)\OpenSSL-Win32\bin\openssl.exe",
        "C:\OpenSSL-Win64\bin\openssl.exe",
        "C:\OpenSSL-Win32\bin\openssl.exe"
    )
    
    # Check if OpenSSL is in PATH
    $opensslInPath = Get-Command "openssl" -ErrorAction SilentlyContinue
    if ($opensslInPath) {
        return $opensslInPath.Source
    }
    
    # Check common installation paths
    foreach ($path in $opensslPaths) {
        if (Test-Path $path) {
            return $path
        }
    }
    
    return $null
}

function Test-OpenSSL {
    param (
        [string]$OpenSSLPath
    )
    
    try {
        $output = & $OpenSSLPath "version" 2>&1
        if ($output -like "OpenSSL*") {
            return $true
        }
        return $false
    }
    catch {
        return $false
    }
}

function Convert-PfxToPem {
    param (
        [string]$PfxPath,
        [SecureString]$PfxPassword,
        [string]$OutputPath,
        [string]$BaseName,
        [string]$OpenSSLPath
    )
    
    # Convert secure string to plain text for OpenSSL
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PfxPassword)
    $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    
    # Create password file for OpenSSL
    $passwordFilePath = Join-Path $OutputPath "temp_pwd.txt"
    Set-Content -Path $passwordFilePath -Value $plainPassword -NoNewline
    
    try {
        # Extract certificate
        $certPath = Join-Path $OutputPath "$BaseName.crt"
        Write-Host "Extracting certificate to $certPath..." -ForegroundColor Cyan
        & $OpenSSLPath pkcs12 -in $PfxPath -clcerts -nokeys -out $certPath -passin "file:$passwordFilePath"
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Error extracting certificate from PFX file." -ForegroundColor Red
            throw "OpenSSL command failed with exit code $LASTEXITCODE"
        }
        
        # Extract private key directly to unencrypted form in one step (more reliable)
        $keyPath = Join-Path $OutputPath "$BaseName.key"
        Write-Host "Extracting private key and saving to $keyPath..." -ForegroundColor Cyan
        & $OpenSSLPath pkcs12 -in $PfxPath -nocerts -nodes -out $keyPath -passin "file:$passwordFilePath"
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Error extracting private key from PFX file." -ForegroundColor Red
            throw "OpenSSL command failed with exit code $LASTEXITCODE"
        }
    }
    catch {
        Write-Host "Error during OpenSSL operation: $_" -ForegroundColor Red
        # Continue to cleanup
    }
    finally {
        # Clean up temporary files
        if (Test-Path $passwordFilePath) {
            Remove-Item -Path $passwordFilePath -Force
        }
    }
    
    # Verify files were created
    $success = $true
    if (-not (Test-Path $certPath)) {
        Write-Host "Warning: Certificate file was not created successfully." -ForegroundColor Yellow
        $success = $false
    }
    if (-not (Test-Path $keyPath)) {
        Write-Host "Warning: Private key file was not created successfully." -ForegroundColor Yellow
        $success = $false
    }
    
    if (-not $success) {
        Write-Host "The export process had errors. Files may be incomplete or missing." -ForegroundColor Red
    }
    
    return @{
        CertificatePath = $certPath
        PrivateKeyPath = $keyPath
        Success = $success
    }
}
#endregion

#region Main Script
# Ensure output directory exists
if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}
$OutputPath = (Resolve-Path $OutputPath).Path

# Find OpenSSL if not explicitly provided
if (-not $OpenSSLPath) {
    Write-Host "Searching for OpenSSL installation..." -ForegroundColor Cyan
    $OpenSSLPath = Find-OpenSSL
    
    if (-not $OpenSSLPath) {
        Write-Host "OpenSSL not found. Please install OpenSSL or specify the path using -OpenSSLPath parameter." -ForegroundColor Red
        Write-Host "You can download OpenSSL from: https://slproweb.com/products/Win32OpenSSL.html" -ForegroundColor Yellow
        exit 1
    }
}

# Verify OpenSSL works
if (-not (Test-OpenSSL -OpenSSLPath $OpenSSLPath)) {
    Write-Host "The specified OpenSSL executable is not valid. Please check the path." -ForegroundColor Red
    exit 1
}

Write-Host "Using OpenSSL from: $OpenSSLPath" -ForegroundColor Green

# Search for certificates
try {
    if ($Action -eq "thumbprint") {
        # Search by thumbprint (exact match)
        Write-Host "Searching for certificate with thumbprint: $Value" -ForegroundColor Cyan
        $certs = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $Value }
    }
    elseif ($Action -eq "search") {
        # Search by subject or common name if value provided
        if ($Value) {
            Write-Host "Searching for certificates matching: $Value" -ForegroundColor Cyan
            $certs = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { 
                $_.Subject -like "*$Value*" -or
                $_.Subject.Contains("CN=$Value") -or
                ($_.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }) -like "*$Value*"
            }
        } else {
            # List all certificates
            Write-Host "Listing all certificates in the Personal store:" -ForegroundColor Cyan
            $certs = Get-ChildItem -Path Cert:\CurrentUser\My
        }
    }
    
    if (-not $certs -or $certs.Count -eq 0) {
        Write-Host "No certificates found matching the criteria." -ForegroundColor Yellow
        exit 1
    }
    
    # Display found certificates for selection
    Write-Host "Found $($certs.Count) certificate(s):" -ForegroundColor Green
    for ($i = 0; $i -lt $certs.Count; $i++) {
        $cert = $certs[$i]
        $index = $i + 1
        
        Write-Host "[$index] Subject: $($cert.Subject)" -ForegroundColor Green
        Write-Host "    Thumbprint: $($cert.Thumbprint)"
        Write-Host "    Expiration: $($cert.NotAfter)"
        Write-Host "    Issuer: $($cert.Issuer)"
        Write-Host "    Has Private Key: $($cert.HasPrivateKey)"
        if ($i -lt ($certs.Count - 1)) {
            Write-Host ""
        }
    }
    
    # Select a certificate
    if ($certs.Count -eq 1) {
        $selectedCert = $certs[0]
        Write-Host "Selected the only certificate found." -ForegroundColor Green
    }
    else {
        # Prompt user to select a certificate
        do {
            $selection = Read-Host "Enter the number of the certificate to export (1-$($certs.Count))"
            $index = [int]::Parse($selection) - 1
        } while ($index -lt 0 -or $index -ge $certs.Count)
        
        $selectedCert = $certs[$index]
        Write-Host "Selected certificate: $($selectedCert.Subject)" -ForegroundColor Green
    }
    
    # Check if certificate has private key
    if (-not $selectedCert.HasPrivateKey) {
        Write-Host "Warning: The selected certificate does not have a private key. The exported PEM key file may not be usable." -ForegroundColor Yellow
    }
    
    # Generate base filename from the certificate subject
    $baseName = ($selectedCert.Subject -replace 'CN=|[^a-zA-Z0-9.-_]', '') -replace '^$', 'certificate'
    if ([string]::IsNullOrWhiteSpace($baseName)) {
        $baseName = "certificate"
    }
    
    # Export to PFX
    $pfxPath = Join-Path $OutputPath "$baseName.pfx"
    
    # Generate a random temporary password for the PFX
    Write-Host "Generating a temporary password for the PFX file..." -ForegroundColor Cyan
    $tempPassword = [System.Guid]::NewGuid().ToString()
    $pfxPassword = ConvertTo-SecureString -String $tempPassword -AsPlainText -Force
    
    Write-Host "Exporting certificate to PFX file: $pfxPath" -ForegroundColor Cyan
    try {
        Export-PfxCertificate -Cert $selectedCert -FilePath $pfxPath -Password $pfxPassword -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Host "Failed to export certificate to PFX: $_" -ForegroundColor Red
        exit 1
    }
    
    # Convert PFX to PEM
    $conversionResult = Convert-PfxToPem -PfxPath $pfxPath -PfxPassword $pfxPassword -OutputPath $OutputPath -BaseName $baseName -OpenSSLPath $OpenSSLPath
    
    if ($conversionResult.Success) {
        Write-Host "`nCertificate export completed successfully!" -ForegroundColor Green
        Write-Host "Files created:"
        Write-Host "- PFX (PKCS#12): $pfxPath"
        Write-Host "- Certificate (PEM): $($conversionResult.CertificatePath)"
        Write-Host "- Private Key (PEM): $($conversionResult.PrivateKeyPath)"
        
        Write-Host "`nTo use with the TCP/TLS proxy:"
        if ($selectedCert.HasPrivateKey) {
            $proxyCommand = ".\tcp-proxy.exe -target-client-cert $($conversionResult.CertificatePath) -target-client-key $($conversionResult.PrivateKeyPath) -target-host your-target-host"
            Write-Host $proxyCommand
        } else {
            Write-Host "Warning: This certificate doesn't have a private key, so it may not be usable for client authentication." -ForegroundColor Yellow
        }
    } else {
        Write-Host "`nThe certificate export process had errors." -ForegroundColor Red
        Write-Host "Please check the error messages above and try again." -ForegroundColor Red
    }
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
    exit 1
}
#endregion 