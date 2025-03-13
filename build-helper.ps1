param (
    [switch]$Release = $false
)

$BuildConfiguration = if ($Release) { "Release" } else { "Debug" }

Write-Host "Building WinCertHelper .NET application in $BuildConfiguration configuration..."

# Check if .NET SDK is installed
$dotnetVersion = dotnet --version
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: .NET SDK is not installed. Please install .NET 6.0 SDK or later." -ForegroundColor Red
    exit 1
}

Write-Host "Using .NET SDK version: $dotnetVersion" -ForegroundColor Green

# Navigate to the WinCertHelper directory
Push-Location WinCertHelper

try {
    # Restore dependencies
    Write-Host "Restoring dependencies..." -ForegroundColor Cyan
    dotnet restore
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error: Failed to restore .NET dependencies." -ForegroundColor Red
        exit 1
    }

    # Build the application
    Write-Host "Building application..." -ForegroundColor Cyan
    dotnet build --configuration $BuildConfiguration
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error: Failed to build .NET application." -ForegroundColor Red
        exit 1
    }

    # Publish the application
    Write-Host "Publishing application..." -ForegroundColor Cyan
    dotnet publish --configuration $BuildConfiguration --self-contained false
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error: Failed to publish .NET application." -ForegroundColor Red
        exit 1
    }

    $binPath = "bin\$BuildConfiguration\net6.0"
    if (Test-Path $binPath) {
        Write-Host "Build completed successfully. Helper is available at: $binPath\WinCertHelper.exe" -ForegroundColor Green
    } else {
        Write-Host "Build completed but output directory was not found." -ForegroundColor Yellow
    }
} finally {
    # Return to the original directory
    Pop-Location
}

# Update the path in the Go code
$wincertFile = "wincert\wincert.go"
if (Test-Path $wincertFile) {
    $content = Get-Content $wincertFile -Raw
    $relPath = "WinCertHelper\bin\$BuildConfiguration\net6.0\WinCertHelper.exe"
    $escapedPath = $relPath.Replace("\", "/")
    
    # Update the dotNetHelperPath variable
    $updatedContent = $content -replace 'var dotNetHelperPath = ".*"', "var dotNetHelperPath = `"$escapedPath`""
    Set-Content -Path $wincertFile -Value $updatedContent
    
    Write-Host "Updated helper path in wincert.go to: $escapedPath" -ForegroundColor Green
} else {
    Write-Host "Warning: Could not find wincert.go to update helper path." -ForegroundColor Yellow
}

Write-Host "Build process completed." -ForegroundColor Green 