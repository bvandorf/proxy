# run_tests.ps1
# Script to run Go tests and save output to test_output.txt

param (
    [string]$OutputFile = "test_output.txt",
    [switch]$Verbose,
    [switch]$Coverage,
    [switch]$SetupCerts = $true,
    [int]$Timeout = 15, # Timeout in seconds per test
    [switch]$RunOneByOne = $true # Run tests one by one for better isolation
)

# Create a timestamp for the test run
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$separator = "=" * 80

# Function to check if a command exists
function Test-CommandExists {
    param (
        [string]$command
    )
    
    $exists = $false
    try {
        if (Get-Command $command -ErrorAction Stop) {
            $exists = $true
        }
    } catch {
        $exists = $false
    }
    return $exists
}

# First, set up the certificates if the parameter is set
if ($SetupCerts) {
    Write-Host "Setting up test certificates..." -ForegroundColor Cyan
    
    # Generate certificates using our Go tool or OpenSSL
    Write-Host "Generating self-signed certificates for testing..." -ForegroundColor Cyan
    
    try {
        # Use Go directly for certificate generation as it's more reliable cross-platform
        Write-Host "Using Go for certificate generation..." -ForegroundColor Cyan
        & go run gen_test_certs.go
        
        if ((Test-Path ".\server.crt") -and (Test-Path ".\server.key") -and 
            (Test-Path ".\client.crt") -and (Test-Path ".\client.key") -and
            (Test-Path ".\ca.crt")) {
            Write-Host "Successfully generated certificates with Go:" -ForegroundColor Green
            Write-Host "  - server.crt, server.key - Server certificate and key" -ForegroundColor Green
            Write-Host "  - client.crt, client.key - Client certificate and key" -ForegroundColor Green
            Write-Host "  - ca.crt - Certificate Authority certificate" -ForegroundColor Green
        } else {
            throw "Failed to generate all required certificates with Go"
        }
    } catch {
        Write-Host "Error generating certificates: '$($_.Exception.Message)'" -ForegroundColor Red
        Write-Host "Tests requiring TLS may fail" -ForegroundColor Yellow
    }
}

# Write header to the output file
"$separator" | Out-File -FilePath $OutputFile -Force
"TEST RUN: $timestamp" | Out-File -FilePath $OutputFile -Append
"$separator" | Out-File -FilePath $OutputFile -Append
"" | Out-File -FilePath $OutputFile -Append

# Overall exit code
$overallExitCode = 0

if ($RunOneByOne) {
    # Get list of test functions
    Write-Host "Listing available tests..." -ForegroundColor Cyan
    $testListCmd = "go test -list=. ."
    $testList = & cmd /c "$testListCmd 2>&1" | Where-Object { $_ -match "^Test" }
    
    if ($testList.Count -eq 0) {
        Write-Host "No tests found" -ForegroundColor Yellow
        exit 1
    }
    
    Write-Host "Found $($testList.Count) tests:" -ForegroundColor Cyan
    $testList | ForEach-Object { Write-Host "  - $_" -ForegroundColor White }
    
    # Run each test individually
    foreach ($testName in $testList) {
        Write-Host "`nRunning test: $testName" -ForegroundColor Cyan
        
        # Build the command with timeout
        $command = "go test"
        if ($Verbose) {
            $command += " -v"
        }
        if ($Coverage) {
            $command += " -cover"
        }
        $command += " -timeout ${Timeout}s -run=^$testName$ ."
        
        # Display the command being run
        Write-Host "Command: $command" -ForegroundColor Gray
        "RUNNING TEST: $testName" | Out-File -FilePath $OutputFile -Append
        "COMMAND: $command" | Out-File -FilePath $OutputFile -Append
        "" | Out-File -FilePath $OutputFile -Append
        
        # Run the test and capture output
        $startTime = Get-Date
        try {
            # Execute the command and capture output
            $output = & cmd /c "$command 2>&1"
            $testExitCode = $LASTEXITCODE
            
            # Display the output
            $output | ForEach-Object { Write-Host $_ }
            
            # Save to file
            $output | Out-File -FilePath $OutputFile -Append
            
            # Update overall exit code
            if ($testExitCode -ne 0) {
                $overallExitCode = 1
            }
        } catch {
            $errorMsg = "ERROR: Test execution failed with exception: $($_.Exception.Message)"
            $errorMsg | Out-File -FilePath $OutputFile -Append
            Write-Host $errorMsg -ForegroundColor Red
            $testExitCode = 1
            $overallExitCode = 1
        }
        $endTime = Get-Date
        $duration = $endTime - $startTime
        
        # Write test summary
        Write-Host "  Duration: $($duration.TotalSeconds) seconds" -ForegroundColor Cyan
        if ($testExitCode -eq 0) {
            Write-Host "  Result: PASSED" -ForegroundColor Green
        } else {
            Write-Host "  Result: FAILED" -ForegroundColor Red
        }
        
        # Write separator for next test
        "" | Out-File -FilePath $OutputFile -Append
        "$separator" | Out-File -FilePath $OutputFile -Append
        "" | Out-File -FilePath $OutputFile -Append
    }
} else {
    # Run all tests at once
    # Build the command with timeout
    $command = "go test"
    if ($Verbose) {
        $command += " -v"
    }
    if ($Coverage) {
        $command += " -cover"
    }
    $command += " -timeout ${Timeout}s ."
    
    # Display the command being run
    Write-Host "Running: $command" -ForegroundColor Cyan
    "COMMAND: $command" | Out-File -FilePath $OutputFile -Append
    "" | Out-File -FilePath $OutputFile -Append
    
    # Run the tests and capture output
    $startTime = Get-Date
    try {
        # Execute the command and capture output
        $output = & cmd /c "$command 2>&1"
        $overallExitCode = $LASTEXITCODE
        
        # Display the output
        $output | ForEach-Object { Write-Host $_ }
        
        # Save to file
        $output | Out-File -FilePath $OutputFile -Append
    } catch {
        $errorMsg = "ERROR: Test execution failed with exception: $($_.Exception.Message)"
        $errorMsg | Out-File -FilePath $OutputFile -Append
        Write-Host $errorMsg -ForegroundColor Red
        $overallExitCode = 1
    }
    $endTime = Get-Date
    $duration = $endTime - $startTime
    
    # Write footer with test duration
    "" | Out-File -FilePath $OutputFile -Append
    "$separator" | Out-File -FilePath $OutputFile -Append
    "TEST DURATION: $($duration.TotalSeconds) seconds" | Out-File -FilePath $OutputFile -Append
    "EXIT CODE: $overallExitCode" | Out-File -FilePath $OutputFile -Append
    "$separator" | Out-File -FilePath $OutputFile -Append
}

# Check for common error patterns
$errorPatterns = @("FAIL", "panic:", "fatal error", "ERROR", "Exception", "runtime error")
$foundErrors = $false

foreach ($pattern in $errorPatterns) {
    $matches = Select-String -Path $OutputFile -Pattern $pattern -SimpleMatch -Quiet
    if ($matches) {
        $foundErrors = $true
        Write-Host "Found error pattern: $pattern" -ForegroundColor Yellow
    }
}

# Show overall summary
Write-Host "`nOverall Test Summary:" -ForegroundColor Cyan
Write-Host "  Duration: $(((Get-Date) - $startTime).TotalSeconds) seconds" -ForegroundColor Cyan
if ($overallExitCode -eq 0 -and -not $foundErrors) {
    Write-Host "  Result: ALL TESTS PASSED" -ForegroundColor Green
} else {
    Write-Host "  Result: SOME TESTS FAILED" -ForegroundColor Red
    Write-Host "  See $OutputFile for details" -ForegroundColor Red
}

# Return the exit code from the tests
exit $overallExitCode 