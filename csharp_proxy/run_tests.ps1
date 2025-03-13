# Test Runner for TcpTlsProxy
# Runs all unit tests and saves output to a file

# Set output file path
$outputFile = "test_output.txt"

# Run the tests from the main directory
Write-Host "Running tests..." -ForegroundColor Green
dotnet test TcpTlsProxy.Tests/TcpTlsProxy.Tests.csproj --verbosity normal | Tee-Object -FilePath $outputFile

# Check test results
if ($LASTEXITCODE -eq 0) {
    Write-Host "All tests passed!" -ForegroundColor Green
} else {
    Write-Host "Some tests failed. See $outputFile for details." -ForegroundColor Red
    
    # Extract error information from the test output
    Write-Host "Errors found:" -ForegroundColor Red
    Get-Content $outputFile | Select-String -Pattern "Failed|Error" | ForEach-Object {
        Write-Host "  $_" -ForegroundColor Red
    }
} 