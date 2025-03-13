# TcpTlsProxy Test Suite

This project contains the automated test suite for the TcpTlsProxy, a TCP proxy with TLS support. The tests validate the functionality, reliability, and security of the proxy implementation.

## Test Structure

The test suite is organized as follows:

- **ProxyConfigTests.cs**: Validates the configuration settings and defaults
- **ProxyLoggerTests.cs**: Tests the logging functionality
- **TcpProxyTests.cs**: Unit tests for the main proxy class
- **CertificateTests.cs**: Tests for certificate-related functionality
- **IntegrationTests.cs**: End-to-end tests with mocked networking components

## Running the Tests

### Using the Test Runner Script

The easiest way to run all tests is to use the PowerShell script in the parent directory:

```powershell
.\run_tests.ps1
```

This will:
1. Restore all NuGet packages
2. Build the test project
3. Run all tests
4. Save the test output to `test_output.txt`
5. Display a summary of any test failures

### Using dotnet CLI

You can also run the tests directly using the .NET CLI:

```powershell
# From the TcpTlsProxy.Tests directory
dotnet test
```

## Test Categories

The tests are organized into several categories:

- **Unit Tests**: Test individual components in isolation
- **Integration Tests**: Test multiple components working together
- **Mocked Tests**: Use mocking to simulate external systems like networking

## CI Environment Detection

Some tests that require network access or special permissions are automatically skipped in CI environments. These tests check for the presence of a `CI` environment variable with the value "true".

## Troubleshooting

If tests fail, check:
1. Network connectivity (for integration tests)
2. Windows certificate store access (for certificate tests)
3. Port availability (for proxy tests)

On Windows, you may need to run as Administrator for some tests to access the certificate store. 