using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CsProxyTools.Clients;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using Xunit.Sdk;

namespace CsProxyTools.Tests.Clients;

public class TlsClientTests : IDisposable
{
    private readonly Mock<ILogger> _loggerMock;
    private readonly TcpListener _server;
    private readonly string _host = "127.0.0.1";
    private readonly int _port = 12346;
    private readonly X509Certificate2 _certificate;
    private bool _disposed;

    public TlsClientTests()
    {
        _loggerMock = new Mock<ILogger>();
        _server = new TcpListener(IPAddress.Parse(_host), _port);
        _server.Start();

        // Create a stronger self-signed certificate with proper subject name
        _certificate = GenerateSelfSignedCertificate();
        
        Console.WriteLine($"TEST SETUP: Created certificate with subject: {_certificate.Subject}");
        Console.WriteLine($"TEST SETUP: Certificate valid from {_certificate.NotBefore} to {_certificate.NotAfter}");
    }

    private X509Certificate2 GenerateSelfSignedCertificate()
    {
        // Use SubjectAlternativeName for proper hostname validation
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddIpAddress(IPAddress.Parse(_host));
        sanBuilder.AddDnsName("localhost");

        // Create a stronger RSA key
        using var rsa = RSA.Create(2048);
        
        var distinguishedName = new X500DistinguishedName($"CN=localhost");
        
        var request = new CertificateRequest(
            distinguishedName,
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // Add the SAN extension
        request.CertificateExtensions.Add(sanBuilder.Build());
        
        // Add basic constraints with CA set to false
        var basicConstraints = new X509BasicConstraintsExtension(false, false, 0, true);
        request.CertificateExtensions.Add(basicConstraints);
        
        // Add key usage
        var keyUsage = new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, 
            true);
        request.CertificateExtensions.Add(keyUsage);
        
        // Add enhanced key usage (for server authentication)
        var enhancedKeyUsage = new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, // Server Authentication
            true);
        request.CertificateExtensions.Add(enhancedKeyUsage);

        // Create the self-signed certificate
        var certificate = request.CreateSelfSigned(
            DateTimeOffset.Now.AddDays(-1),  // Valid from yesterday
            DateTimeOffset.Now.AddYears(1)); // Valid for a year
            
        // For Windows, ensure we have a private key properly stored
        return new X509Certificate2(certificate.Export(X509ContentType.Pfx, "testpassword"), 
                                   "testpassword", 
                                   X509KeyStorageFlags.Exportable);
    }

    [Fact(Timeout = 60000)]
    public async Task ConnectAsync_ShouldConnect_WhenServerIsAvailable()
    {
        Console.WriteLine("TEST: Starting TLS connect test with verbose logging");
        
        // Create a loopback listener on a specific port for better control
        var port = 12347; // Use a different port to avoid conflicts
        var host = "127.0.0.1";
        var localServer = new TcpListener(IPAddress.Parse(host), port);
        localServer.Start();
        Console.WriteLine($"TEST: Started local server on {host}:{port}");
        
        try
        {
            // Arrange
            var client = new TlsClient(_loggerMock.Object, host, port, false);
            var connectionStarted = false;
            var connectionEvent = new TaskCompletionSource<bool>();
            
            client.Connected += (s, e) => {
                Console.WriteLine("TEST: TLS Connected event triggered");
                connectionStarted = true;
                connectionEvent.TrySetResult(true);
            };
            
            // Use a longer timeout for test operations
            using var testTimeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            
            // Server task
            var serverTask = Task.Run(async () =>
            {
                try
                {
                    Console.WriteLine("TEST: Server accepting client connection...");
                    using var serverClient = await localServer.AcceptTcpClientAsync();
                    Console.WriteLine("TEST: Server accepted client connection");
                    
                    // Configure server client for better reliability
                    serverClient.NoDelay = true;
                    serverClient.SendTimeout = 30000;
                    serverClient.ReceiveTimeout = 30000;
                    
                    // Create SSL stream with simple validator
                    using var sslStream = new SslStream(
                        serverClient.GetStream(),
                        false,
                        (sender, certificate, chain, errors) => {
                            Console.WriteLine($"TEST: Server validating client cert, errors: {errors}");
                            return true; // Accept all
                        });
                    
                    Console.WriteLine("TEST: Server starting SSL handshake");
                    
                    // Configure server authentication with simplified options
                    await sslStream.AuthenticateAsServerAsync(
                        _certificate,
                        false, // No client cert required
                        System.Security.Authentication.SslProtocols.Tls12, // TLS 1.2 only
                        false); // No revocation check
                    
                    Console.WriteLine("TEST: Server SSL handshake completed successfully");
                    
                    // Send test data to keep connection alive
                    var testData = Encoding.UTF8.GetBytes("Test data from server");
                    await sslStream.WriteAsync(testData, 0, testData.Length);
                    
                    // Wait for client test to complete
                    await Task.Delay(3000);
                    
                    Console.WriteLine("TEST: Server shutting down");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"TEST: Server error: {ex.GetType().Name} - {ex.Message}");
                }
                finally
                {
                    Console.WriteLine("TEST: Server task completed");
                }
            });
            
            Console.WriteLine("TEST: Server task started");
            
            // Give server time to start listening
            await Task.Delay(1000);
            
            try
            {
                // Act - Connect client
                Console.WriteLine("TEST: Client connecting");
                await client.ConnectAsync(testTimeoutCts.Token);
                Console.WriteLine("TEST: Client connected successfully");
                
                // Wait for connected event with timeout
                var eventTimeout = TimeSpan.FromSeconds(5);
                Console.WriteLine($"TEST: Waiting for Connected event with {eventTimeout.TotalSeconds}s timeout");
                try
                {
                    await connectionEvent.Task.WaitAsync(eventTimeout);
                    Console.WriteLine("TEST: Connected event received");
                }
                catch (TimeoutException)
                {
                    Console.WriteLine("TEST: Timeout waiting for Connected event!");
                    throw;
                }
                
                // Assert
                Assert.True(connectionStarted, "Connected event should have been triggered");
                Console.WriteLine("TEST: TLS connection test passed");
            }
            finally
            {
                Console.WriteLine("TEST: Test cleanup starting");
                await client.DisposeAsync();
                testTimeoutCts.Cancel();
                
                // Wait for server task to complete
                try {
                    await Task.WhenAny(serverTask, Task.Delay(5000));
                }
                catch (Exception ex) {
                    Console.WriteLine($"TEST: Error waiting for server task: {ex.Message}");
                }
                
                Console.WriteLine("TEST: Test cleanup completed");
            }
        }
        finally
        {
            localServer.Stop();
            Console.WriteLine("TEST: Local server stopped");
        }
    }

    [Fact(Timeout = 45000)]
    public async Task ConnectAsync_ShouldThrowException_WhenServerIsNotAvailable()
    {
        // Arrange
        _server.Stop();
        var client = new TlsClient(_loggerMock.Object, _host, _port, false);
        
        // Timeout for operation
        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        try
        {
            // Act & Assert
            await Assert.ThrowsAsync<SocketException>(async () => 
                await client.ConnectAsync(timeoutCts.Token));
        }
        finally
        {
            // Always dispose client
            await client.DisposeAsync();
        }
    }

    [Fact(Timeout = 60000)]
    public async Task DisconnectAsync_ShouldDisconnect_WhenConnected()
    {
        Console.WriteLine("TEST: Starting TLS DisconnectAsync test");
        
        var port = 12348; // Different port to avoid conflicts
        var host = "127.0.0.1";
        var localServer = new TcpListener(IPAddress.Parse(host), port);
        localServer.Start();
        Console.WriteLine($"TEST: Started local server on {host}:{port}");
        
        try
        {
            // Arrange
            var client = new TlsClient(_loggerMock.Object, host, port, false);
            var disconnectEvent = new TaskCompletionSource<bool>();
            var connectionClosed = false;
            
            client.Disconnected += (s, e) => {
                Console.WriteLine("TEST: TLS Disconnected event triggered");
                connectionClosed = true;
                disconnectEvent.TrySetResult(true);
            };
            
            // Use a longer timeout for test operations
            using var testTimeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            
            // Server task
            var serverTask = Task.Run(async () =>
            {
                try
                {
                    Console.WriteLine("TEST: Server accepting client connection...");
                    using var serverClient = await localServer.AcceptTcpClientAsync();
                    Console.WriteLine("TEST: Server accepted client connection");
                    
                    // Configure server
                    serverClient.NoDelay = true;
                    serverClient.SendTimeout = 30000;
                    serverClient.ReceiveTimeout = 30000;
                    
                    // Create SSL stream
                    using var sslStream = new SslStream(
                        serverClient.GetStream(),
                        false, 
                        (sender, certificate, chain, errors) => true);
                    
                    Console.WriteLine("TEST: Server starting SSL handshake");
                    
                    // Authenticate server
                    await sslStream.AuthenticateAsServerAsync(
                        _certificate,
                        false,
                        System.Security.Authentication.SslProtocols.Tls12,
                        false);
                    
                    Console.WriteLine("TEST: Server SSL handshake completed successfully");
                    
                    // Keep the connection alive by reading data
                    // This will exit when client disconnects
                    Console.WriteLine("TEST: Server waiting for client to disconnect...");
                    var buffer = new byte[1024];
                    try
                    {
                        await sslStream.ReadAsync(buffer, 0, buffer.Length);
                        Console.WriteLine("TEST: Server read data before disconnect");
                    }
                    catch (IOException ex)
                    {
                        Console.WriteLine($"TEST: Server detected client disconnect: {ex.Message}");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"TEST: Server error: {ex.GetType().Name} - {ex.Message}");
                }
                finally
                {
                    Console.WriteLine("TEST: Server task completed");
                }
            });
            
            // Allow server to start
            await Task.Delay(1000); 
            
            try
            {
                // Act - connect
                Console.WriteLine("TEST: Client connecting");
                await client.ConnectAsync(testTimeoutCts.Token);
                Console.WriteLine("TEST: Client connected successfully");
                
                // Wait a moment to ensure stable connection
                await Task.Delay(1000);
                
                // Now disconnect
                Console.WriteLine("TEST: Client disconnecting");
                await client.DisconnectAsync(testTimeoutCts.Token);
                Console.WriteLine("TEST: Client disconnect method completed");
                
                // Wait for disconnected event with timeout
                var eventTimeout = TimeSpan.FromSeconds(5);
                Console.WriteLine($"TEST: Waiting for Disconnected event with {eventTimeout.TotalSeconds}s timeout");
                await disconnectEvent.Task.WaitAsync(eventTimeout);
                Console.WriteLine("TEST: Disconnected event received");
                
                // Assert
                Assert.True(connectionClosed, "Disconnected event should have been triggered");
                Console.WriteLine("TEST: TLS Disconnect test passed");
            }
            finally
            {
                Console.WriteLine("TEST: Client cleanup starting");
                await client.DisposeAsync();
                testTimeoutCts.Cancel();
                
                // Wait for server task to complete
                await Task.WhenAny(serverTask, Task.Delay(5000));
                Console.WriteLine("TEST: Client cleanup completed");
            }
        }
        finally
        {
            localServer.Stop();
            Console.WriteLine("TEST: Local server stopped");
        }
    }

    [Fact(Timeout = 45000)]
    public async Task WriteAsync_ShouldThrowException_WhenNotConnected()
    {
        Console.WriteLine("TEST: Starting TLS WriteAsync_ShouldThrowException_WhenNotConnected test");
        
        // Arrange
        var client = new TlsClient(_loggerMock.Object, _host, _port, false);
        var data = new byte[] { 1, 2, 3 };

        // Act & Assert
        try {
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () => 
                await client.WriteAsync(new ReadOnlyMemory<byte>(data)));
            
            Console.WriteLine($"TEST: Expected exception thrown: {exception.Message}");
        }
        finally {
            await client.DisposeAsync();
        }
        
        Console.WriteLine("TEST: TLS WriteAsync_ShouldThrowException_WhenNotConnected test passed");
    }

    [Fact(Timeout = 60000)]
    public async Task WriteAsync_ShouldSendData_WhenConnected()
    {
        Console.WriteLine("TEST: Starting TLS WriteAsync test");
        
        var port = 12349; // Different port to avoid conflicts
        var host = "127.0.0.1";
        var localServer = new TcpListener(IPAddress.Parse(host), port);
        localServer.Start();
        Console.WriteLine($"TEST: Started local server on {host}:{port}");
        
        try
        {
            // Arrange
            var client = new TlsClient(_loggerMock.Object, host, port, false);
            var data = new byte[] { 1, 2, 3 };
            var serverDataReceived = new TaskCompletionSource<byte[]>();
            
            // Use a longer timeout for test operations
            using var testTimeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            
            // Server task
            var serverTask = Task.Run(async () =>
            {
                try
                {
                    Console.WriteLine("TEST: Server accepting client connection...");
                    using var serverClient = await localServer.AcceptTcpClientAsync();
                    Console.WriteLine("TEST: Server accepted client connection");
                    
                    // Configure server
                    serverClient.NoDelay = true;
                    serverClient.SendTimeout = 30000;
                    serverClient.ReceiveTimeout = 30000;
                    
                    // Create SSL stream
                    using var sslStream = new SslStream(
                        serverClient.GetStream(),
                        false, 
                        (sender, certificate, chain, errors) => true);
                    
                    Console.WriteLine("TEST: Server starting SSL handshake");
                    
                    // Authenticate server
                    await sslStream.AuthenticateAsServerAsync(
                        _certificate,
                        false,
                        System.Security.Authentication.SslProtocols.Tls12,
                        false);
                    
                    Console.WriteLine("TEST: Server SSL handshake completed successfully");
                    
                    // Read data from client
                    Console.WriteLine("TEST: Server waiting to receive data from client");
                    var buffer = new byte[1024];
                    var bytesRead = await sslStream.ReadAsync(buffer, 0, buffer.Length);
                    Console.WriteLine($"TEST: Server received {bytesRead} bytes from client");
                    
                    // Set the TaskCompletionSource with received data
                    serverDataReceived.TrySetResult(buffer.Take(bytesRead).ToArray());
                    
                    // Keep connection alive until test completes
                    await Task.Delay(1000);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"TEST: Server error: {ex.GetType().Name} - {ex.Message}");
                    serverDataReceived.TrySetException(ex);
                }
                finally
                {
                    Console.WriteLine("TEST: Server task completed");
                }
            });
            
            // Allow server to start
            await Task.Delay(1000);
            
            try
            {
                // Act - connect and write data
                Console.WriteLine("TEST: Client connecting");
                await client.ConnectAsync(testTimeoutCts.Token);
                Console.WriteLine("TEST: Client connected successfully");
                
                // Wait a moment to ensure stable connection
                await Task.Delay(1000);
                
                // Write data
                Console.WriteLine("TEST: Client writing data");
                await client.WriteAsync(new ReadOnlyMemory<byte>(data), testTimeoutCts.Token);
                Console.WriteLine("TEST: Client wrote data successfully");
                
                // Wait for server to receive data
                var eventTimeout = TimeSpan.FromSeconds(5);
                Console.WriteLine($"TEST: Waiting for server to receive data with {eventTimeout.TotalSeconds}s timeout");
                var receivedData = await serverDataReceived.Task.WaitAsync(eventTimeout);
                Console.WriteLine($"TEST: Server received {receivedData.Length} bytes");
                
                // Assert data matches
                Assert.Equal(data, receivedData);
                Console.WriteLine("TEST: TLS WriteAsync test passed");
            }
            finally
            {
                Console.WriteLine("TEST: Client cleanup starting");
                await client.DisposeAsync();
                testTimeoutCts.Cancel();
                
                // Wait for server task to complete
                await Task.WhenAny(serverTask, Task.Delay(5000));
                Console.WriteLine("TEST: Client cleanup completed");
            }
        }
        finally
        {
            localServer.Stop();
            Console.WriteLine("TEST: Local server stopped");
        }
    }

    [Fact(Timeout = 60000)]
    public async Task DataReceived_ShouldBeTriggered_WhenDataIsReceived()
    {
        Console.WriteLine("TEST: Starting TLS DataReceived test");
        
        var port = 12350; // Different port to avoid conflicts
        var host = "127.0.0.1";
        var localServer = new TcpListener(IPAddress.Parse(host), port);
        localServer.Start();
        Console.WriteLine($"TEST: Started local server on {host}:{port}");
        
        try
        {
            // Arrange
            var client = new TlsClient(_loggerMock.Object, host, port, false);
            var clientDataReceived = new TaskCompletionSource<byte[]>();
            var testData = new byte[] { 1, 2, 3 };
            
            client.DataReceived += (s, e) => {
                Console.WriteLine($"TEST: Client DataReceived event triggered with {e.Data.Length} bytes");
                clientDataReceived.TrySetResult(e.Data.ToArray());
            };
            
            // Use a longer timeout for test operations
            using var testTimeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            
            // Server task
            var serverTask = Task.Run(async () =>
            {
                try
                {
                    Console.WriteLine("TEST: Server accepting client connection...");
                    using var serverClient = await localServer.AcceptTcpClientAsync();
                    Console.WriteLine("TEST: Server accepted client connection");
                    
                    // Configure server
                    serverClient.NoDelay = true;
                    serverClient.SendTimeout = 30000;
                    serverClient.ReceiveTimeout = 30000;
                    
                    // Create SSL stream
                    using var sslStream = new SslStream(
                        serverClient.GetStream(),
                        false, 
                        (sender, certificate, chain, errors) => true);
                    
                    Console.WriteLine("TEST: Server starting SSL handshake");
                    
                    // Authenticate server
                    await sslStream.AuthenticateAsServerAsync(
                        _certificate,
                        false,
                        System.Security.Authentication.SslProtocols.Tls12,
                        false);
                    
                    Console.WriteLine("TEST: Server SSL handshake completed successfully");
                    
                    // Give client a moment to be ready to receive
                    await Task.Delay(1000);
                    
                    // Send data to client
                    Console.WriteLine("TEST: Server sending data to client");
                    await sslStream.WriteAsync(testData, 0, testData.Length);
                    Console.WriteLine("TEST: Server sent data successfully");
                    
                    // Keep connection alive until test completes
                    await Task.Delay(3000);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"TEST: Server error: {ex.GetType().Name} - {ex.Message}");
                }
                finally
                {
                    Console.WriteLine("TEST: Server task completed");
                }
            });
            
            // Allow server to start
            await Task.Delay(1000);
            
            try
            {
                // Act - connect and wait for data
                Console.WriteLine("TEST: Client connecting");
                await client.ConnectAsync(testTimeoutCts.Token);
                Console.WriteLine("TEST: Client connected successfully");
                
                // Wait for DataReceived event
                var eventTimeout = TimeSpan.FromSeconds(10);
                Console.WriteLine($"TEST: Waiting for client to receive data with {eventTimeout.TotalSeconds}s timeout");
                var receivedData = await clientDataReceived.Task.WaitAsync(eventTimeout);
                Console.WriteLine($"TEST: Client received {receivedData.Length} bytes");
                
                // Assert data matches
                Assert.Equal(testData, receivedData);
                Console.WriteLine("TEST: TLS DataReceived test passed");
            }
            finally
            {
                Console.WriteLine("TEST: Client cleanup starting");
                await client.DisposeAsync();
                testTimeoutCts.Cancel();
                
                // Wait for server task to complete
                await Task.WhenAny(serverTask, Task.Delay(5000));
                Console.WriteLine("TEST: Client cleanup completed");
            }
        }
        finally
        {
            localServer.Stop();
            Console.WriteLine("TEST: Local server stopped");
        }
    }

    private async Task AcceptAndAuthenticateClient()
    {
        using var serverClient = await _server.AcceptTcpClientAsync();
        using var sslStream = new SslStream(serverClient.GetStream(), false);
        await sslStream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
        {
            ServerCertificate = _certificate,
            ClientCertificateRequired = false,
            EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13
        });
        // Keep the server alive until the test completes
        await Task.Delay(1000);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _server.Stop();
            _certificate.Dispose();
            _disposed = true;
        }
    }
} 