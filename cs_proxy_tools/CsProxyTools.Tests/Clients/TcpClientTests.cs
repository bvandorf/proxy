using System.Net;
using System.Net.Sockets;
using CsProxyTools.Clients;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace CsProxyTools.Tests.Clients;

public class TcpClientTests : IDisposable
{
    private readonly Mock<ILogger> _loggerMock;
    private readonly TcpListener _server;
    private readonly string _host = "127.0.0.1";
    private readonly int _port = 12345;
    private bool _disposed;

    public TcpClientTests()
    {
        _loggerMock = new Mock<ILogger>();
        _server = new TcpListener(IPAddress.Parse(_host), _port);
        _server.Start();
    }

    [Fact(Timeout = 30000)]
    public async Task ConnectAsync_ShouldConnect_WhenServerIsAvailable()
    {
        // Arrange
        var client = new CsProxyTools.Clients.TcpClient(_loggerMock.Object, _host, _port);
        var connectionStarted = false;
        client.Connected += (s, e) => connectionStarted = true;
        
        // Timeout for all operations
        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        // Start a server that just accepts connections
        var serverTask = Task.Run(async () =>
        {
            try
            {
                var serverClient = await _server.AcceptTcpClientAsync().WaitAsync(timeoutCts.Token);
                
                // Keep connection open until test is done
                await Task.Delay(1000, timeoutCts.Token);
                serverClient.Close();
            }
            catch (Exception)
            {
                // Ignore exceptions
            }
        });

        try
        {
            // Act - Connect client
            await client.ConnectAsync(timeoutCts.Token);

            // Assert
            Assert.True(connectionStarted);
        }
        finally
        {
            await client.DisposeAsync();
            
            // Ensure server task completes
            var serverCleanupCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try
            {
                await serverTask.WaitAsync(serverCleanupCts.Token);
            }
            catch (TimeoutException)
            {
                // Ignore timeout during cleanup
            }
        }
    }

    [Fact(Timeout = 30000)]
    public async Task ConnectAsync_ShouldThrowException_WhenServerIsNotAvailable()
    {
        // Arrange
        _server.Stop();
        var client = new CsProxyTools.Clients.TcpClient(_loggerMock.Object, _host, _port);
        
        // Timeout for operation
        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        try
        {
            // Act & Assert - Accept either SocketException or TimeoutException
            var exception = await Assert.ThrowsAnyAsync<Exception>(async () => 
                await client.ConnectAsync(timeoutCts.Token));
                
            // Verify it's one of our expected exception types
            Assert.True(
                exception is SocketException || exception is TimeoutException,
                $"Expected SocketException or TimeoutException, got {exception.GetType().Name}");
        }
        finally
        {
            // Always dispose client
            await client.DisposeAsync();
        }
    }

    [Fact(Timeout = 30000)]
    public async Task DisconnectAsync_ShouldDisconnect_WhenConnected()
    {
        Console.WriteLine("TEST: Starting simplified DisconnectAsync test");
        // Arrange
        var tcs = new TaskCompletionSource<bool>();
        
        // Use shorter timeouts for better test reliability
        using var testTimeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        
        var serverTask = Task.Run(async () => {
            try {
                Console.WriteLine("TEST: Server accepting connection");
                var client = await _server.AcceptTcpClientAsync().WaitAsync(testTimeoutCts.Token);
                Console.WriteLine("TEST: Server accepted connection, waiting");
                
                // Wait until the test completes or timeout
                try {
                    await Task.Delay(8000, testTimeoutCts.Token);
                } catch (OperationCanceledException) {
                    Console.WriteLine("TEST: Server delay canceled");
                }
            }
            catch (Exception ex) {
                Console.WriteLine($"TEST: Server error: {ex.Message}");
            }
        });

        var client = new CsProxyTools.Clients.TcpClient(_loggerMock.Object, _host, _port);
        var connectionClosed = false;
        client.Disconnected += (s, e) => {
            Console.WriteLine("TEST: Disconnected event triggered");
            connectionClosed = true;
            tcs.TrySetResult(true);
        };

        // Act
        try {
            Console.WriteLine("TEST: Connecting client");
            await client.ConnectAsync(testTimeoutCts.Token);
            Console.WriteLine("TEST: Client connected, now disconnecting");
            
            await client.DisconnectAsync(testTimeoutCts.Token);
            Console.WriteLine("TEST: Client disconnected");
            
            // Use a separate timeout just for waiting for the event
            using var eventTimeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            await tcs.Task.WaitAsync(eventTimeoutCts.Token);
            
            // Assert
            Assert.True(connectionClosed);
            Console.WriteLine("TEST: Test completed successfully");
        }
        catch (Exception ex) {
            Console.WriteLine($"TEST: Exception in test: {ex.GetType().Name} - {ex.Message}");
            throw;
        }
        finally {
            Console.WriteLine("TEST: Cleanup");
            testTimeoutCts.Cancel(); // Cancel the server task
            await client.DisposeAsync();
            
            // Wait for server task with short timeout
            try {
                await serverTask.WaitAsync(TimeSpan.FromSeconds(1));
            } catch (TimeoutException) {
                Console.WriteLine("TEST: Server task cleanup timed out");
            }
        }
    }

    [Fact(Timeout = 30000)]
    public async Task WriteAsync_ShouldThrowException_WhenNotConnected()
    {
        // Arrange - Use an invalid host to ensure auto-connect fails
        var client = new CsProxyTools.Clients.TcpClient(_loggerMock.Object, "invalid-host-that-does-not-exist", 12345);

        var data = new byte[] { 1, 2, 3 };

        // Act & Assert
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            client.WriteAsync(new ReadOnlyMemory<byte>(data)));
        await client.DisposeAsync();
    }

    [Fact(Timeout = 30000)]
    public async Task WriteAsync_ShouldSendData_WhenConnected()
    {
        // Arrange
        var client = new CsProxyTools.Clients.TcpClient(_loggerMock.Object, _host, _port);
        var receivedData = Array.Empty<byte>();
        var data = new byte[] { 1, 2, 3 };
        
        // Timeout for all operations
        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        // Start a server that accepts a connection and reads data
        var serverDataReceived = new TaskCompletionSource<byte[]>();
        var serverTask = Task.Run(async () =>
        {
            try
            {
                var serverClient = await _server.AcceptTcpClientAsync().WaitAsync(timeoutCts.Token);
                var buffer = new byte[1024];
                var bytesRead = await serverClient.GetStream().ReadAsync(buffer, 0, buffer.Length, timeoutCts.Token);
                serverDataReceived.SetResult(buffer.Take(bytesRead).ToArray());
                serverClient.Close();
            }
            catch (Exception ex)
            {
                serverDataReceived.TrySetException(ex);
            }
        });

        try
        {
            // Connect client
            await client.ConnectAsync(timeoutCts.Token);
            
            // Write data
            await client.WriteAsync(new ReadOnlyMemory<byte>(data), timeoutCts.Token);
            
            // Wait for server to receive data
            receivedData = await serverDataReceived.Task.WaitAsync(timeoutCts.Token);
            
            // Assert
            Assert.Equal(data, receivedData);
        }
        finally
        {
            await client.DisposeAsync();
            
            // Ensure server task completes
            var serverCleanupCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try
            {
                await serverTask.WaitAsync(serverCleanupCts.Token);
            }
            catch (TimeoutException)
            {
                // Ignore timeout during cleanup
            }
        }
    }

    [Fact(Timeout = 30000)]
    public async Task DataReceived_ShouldBeTriggered_WhenDataIsReceived()
    {
        // Arrange
        var client = new CsProxyTools.Clients.TcpClient(_loggerMock.Object, _host, _port);
        var receivedData = Array.Empty<byte>();
        var clientDataReceived = new TaskCompletionSource<byte[]>();
        client.DataReceived += (s, e) => clientDataReceived.TrySetResult(e.Data.ToArray());
        
        // Timeout for all operations
        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        // Start a server that accepts a connection and sends data
        var serverTask = Task.Run(async () =>
        {
            try
            {
                var serverClient = await _server.AcceptTcpClientAsync().WaitAsync(timeoutCts.Token);
                
                // Send data to client
                var data = new byte[] { 1, 2, 3 };
                await serverClient.GetStream().WriteAsync(data, 0, data.Length, timeoutCts.Token);
                
                // Keep connection open until test is done
                await Task.Delay(1000, timeoutCts.Token);
                serverClient.Close();
            }
            catch (OperationCanceledException)
            {
                // Ignore cancellation
            }
            catch (Exception)
            {
                // Ignore other exceptions
            }
        });

        try
        {
            // Connect client
            await client.ConnectAsync(timeoutCts.Token);
            
            // Wait for client to receive data
            receivedData = await clientDataReceived.Task.WaitAsync(timeoutCts.Token);
            
            // Assert
            Assert.Equal(new byte[] { 1, 2, 3 }, receivedData);
        }
        finally
        {
            await client.DisposeAsync();
            
            // Ensure server task completes
            var serverCleanupCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try
            {
                await serverTask.WaitAsync(serverCleanupCts.Token);
            }
            catch (TimeoutException)
            {
                // Ignore timeout during cleanup
            }
        }
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _server.Stop();
            _disposed = true;
        }
    }
} 