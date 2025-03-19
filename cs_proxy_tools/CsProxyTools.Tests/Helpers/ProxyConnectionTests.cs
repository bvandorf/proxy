using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using CsProxyTools.Clients;
using CsProxyTools.Helpers;
using CsProxyTools.Interfaces;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using TcpClientImpl = CsProxyTools.Clients.TcpClient;

namespace CsProxyTools.Tests.Helpers;

public class ProxyConnectionTests : IDisposable
{
    private readonly Mock<ILogger> _loggerMock;
    private readonly TcpListener _clientServer;
    private readonly TcpListener _targetServer;
    private readonly int _clientPort = 12350;
    private readonly int _targetPort = 12351;
    private readonly string _host = "127.0.0.1";
    private bool _disposed;

    public ProxyConnectionTests()
    {
        _loggerMock = new Mock<ILogger>();
        
        // Setup client side server (simulates incoming connection)
        _clientServer = new TcpListener(IPAddress.Parse(_host), _clientPort);
        _clientServer.Start();
        
        // Setup target server (simulates remote server)
        _targetServer = new TcpListener(IPAddress.Parse(_host), _targetPort);
        _targetServer.Start();
    }
    
    [Fact(Timeout = 30000)]
    public async Task Start_ShouldConnectSuccessfully_WhenTargetServerAvailable()
    {
        // Start target server
        _targetServer.Start();
        
        // Create client connection
        var clientConnection = new TestConnection(_loggerMock.Object);
        
        // Create target client
        var tcpClient = new TcpClientImpl(_loggerMock.Object, "127.0.0.1", _targetPort);
        
        // Create proxy connection
        var proxyConnection = new ProxyConnection(_loggerMock.Object, "test", clientConnection, tcpClient);
        
        // Start accepting connections on the target server
        var acceptTask = Task.Run(async () =>
        {
            var client = await _targetServer.AcceptTcpClientAsync();
            return client;
        });
        
        // Act
        await proxyConnection.Start();
        
        // Wait for the connection to be accepted (with timeout)
        var targetClient1 = await acceptTask.WaitAsync(TimeSpan.FromSeconds(5));
        
        // Assert
        Assert.NotNull(targetClient1);
        Assert.True(targetClient1.Connected);
        
        // Cleanup
        await proxyConnection.DisposeAsync();
    }
    
    [Fact(Timeout = 30000)]
    public async Task Start_ShouldRetryAndConnect_WhenTargetServerBecomesAvailable()
    {
        // Don't start target server yet
        
        // Create client connection
        var clientConnection = new TestConnection(_loggerMock.Object);
        
        // Create target client
        var tcpClient = new TcpClientImpl(_loggerMock.Object, "127.0.0.1", _targetPort);
        
        // Create the proxy connection
        var proxyConnection = new ProxyConnection(
            _loggerMock.Object,
            "test-client-id",
            clientConnection,
            tcpClient);
            
        // Start the proxy connection in a background task (it will retry connecting)
        var startTask = Task.Run(async () => 
        {
            await proxyConnection.Start();
        });
        
        // Wait a moment to allow initial connection attempts to fail
        await Task.Delay(2000);
        
        // Now restart the target server to allow the retry to succeed
        _targetServer.Start();
        
        // Start accepting connections on the target server
        var acceptTask = Task.Run(async () =>
        {
            var client = await _targetServer.AcceptTcpClientAsync();
            return client;
        });
        
        // Wait for both tasks to complete (with timeout)
        await Task.WhenAny(startTask, Task.Delay(10000));
        var targetClient1 = await acceptTask.WaitAsync(TimeSpan.FromSeconds(10));
        
        // Assert
        Assert.NotNull(targetClient1);
        Assert.True(targetClient1.Connected);
        
        // Cleanup
        await proxyConnection.DisposeAsync();
    }
    
    [Fact(Timeout = 30000)]
    public async Task Start_ShouldTimeout_WhenTargetServerNeverBecomesAvailable()
    {
        // Don't start target server
        
        // Create client connection
        var clientConnection = new TestConnection(_loggerMock.Object);
        
        // Create target client with non-routable IP to force failure
        var tcpClient = new TcpClientImpl(_loggerMock.Object, "192.168.255.255", _targetPort);
        
        // Create the proxy connection with a custom field to reduce the timeout for testing
        var proxyConnection = new ProxyConnection(
            _loggerMock.Object,
            "test-client-id",
            clientConnection,
            tcpClient);
            
        // Act & Assert - Accept either TimeoutException or Exception with timeout in the message or socket permission errors
        var exception = await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            // Set a shorter timeout for the test
            using var cts = new CancellationTokenSource(5000);
            await proxyConnection.Start().WaitAsync(cts.Token);
        });
        
        // Assert the exception message contains timeout information or it's a TimeoutException or socket permission issue
        Assert.True(
            exception is TimeoutException || 
            exception.Message.Contains("timed out", StringComparison.OrdinalIgnoreCase) ||
            exception.Message.Contains("socket", StringComparison.OrdinalIgnoreCase) && 
            exception.Message.Contains("permission", StringComparison.OrdinalIgnoreCase),
            $"Expected timeout or socket permission exception, got: {exception.GetType().Name}: {exception.Message}");
        
        // Cleanup
        await proxyConnection.DisposeAsync();
    }
    
    [Fact(Timeout = 30000)]
    public async Task DataFlow_ShouldPassDataBidirectionally_WhenConnected()
    {
        // Use unique ports for this test
        int targetPort = 12341;
        
        // Create dedicated target server for this test
        var targetServer = new TcpListener(IPAddress.Parse(_host), targetPort);
        
        // Start server
        targetServer.Start();
        
        try
        {
            // Create connections - use TestConnection which simulates client connections
            var clientConnection = new TestConnection(_loggerMock.Object);
            var tcpClient = new TcpClientImpl(_loggerMock.Object, "127.0.0.1", targetPort);
            
            // Create the proxy connection
            var proxyConnection = new ProxyConnection(
                _loggerMock.Object,
                "test-client-id",
                clientConnection,
                tcpClient);
            
            // Start accepting connection on target server
            var targetTask = Task.Run(async () =>
            {
                var client = await targetServer.AcceptTcpClientAsync();
                return client;
            });
            
            // Start the proxy
            await proxyConnection.Start();
            
            // Get the accepted target connection
            var acceptedTarget = await targetTask.WaitAsync(TimeSpan.FromSeconds(5));
            
            // Now simulate the client sending data through the TestConnection
            var testData = new byte[] { 1, 2, 3, 4, 5 };
            await clientConnection.SetDataToRead(testData);
            
            // Wait a moment for data to flow through
            await Task.Delay(1000);
            
            // Read data from target
            var buffer = new byte[1024];
            acceptedTarget.GetStream().ReadTimeout = 2000;
            var bytesRead = await acceptedTarget.GetStream().ReadAsync(buffer);
            
            // Assert data was received correctly at the target
            Assert.Equal(testData.Length, bytesRead);
            Assert.Equal(testData, buffer.Take(bytesRead).ToArray());
            
            // Now send data from target to client
            var responseData = new byte[] { 10, 20, 30, 40, 50 };
            await acceptedTarget.GetStream().WriteAsync(responseData);
            
            // Wait a moment for data to flow through
            await Task.Delay(1000);
            
            // Verify that the data was written to the TestConnection's DataWritten property
            Assert.Equal(responseData.Length, clientConnection.DataWritten.Count);
            Assert.Equal(responseData, clientConnection.DataWritten.ToArray());
            
            // Cleanup
            await proxyConnection.DisposeAsync();
            acceptedTarget.Close();
        }
        finally
        {
            // Always stop the server
            targetServer.Stop();
        }
    }
    
    [Fact]
    public async Task Start_ShouldHandleGracefully_WhenClientDisconnectsBeforeTargetConnects()
    {
        // Don't start target server yet (to ensure connection attempts will take time)
        
        // Create client connection that will disconnect shortly
        var clientConnection = new TestConnection(_loggerMock.Object);
        
        // Create target client with a non-routable IP to force connection failure
        var tcpClient = new TcpClientImpl(_loggerMock.Object, "192.168.255.255", _targetPort);
        
        // Create proxy connection
        var proxyConnection = new ProxyConnection(_loggerMock.Object, "test", clientConnection, tcpClient);
        
        // Create a flag to track if an exception was thrown, as expected
        var exceptionThrown = false;
        
        // Start the connection (this will retry connecting to target)
        var startTask = Task.Run(async () => 
        {
            try
            {
                await proxyConnection.Start();
            }
            catch (Exception)
            {
                // We expect an exception when the client disconnects during connection attempts
                exceptionThrown = true;
            }
        });
        
        // Wait briefly to allow the connection attempt to begin
        await Task.Delay(500);
        
        // Simulate client disconnecting
        await clientConnection.DisconnectAsync();
        
        // Wait for the start task to complete (should be fast once client disconnects)
        var completedTask = await Task.WhenAny(startTask, Task.Delay(5000));
        
        // Assert that the task completed (didn't time out)
        Assert.Equal(startTask, completedTask);
        Assert.True(exceptionThrown, "Expected an exception to be thrown when client disconnects during connection");
        
        // Cleanup
        await proxyConnection.DisposeAsync();
    }
    
    public void Dispose()
    {
        if (!_disposed)
        {
            _clientServer.Stop();
            _targetServer.Stop();
            _disposed = true;
        }
    }
    
    // Helper test class for connection testing
    private class TestConnection : IConnection
    {
        private readonly ILogger _logger;
        private TaskCompletionSource<bool> _readCompletionSource;
        private byte[] _dataToRead;
        public List<byte> DataWritten { get; } = new List<byte>();
        public string Id { get; } = "test-connection";
        public bool IsConnected { get; set; } = true;
        
        public TestConnection(ILogger logger)
        {
            _logger = logger;
            _readCompletionSource = new TaskCompletionSource<bool>();
            _dataToRead = Array.Empty<byte>();
        }
        
        public async Task<ReadResult> ReadAsync(CancellationToken cancellationToken = default)
        {
            await _readCompletionSource.Task.WaitAsync(cancellationToken);
            
            // Reset for next read
            _readCompletionSource = new TaskCompletionSource<bool>();
            
            // Create a buffer with our test data
            var readResult = new ReadResult(
                new ReadOnlySequence<byte>(_dataToRead),
                isCanceled: false,
                isCompleted: false);
            
            return readResult;
        }
        
        public Task WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            DataWritten.AddRange(buffer.ToArray());
            return Task.CompletedTask;
        }
        
        public async Task SetDataToRead(byte[] data)
        {
            _dataToRead = data;
            var oldTcs = _readCompletionSource;
            _readCompletionSource = new TaskCompletionSource<bool>();
            oldTcs.SetResult(true);
            
            // Also trigger the DataReceived event to simulate real behavior
            DataReceived?.Invoke(this, new DataReceivedEventArgs(Id, new ReadOnlyMemory<byte>(data)));
            
            return;
        }
        
        public event EventHandler<ConnectionEventArgs>? ConnectionClosed;
        public event EventHandler<ConnectionEventArgs>? ConnectionStarted;
        public event EventHandler<DataReceivedEventArgs>? DataReceived;
        
        public ValueTask DisposeAsync()
        {
            IsConnected = false;
            return ValueTask.CompletedTask;
        }
        
        public Task StartAsync(CancellationToken cancellationToken = default)
        {
            ConnectionStarted?.Invoke(this, new ConnectionEventArgs(Id));
            return Task.CompletedTask;
        }
        
        public Task StopAsync(CancellationToken cancellationToken = default)
        {
            if (IsConnected)
            {
                IsConnected = false;
                // Invoke the event but only if we were connected to avoid infinite recursion
                ConnectionClosed?.Invoke(this, new ConnectionEventArgs(Id));
            }
            return Task.CompletedTask;
        }
        
        public Task DisconnectAsync()
        {
            if (IsConnected)
            {
                IsConnected = false;
                // Invoke the event but only if we were connected to avoid infinite recursion
                ConnectionClosed?.Invoke(this, new ConnectionEventArgs(Id));
            }
            return Task.CompletedTask;
        }
    }
} 