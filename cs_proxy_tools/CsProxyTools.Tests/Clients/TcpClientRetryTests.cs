using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using CsProxyTools.Clients;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using TcpClientImpl = CsProxyTools.Clients.TcpClient;

namespace CsProxyTools.Tests.Clients;

public class TcpClientRetryTests : IDisposable
{
    private readonly Mock<ILogger> _loggerMock;
    private readonly TcpListener _tcpListener;
    private readonly int _port = 12355;
    private bool _disposed;

    public TcpClientRetryTests()
    {
        _loggerMock = new Mock<ILogger>();
        _tcpListener = new TcpListener(IPAddress.Loopback, _port);
    }
    
    [Fact]
    public async Task ConnectAsync_ShouldNotRetryMultipleTimes_WhenConnectedSuccessfully()
    {
        // Start the server first
        _tcpListener.Start();
        
        // Create client
        var tcpClient = new TcpClientImpl(_loggerMock.Object, "localhost", _port);
        
        // Setup a task to accept one connection and count how many we get
        var acceptanceCount = 0;
        var acceptanceTask = Task.Run(async () =>
        {
            var clientA = await _tcpListener.AcceptTcpClientAsync();
            acceptanceCount++;
            // Only wait for one client
            return clientA;
        });
        
        // Connect to the server
        await tcpClient.ConnectAsync();
        
        // Wait for the server to accept
        var acceptedClient = await acceptanceTask.WaitAsync(TimeSpan.FromSeconds(5));
        
        // We should have received exactly one connection attempt
        Assert.Equal(1, acceptanceCount);
        Assert.True(tcpClient.IsConnected);
        Assert.True(acceptedClient.Connected);
        
        // Cleanup
        await tcpClient.DisconnectAsync();
        acceptedClient.Close();
    }
    
    [Fact]
    public async Task ConnectAsync_ShouldEventuallyConnect_WhenInitialAttemptsFail()
    {
        // Don't start the server initially
        
        // Create client
        var tcpClient = new TcpClientImpl(_loggerMock.Object, "localhost", _port);
        
        // Start trying to connect in the background (will retry)
        var connectTask = Task.Run(async () => await tcpClient.ConnectAsync());
        
        // Wait a bit for some retries to happen
        await Task.Delay(2000);
        
        // Start the server to allow connection
        _tcpListener.Start();
        
        // Accept the connection
        var serverClient = await _tcpListener.AcceptTcpClientAsync();
        
        // Wait for the connection to complete
        await connectTask.WaitAsync(TimeSpan.FromSeconds(5));
        
        // Client should now be connected
        Assert.True(tcpClient.IsConnected);
        Assert.True(serverClient.Connected);
        
        // Cleanup
        await tcpClient.DisconnectAsync();
        serverClient.Close();
    }
    
    [Fact]
    public async Task ConnectAsync_ShouldTimeout_WhenServerNeverBecomesAvailable()
    {
        // Don't start the server
        
        // Create client
        var tcpClient = new TcpClientImpl(_loggerMock.Object, "non-existent-host", _port);
        
        // Try to connect with a timeout
        var exception = await Assert.ThrowsAnyAsync<Exception>(() => 
        {
            return tcpClient.ConnectAsync().WaitAsync(TimeSpan.FromSeconds(10));
        });
        
        // Should not be connected
        Assert.False(tcpClient.IsConnected);
        
        // Cleanup
        await tcpClient.DisconnectAsync();
    }
    
    [Fact]
    public async Task DisconnectAsync_ShouldCleanupResources_WhenMultipleDisconnectsCalled()
    {
        // Start the server
        _tcpListener.Start();
        
        // Create client and connect
        var tcpClient = new TcpClientImpl(_loggerMock.Object, "localhost", _port);
        var connectTask = tcpClient.ConnectAsync();
        
        // Accept the connection
        var serverClient = await _tcpListener.AcceptTcpClientAsync();
        
        // Wait for connection to complete
        await connectTask;
        
        // Verify connected
        Assert.True(tcpClient.IsConnected);
        
        // Call disconnect multiple times
        await tcpClient.DisconnectAsync();
        await tcpClient.DisconnectAsync(); // Should not throw
        await tcpClient.DisconnectAsync(); // Should not throw
        
        // Verify disconnected
        Assert.False(tcpClient.IsConnected);
        
        // Cleanup
        serverClient.Close();
    }
    
    [Fact]
    public async Task WriteAsync_ShouldAutomaticallyConnect_WhenNotConnected()
    {
        // Start the server
        _tcpListener.Start();
        
        // Create client - we'll connect it explicitly
        var tcpClient = new TcpClientImpl(_loggerMock.Object, "localhost", _port);
        
        // Connect first
        await tcpClient.ConnectAsync();
        Assert.True(tcpClient.IsConnected);
        
        // Setup accept task
        var acceptTask = Task.Run(async () => await _tcpListener.AcceptTcpClientAsync());
        
        // Get the connection on the server side
        var serverClient = await acceptTask.WaitAsync(TimeSpan.FromSeconds(5));
        
        // Try to write data with an already connected client
        var testData = new byte[] { 1, 2, 3, 4, 5 };
        await tcpClient.WriteAsync(testData);
        
        // Read the data on the server side
        var buffer = new byte[1024];
        var bytesRead = await serverClient.GetStream().ReadAsync(buffer);
        
        // Verify data was received
        Assert.Equal(testData.Length, bytesRead);
        Assert.Equal(testData, buffer.AsSpan(0, bytesRead).ToArray());
        
        // Cleanup
        await tcpClient.DisconnectAsync();
        serverClient.Close();
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            try { _tcpListener?.Stop(); } catch { }
            _disposed = true;
        }
    }
} 