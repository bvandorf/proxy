using CsProxyTools.Interfaces;
using Microsoft.Extensions.Logging;
using System.Net.Sockets;

namespace CsProxyTools.Helpers;

/// <summary>
/// Delegate that creates a new client connection for a given connection ID
/// </summary>
/// <param name="connectionId">The unique ID of the connection</param>
/// <returns>A new IClient instance</returns>
public delegate IClient ClientFactory(string connectionId);

public class ProxyConnection : IAsyncDisposable
{
    private readonly IConnection _client;
    private readonly IClient _server;
    private readonly ILogger _logger;
    private readonly string _clientId;
    private readonly string _serverId;
    private bool _isDisposed;
    private readonly CancellationTokenSource _cts = new CancellationTokenSource();
    
    // Connection timeouts and retry settings
    private const int ConnectionTimeoutMs = 30000; // 30 seconds total timeout
    private const int MaxRetryAttempts = 5;
    private const int RetryDelayMs = 1000; // 1 second between retries

    /// <summary>
    /// Creates a new proxy connection with a specific target client
    /// </summary>
    public ProxyConnection(
        ILogger logger,
        string clientId, 
        IConnection client,
        IClient server)
    {
        _client = client;
        _server = server;
        _logger = logger;
        _clientId = clientId;
        _serverId = server.Id;

        // Set up event handlers
        _client.DataReceived += Client_DataReceived;
        _server.DataReceived += Server_DataReceived;
        _client.ConnectionClosed += Client_Disconnected;
        _server.Disconnected += Server_Disconnected;
    }
    
    /// <summary>
    /// Creates a new proxy connection with a factory to create the target client
    /// </summary>
    public ProxyConnection(
        ILogger logger,
        string clientId, 
        IConnection client,
        ClientFactory createTargetClient)
    {
        _client = client;
        _logger = logger;
        _clientId = clientId;
        
        // Create the target client using the factory
        _server = createTargetClient(clientId);
        _serverId = _server.Id;

        // Set up event handlers
        _client.DataReceived += Client_DataReceived;
        _server.DataReceived += Server_DataReceived;
        _client.ConnectionClosed += Client_Disconnected;
        _server.Disconnected += Server_Disconnected;
    }

    public async Task Start()
    {
        try 
        {
            _logger.LogInformation("Starting proxy connection between client {ClientId} and server {ServerId}", 
                _clientId, _serverId);
            
            // Connect to the server with retry logic
            bool connected = false;
            int attemptCount = 0;
            Exception? lastException = null;
            
            // Set a timeout for the entire connect operation
            using var timeoutCts = new CancellationTokenSource(ConnectionTimeoutMs);
            using var linkedCts = !_cts.IsCancellationRequested ? 
                CancellationTokenSource.CreateLinkedTokenSource(timeoutCts.Token, _cts.Token) : 
                CancellationTokenSource.CreateLinkedTokenSource(timeoutCts.Token);
            
            while (attemptCount < MaxRetryAttempts && !connected)
            {
                try
                {
                    attemptCount++;
                    _logger.LogDebug("Connecting to target server, attempt {Attempt}/{MaxAttempts}", 
                        attemptCount, MaxRetryAttempts);
                    
                    await _server.ConnectAsync(linkedCts.Token);
                    connected = true;
                    
                    _logger.LogInformation("Successfully connected to target server on attempt {Attempt}", attemptCount);
                }
                catch (OperationCanceledException)
                {
                    if (timeoutCts.IsCancellationRequested)
                    {
                        _logger.LogError("Connection to target server timed out after {TimeoutMs}ms", ConnectionTimeoutMs);
                        throw new TimeoutException($"Connection to target server timed out after {ConnectionTimeoutMs}ms");
                    }
                    
                    throw; // Rethrow if it's from our internal _cts
                }
                catch (Exception ex)
                {
                    lastException = ex;
                    
                    if (attemptCount < MaxRetryAttempts)
                    {
                        _logger.LogWarning(ex, "Failed to connect to target server on attempt {Attempt}/{MaxAttempts}, " + 
                            "retrying in {RetryDelayMs}ms...", attemptCount, MaxRetryAttempts, RetryDelayMs);
                        
                        try
                        {
                            await Task.Delay(RetryDelayMs, linkedCts.Token);
                        }
                        catch (OperationCanceledException)
                        {
                            if (timeoutCts.IsCancellationRequested)
                            {
                                _logger.LogError("Connection to target server timed out after {TimeoutMs}ms", ConnectionTimeoutMs);
                                throw new TimeoutException($"Connection to target server timed out after {ConnectionTimeoutMs}ms");
                            }
                            
                            throw; // Rethrow if it's from our internal _cts
                        }
                    }
                    else
                    {
                        _logger.LogError(ex, "Failed to connect to target server after {MaxAttempts} attempts", MaxRetryAttempts);
                        throw;
                    }
                }
            }
            
            if (!connected)
            {
                if (lastException != null)
                {
                    throw lastException;
                }
                throw new InvalidOperationException($"Failed to connect to target server");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error starting proxy connection between client {ClientId} and server {ServerId}", 
                _clientId, _serverId);
            
            // Clean up and propagate the error
            await DisposeAsync();
            throw;
        }
    }

    private void Client_DataReceived(object? sender, DataReceivedEventArgs args)
    {
        try
        {
            var clientEndpoint = args.RemoteEndpoint ?? "unknown";
            _logger.LogInformation("Client {ClientEndpoint}:{ClientId} -> Server {ServerId}: {Length} bytes\n{DataPreview}",
                clientEndpoint, _clientId, _serverId, args.Data.Length, StringUtils.GetDataPreview(args.Data));
            _ = _server.WriteAsync(args.Data);
        }
        catch (Exception ex)
        {
            var clientEndpoint = args.RemoteEndpoint ?? "unknown";
            _logger.LogError(ex, "Error forwarding data from client {ClientEndpoint}:{ClientId} to server {ServerId}",
                clientEndpoint, _clientId, _serverId);
        }
    }

    private void Server_DataReceived(object? sender, DataReceivedEventArgs args)
    {
        try
        {
            var serverEndpoint = args.RemoteEndpoint ?? "unknown";
            _logger.LogInformation("Server {ServerEndpoint}:{ServerId} -> Client {ClientId}: {Length} bytes\n{DataPreview}",
                serverEndpoint, _serverId, _clientId, args.Data.Length, StringUtils.GetDataPreview(args.Data));
            _ = _client.WriteAsync(args.Data);
        }
        catch (Exception ex)
        {
            var serverEndpoint = args.RemoteEndpoint ?? "unknown";
            _logger.LogError(ex, "Error forwarding data from server {ServerEndpoint}:{ServerId} to client {ClientId}",
                serverEndpoint, _serverId, _clientId);
        }
    }

    private void Client_Disconnected(object? sender, ConnectionEventArgs args)
    {
        var clientEndpoint = args.RemoteEndpoint ?? "unknown";
        _logger.LogInformation("Client {ClientEndpoint}:{ClientId} connection closed", 
            clientEndpoint, _clientId);
        
        // Cancel any ongoing operations safely
        if (!_cts.IsCancellationRequested)
        {
            try
            {
                _cts.Cancel();
            }
            catch (ObjectDisposedException)
            {
                // Token was already disposed, ignore
            }
        }
        
        // Disconnect the server
        _server.DisconnectAsync().ContinueWith(t => {
            if (t.IsFaulted)
            {
                _logger.LogError(t.Exception, "Error disconnecting server after client disconnected");
            }
        });
    }

    private void Server_Disconnected(object? sender, ConnectionEventArgs args)
    {
        var serverEndpoint = args.RemoteEndpoint ?? "unknown";
        _logger.LogInformation("Server {ServerEndpoint}:{ServerId} connection closed", 
            serverEndpoint, _serverId);
        
        // Cancel any ongoing operations safely
        if (!_cts.IsCancellationRequested)
        {
            try
            {
                _cts.Cancel();
            }
            catch (ObjectDisposedException)
            {
                // Token was already disposed, ignore
            }
        }
        
        // Disconnect the client
        _client.StopAsync().ContinueWith(t => {
            if (t.IsFaulted)
            {
                _logger.LogError(t.Exception, "Error disconnecting client after server disconnected");
            }
        });
    }

    public async ValueTask DisposeAsync()
    {
        if (_isDisposed) return;

        try
        {
            // Set the disposed flag first to prevent race conditions
            _isDisposed = true;
            
            // Cancel any ongoing operations safely
            if (!_cts.IsCancellationRequested)
            {
                try
                {
                    _cts.Cancel();
                }
                catch (ObjectDisposedException)
                {
                    // Token was already disposed, ignore
                }
            }
            
            // Remove event handlers to prevent further callbacks
            _client.DataReceived -= Client_DataReceived;
            _server.DataReceived -= Server_DataReceived;
            _client.ConnectionClosed -= Client_Disconnected;
            _server.Disconnected -= Server_Disconnected;

            // Dispose both connections
            try
            {
                await _client.DisposeAsync();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error disposing client connection {ClientId}", _clientId);
            }
            
            try
            {
                await _server.DisposeAsync();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error disposing server connection {ServerId}", _serverId);
            }
            
            // Dispose cancellation token source safely
            try
            {
                _cts.Dispose();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error disposing cancellation token source");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error disposing proxy connection between client {ClientId} and server {ServerId}", 
                _clientId, _serverId);
            throw;
        }
    }
} 