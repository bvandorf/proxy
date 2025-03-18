using CsProxyTools.Interfaces;
using Microsoft.Extensions.Logging;

namespace CsProxyTools.Helpers;

public class ProxyConnection : IAsyncDisposable
{
    private readonly IConnection _client;
    private readonly IConnection _server;
    private readonly ILogger _logger;
    private readonly string _clientId;
    private readonly string _serverId;
    private bool _isDisposed;

    public ProxyConnection(
        IConnection client,
        IConnection server,
        ILogger logger,
        string? clientId = null,
        string? serverId = null)
    {
        _client = client;
        _server = server;
        _logger = logger;
        _clientId = clientId ?? client.Id;
        _serverId = serverId ?? server.Id;

        // Set up event handlers
        _client.DataReceived += OnClientDataReceived;
        _server.DataReceived += OnServerDataReceived;
        _client.ConnectionClosed += OnClientConnectionClosed;
        _server.ConnectionClosed += OnServerConnectionClosed;
    }

    private async void OnClientDataReceived(object? sender, DataReceivedEventArgs args)
    {
        try
        {
            _logger.LogInformation("Client {ClientId} -> Server {ServerId}: {Length} bytes", 
                _clientId, _serverId, args.Data.Length);
            await _server.WriteAsync(args.Data);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error forwarding data from client {ClientId} to server {ServerId}", 
                _clientId, _serverId);
        }
    }

    private async void OnServerDataReceived(object? sender, DataReceivedEventArgs args)
    {
        try
        {
            _logger.LogInformation("Server {ServerId} -> Client {ClientId}: {Length} bytes", 
                _serverId, _clientId, args.Data.Length);
            await _client.WriteAsync(args.Data);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error forwarding data from server {ServerId} to client {ClientId}", 
                _serverId, _clientId);
        }
    }

    private void OnClientConnectionClosed(object? sender, ConnectionEventArgs args)
    {
        _logger.LogInformation("Client {ClientId} connection closed", _clientId);
        DisposeAsync().ConfigureAwait(false);
    }

    private void OnServerConnectionClosed(object? sender, ConnectionEventArgs args)
    {
        _logger.LogInformation("Server {ServerId} connection closed", _serverId);
        DisposeAsync().ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        if (_isDisposed) return;

        try
        {
            // Remove event handlers
            _client.DataReceived -= OnClientDataReceived;
            _server.DataReceived -= OnServerDataReceived;
            _client.ConnectionClosed -= OnClientConnectionClosed;
            _server.ConnectionClosed -= OnServerConnectionClosed;

            // Dispose both connections
            await _client.DisposeAsync();
            await _server.DisposeAsync();

            _isDisposed = true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error disposing proxy connection between client {ClientId} and server {ServerId}", 
                _clientId, _serverId);
            throw;
        }
    }
} 