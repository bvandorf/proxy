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
        _client.DataReceived += Client_DataReceived;
        _server.DataReceived += Server_DataReceived;
        _client.ConnectionClosed += Client_Disconnected;
        _server.ConnectionClosed += Server_Disconnected;
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
        _server.StopAsync().GetAwaiter().GetResult();
    }

    private void Server_Disconnected(object? sender, ConnectionEventArgs args)
    {
        var serverEndpoint = args.RemoteEndpoint ?? "unknown";
        _logger.LogInformation("Server {ServerEndpoint}:{ServerId} connection closed", 
            serverEndpoint, _serverId);
        _client.StopAsync().GetAwaiter().GetResult();
    }

    public async ValueTask DisposeAsync()
    {
        if (_isDisposed) return;

        try
        {
            // Remove event handlers
            _client.DataReceived -= Client_DataReceived;
            _server.DataReceived -= Server_DataReceived;
            _client.ConnectionClosed -= Client_Disconnected;
            _server.ConnectionClosed -= Server_Disconnected;

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