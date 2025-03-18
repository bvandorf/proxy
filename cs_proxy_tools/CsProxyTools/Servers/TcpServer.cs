using System.Net;
using System.Net.Sockets;
using System.IO.Pipelines;
using CsProxyTools.Base;
using CsProxyTools.Helpers;
using CsProxyTools.Interfaces;
using Microsoft.Extensions.Logging;

namespace CsProxyTools.Servers;

public class TcpServer : BaseConnection, IServer
{
    private readonly string _host;
    private readonly int _port;
    private readonly Socket _listener;
    private readonly List<Socket> _clients;
    private readonly object _clientsLock = new();

    public event EventHandler<ConnectionEventArgs>? ClientConnected;
    public event EventHandler<ConnectionEventArgs>? ClientDisconnected;
    public bool IsRunning { get; private set; }

    public TcpServer(ILogger logger, string host, int port) 
        : base(logger, Guid.NewGuid().ToString())
    {
        _host = host;
        _port = port;
        _listener = new Socket(SocketType.Stream, ProtocolType.Tcp);
        _clients = new List<Socket>();
    }

    protected override async Task StartConnectionAsync()
    {
        _listener.Bind(new IPEndPoint(IPAddress.Parse(_host), _port));
        _listener.Listen(128);
        IsRunning = true;
        _ = AcceptClientsAsync();
        await Task.CompletedTask;
    }

    protected override async Task StopConnectionAsync()
    {
        IsRunning = false;
        lock (_clientsLock)
        {
            foreach (var client in _clients)
            {
                try
                {
                    client.Close();
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error closing client socket");
                }
            }
            _clients.Clear();
        }

        _listener.Close();
        await Task.CompletedTask;
    }

    protected override async Task WriteDataAsync(ReadOnlyMemory<byte> buffer)
    {
        _logger.LogDebug("TcpServer: Broadcasting {ByteCount} bytes to {ClientCount} clients\n{DataPreview}", 
            buffer.Length, _clients.Count, StringUtils.GetDataPreview(buffer));
        
        byte[] dataBuffer = buffer.ToArray();
        
        foreach (var client in _clients.ToArray())
        {
            try
            {
                await client.SendAsync(dataBuffer, SocketFlags.None);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error writing to client");
            }
        }
    }

    private async Task AcceptClientsAsync()
    {
        while (!_cancellationTokenSource.Token.IsCancellationRequested)
        {
            try
            {
                var client = await _listener.AcceptAsync(_cancellationTokenSource.Token);
                _ = HandleClientAsync(client);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error accepting client");
            }
        }
    }

    private async Task HandleClientAsync(Socket client)
    {
        var remoteEndPoint = client.RemoteEndPoint as System.Net.IPEndPoint;
        var clientIpPort = remoteEndPoint != null 
            ? $"{remoteEndPoint.Address}:{remoteEndPoint.Port}" 
            : "unknown";
        
        var clientId = $"{Guid.NewGuid():N}";
        
        lock (_clientsLock)
        {
            _clients.Add(client);
        }

        _logger.LogInformation("TCP Client {ClientIpPort} connected with ID {ClientId}", clientIpPort, clientId);
        ClientConnected?.Invoke(this, new ConnectionEventArgs(clientId, clientIpPort));

        try
        {
            var buffer = new byte[8192];
            while (!_cancellationTokenSource.Token.IsCancellationRequested)
            {
                var bytesRead = await client.ReceiveAsync(buffer, _cancellationTokenSource.Token);
                if (bytesRead == 0)
                {
                    _logger.LogDebug("TCP Client {ClientIpPort}:{ClientId} closed connection (0 bytes read)", 
                        clientIpPort, clientId);
                    break;
                }

                var data = new byte[bytesRead];
                Array.Copy(buffer, data, bytesRead);
                _logger.LogDebug("TCP Client {ClientIpPort}:{ClientId} received {BytesRead} bytes\n{DataPreview}", 
                    clientIpPort, clientId, bytesRead, StringUtils.GetDataPreview(new ReadOnlyMemory<byte>(data)));
                OnDataReceived(new DataReceivedEventArgs(clientId, new ReadOnlyMemory<byte>(data), clientIpPort));
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("TCP Client {ClientIpPort}:{ClientId} operation canceled", clientIpPort, clientId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error handling TCP client {ClientIpPort}:{ClientId}", clientIpPort, clientId);
        }
        finally
        {
            await RemoveClientAsync(client);
            _logger.LogInformation("TCP Client {ClientIpPort}:{ClientId} disconnected", clientIpPort, clientId);
            ClientDisconnected?.Invoke(this, new ConnectionEventArgs(clientId, clientIpPort));
        }
    }

    private async Task RemoveClientAsync(Socket client)
    {
        lock (_clientsLock)
        {
            _clients.Remove(client);
        }

        try
        {
            client.Close();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error closing client socket");
        }

        await Task.CompletedTask;
    }

    public override async ValueTask DisposeAsync()
    {
        await base.DisposeAsync();
        _listener.Dispose();
    }
} 