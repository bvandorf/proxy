using System.Net;
using System.Net.Sockets;
using System.IO.Pipelines;
using CsProxyTools.Base;
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
        var clients = new List<Socket>();
        lock (_clientsLock)
        {
            clients.AddRange(_clients);
        }

        foreach (var client in clients)
        {
            try
            {
                await client.SendAsync(buffer);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error writing to client");
                await RemoveClientAsync(client);
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
        var clientId = Guid.NewGuid().ToString();
        lock (_clientsLock)
        {
            _clients.Add(client);
        }

        ClientConnected?.Invoke(this, new ConnectionEventArgs(clientId));

        try
        {
            var buffer = new byte[8192];
            while (!_cancellationTokenSource.Token.IsCancellationRequested)
            {
                var bytesRead = await client.ReceiveAsync(buffer, _cancellationTokenSource.Token);
                if (bytesRead == 0) break;

                var data = new byte[bytesRead];
                Array.Copy(buffer, data, bytesRead);
                OnDataReceived(data);
            }
        }
        catch (OperationCanceledException)
        {
            // Normal cancellation, ignore
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error handling client {ClientId}", clientId);
        }
        finally
        {
            await RemoveClientAsync(client);
            ClientDisconnected?.Invoke(this, new ConnectionEventArgs(clientId));
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