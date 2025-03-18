using System.Net.Sockets;
using System.IO.Pipelines;
using CsProxyTools.Base;
using CsProxyTools.Interfaces;
using Microsoft.Extensions.Logging;

namespace CsProxyTools.Clients;

public class TcpClient : BaseConnection, IClient
{
    private readonly string _host;
    private readonly int _port;
    private readonly Socket _socket;
    private readonly NetworkStream _stream;

    public TcpClient(ILogger logger, string host, int port) 
        : base(logger, Guid.NewGuid().ToString())
    {
        _host = host;
        _port = port;
        _socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        _stream = new NetworkStream(_socket);
    }

    protected override async Task StartConnectionAsync()
    {
        await _socket.ConnectAsync(_host, _port);
        _ = ProcessStreamAsync();
    }

    protected override async Task StopConnectionAsync()
    {
        _stream.Close();
        _socket.Close();
        await Task.CompletedTask;
    }

    protected override async Task WriteDataAsync(ReadOnlyMemory<byte> buffer)
    {
        await _stream.WriteAsync(buffer);
    }

    public async Task ConnectAsync(CancellationToken cancellationToken = default)
    {
        await StartAsync(cancellationToken);
    }

    public async Task DisconnectAsync(CancellationToken cancellationToken = default)
    {
        await StopAsync(cancellationToken);
    }

    public event EventHandler<ConnectionEventArgs>? Connected
    {
        add => ConnectionStarted += value;
        remove => ConnectionStarted -= value;
    }

    public event EventHandler<ConnectionEventArgs>? Disconnected
    {
        add => ConnectionClosed += value;
        remove => ConnectionClosed -= value;
    }

    public override async ValueTask DisposeAsync()
    {
        await base.DisposeAsync();
        _stream.Dispose();
        _socket.Dispose();
    }
} 