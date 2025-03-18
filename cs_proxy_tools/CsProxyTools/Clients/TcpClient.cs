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
    private NetworkStream? _stream;

    public TcpClient(ILogger logger, string host, int port) 
        : base(logger, Guid.NewGuid().ToString())
    {
        _host = host;
        _port = port;
        _socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
    }

    protected override async Task StartConnectionAsync()
    {
        _logger.LogDebug("TcpClient: Starting connection to {Host}:{Port}", _host, _port);
        await _socket.ConnectAsync(_host, _port);
        _logger.LogDebug("TcpClient: Socket connected to {Host}:{Port}", _host, _port);
        _stream = new NetworkStream(_socket);
        _logger.LogDebug("TcpClient: Created network stream");
        _ = ReadStreamAsync();
        _logger.LogDebug("TcpClient: Started reading stream");
    }

    private async Task ReadStreamAsync()
    {
        _logger.LogDebug("TcpClient: Starting read stream task");
        try
        {
            var buffer = new byte[8192];
            while (!_cancellationTokenSource.Token.IsCancellationRequested)
            {
                _logger.LogTrace("TcpClient: Reading from stream");
                var bytesRead = await _stream!.ReadAsync(buffer, _cancellationTokenSource.Token);
                _logger.LogTrace("TcpClient: Read {BytesRead} bytes from stream", bytesRead);
                if (bytesRead == 0)
                {
                    _logger.LogDebug("TcpClient: End of stream reached (0 bytes read)");
                    break;
                }

                var memory = new ReadOnlyMemory<byte>(buffer, 0, bytesRead);
                _logger.LogDebug("TcpClient: Triggering DataReceived event for {BytesRead} bytes", bytesRead);
                OnDataReceived(memory);
            }
            _logger.LogDebug("TcpClient: Exited read loop normally");
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("TcpClient: Read operation was canceled");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "TcpClient: Error reading from stream");
        }
        _logger.LogDebug("TcpClient: Read stream task completed");
    }

    protected override async Task StopConnectionAsync()
    {
        _logger.LogDebug("TcpClient: Stopping connection");
        if (_stream != null)
        {
            _logger.LogDebug("TcpClient: Closing stream");
            _stream.Close();
            _stream = null;
        }
        
        if (_socket.Connected)
        {
            _logger.LogDebug("TcpClient: Closing socket");
            _socket.Close();
        }
        
        _logger.LogDebug("TcpClient: Connection stopped");
        await Task.CompletedTask;
    }

    protected override async Task WriteDataAsync(ReadOnlyMemory<byte> buffer)
    {
        if (_stream == null)
        {
            _logger.LogWarning("TcpClient: Stream is not initialized. Attempting to connect first.");
            try {
                await StartConnectionAsync();
                // Ensure the connection started event is triggered
                OnConnectionStarted();
            } catch (Exception ex) {
                throw new InvalidOperationException("Cannot write to stream: failed to connect automatically.", ex);
            }
            
            // Double check that the stream was initialized
            if (_stream == null)
            {
                throw new InvalidOperationException("Stream is not initialized after connection attempt. Call StartAsync first.");
            }
        }
        await _stream.WriteAsync(buffer);
    }

    public async Task ConnectAsync(CancellationToken cancellationToken = default)
    {
        _logger.LogDebug("TcpClient: ConnectAsync called");
        await StartAsync(cancellationToken);
        _logger.LogDebug("TcpClient: ConnectAsync completed");
    }

    public async Task DisconnectAsync(CancellationToken cancellationToken = default)
    {
        _logger.LogDebug("TcpClient: DisconnectAsync called");
        await StopAsync(cancellationToken);
        _logger.LogDebug("TcpClient: DisconnectAsync completed");
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
        _stream?.Dispose();
        _socket.Dispose();
    }
} 