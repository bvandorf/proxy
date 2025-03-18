using System.Net.Sockets;
using System.IO.Pipelines;
using CsProxyTools.Base;
using CsProxyTools.Interfaces;
using CsProxyTools.Helpers;
using Microsoft.Extensions.Logging;

namespace CsProxyTools.Clients;

public class TcpClient : BaseConnection, IClient
{
    private readonly string _host;
    private readonly int _port;
    private readonly Socket _socket;
    private NetworkStream? _stream;
    private readonly object _connectionLock = new object();
    private bool _isConnecting = false;
    private bool _isDisconnecting = false;
    
    // Timeout values
    private const int ConnectionWaitTimeoutMs = 10000; // 10 seconds
    private const int DisconnectionWaitTimeoutMs = 5000; // 5 seconds

    public TcpClient(ILogger logger, string host, int port) 
        : base(logger, Guid.NewGuid().ToString())
    {
        _host = host;
        _port = port;
        _socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
    }

    protected override async Task StartConnectionAsync()
    {
        // Check if we're already connected
        if (_isConnected)
        {
            _logger.LogDebug("TcpClient: Already connected");
            return;
        }
        
        // Check if connection is in progress
        if (_isConnecting)
        {
            _logger.LogDebug("TcpClient: Connection already in progress, waiting up to {Timeout}ms for it to complete", ConnectionWaitTimeoutMs);
            
            // Wait for connection to complete with timeout
            var startTime = DateTime.UtcNow;
            while (_isConnecting && !_isConnected)
            {
                await Task.Delay(100); // Check every 100ms
                
                // Check if we've timed out
                if ((DateTime.UtcNow - startTime).TotalMilliseconds > ConnectionWaitTimeoutMs)
                {
                    _logger.LogWarning("TcpClient: Timed out waiting for connection to complete");
                    throw new TimeoutException($"Timed out waiting for connection to complete after {ConnectionWaitTimeoutMs}ms");
                }
            }
            
            // If we're now connected, return
            if (_isConnected)
            {
                _logger.LogDebug("TcpClient: Existing connection completed successfully");
                return;
            }
        }
        
        // Set connecting flag
        _isConnecting = true;
        
        try
        {
            _logger.LogDebug("TcpClient: Starting connection to {Host}:{Port}", _host, _port);
            await _socket.ConnectAsync(_host, _port);
            _logger.LogDebug("TcpClient: Socket connected to {Host}:{Port}", _host, _port);
            
            // Create the stream - no lock needed since we've set _isConnecting flag
            _stream = new NetworkStream(_socket);
            _logger.LogDebug("TcpClient: Created network stream");
            
            // Start reading data
            _ = ReadStreamAsync();
            _logger.LogDebug("TcpClient: Started reading stream");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "TcpClient: Failed to connect to {Host}:{Port}", _host, _port);
            throw;
        }
        finally
        {
            _isConnecting = false;
        }
    }

    private async Task ReadStreamAsync()
    {
        _logger.LogDebug("TcpClient: Starting read stream task");
        try
        {
            // Create endpoint info string
            string remoteEndpoint = "unknown";
            if (_socket != null && _socket.Connected && _socket.RemoteEndPoint is System.Net.IPEndPoint ipEndPoint) 
            {
                remoteEndpoint = $"{ipEndPoint.Address}:{ipEndPoint.Port}";
            }
            
            var buffer = new byte[8192];
            while (!_cancellationTokenSource.Token.IsCancellationRequested)
            {
                if (_stream == null)
                {
                    _logger.LogDebug("TcpClient: Stream is null, exiting read loop");
                    break;
                }
                
                _logger.LogTrace("TcpClient: Reading from stream");
                
                try
                {
                    var bytesRead = await _stream.ReadAsync(buffer, _cancellationTokenSource.Token);
                    _logger.LogTrace("TcpClient: Read {BytesRead} bytes from stream", bytesRead);
                    
                    if (bytesRead == 0)
                    {
                        _logger.LogDebug("TcpClient: End of stream reached (0 bytes read)");
                        break;
                    }

                    var memory = new ReadOnlyMemory<byte>(buffer, 0, bytesRead);
                    _logger.LogDebug("TcpClient: Triggering DataReceived event for {BytesRead} bytes from {RemoteEndpoint}\n{DataPreview}", 
                        bytesRead, remoteEndpoint, StringUtils.GetDataPreview(memory));
                    OnDataReceived(memory, remoteEndpoint);
                }
                catch (ObjectDisposedException ex)
                {
                    _logger.LogDebug("TcpClient: Stream was disposed during read: {Message}", ex.Message);
                    break;
                }
                catch (IOException ex)
                {
                    _logger.LogDebug("TcpClient: IO exception during read: {Message}", ex.Message);
                    break;
                }
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
        // Check if we're already disconnected
        if (!_isConnected && !_isConnecting)
        {
            _logger.LogDebug("TcpClient: Already disconnected");
            return;
        }
        
        // Check if disconnection is in progress
        if (_isDisconnecting)
        {
            _logger.LogDebug("TcpClient: Disconnection already in progress, waiting up to {Timeout}ms for it to complete", DisconnectionWaitTimeoutMs);
            
            // Wait for disconnection to complete with timeout
            var startTime = DateTime.UtcNow;
            while (_isDisconnecting)
            {
                await Task.Delay(100); // Check every 100ms
                
                // Check if we've timed out
                if ((DateTime.UtcNow - startTime).TotalMilliseconds > DisconnectionWaitTimeoutMs)
                {
                    _logger.LogWarning("TcpClient: Timed out waiting for disconnection to complete");
                    break; // Break out and try to disconnect anyway
                }
            }
            
            // If we're already disconnected, return
            if (!_isConnected && !_isConnecting)
            {
                _logger.LogDebug("TcpClient: Existing disconnection completed successfully");
                return;
            }
        }
        
        // Set disconnecting flag
        _isDisconnecting = true;
        
        try
        {
            _logger.LogDebug("TcpClient: Stopping connection");
            
            // Safely capture and clear stream reference
            var streamToClose = _stream;
            _stream = null;
            
            // Close stream if it exists
            if (streamToClose != null)
            {
                _logger.LogDebug("TcpClient: Closing stream");
                try
                {
                    streamToClose.Close();
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "TcpClient: Error closing stream");
                }
            }
            
            // Close socket if connected
            if (_socket.Connected)
            {
                _logger.LogDebug("TcpClient: Closing socket");
                try
                {
                    _socket.Close();
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "TcpClient: Error closing socket");
                }
            }
            
            _logger.LogDebug("TcpClient: Connection stopped");
        }
        finally
        {
            _isDisconnecting = false;
        }
    }

    protected override async Task WriteDataAsync(ReadOnlyMemory<byte> buffer)
    {
        // Check if stream is available
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
        
        // Get remote endpoint info for logging if available
        string remoteEndpoint = "unknown";
        if (_socket != null && _socket.Connected && _socket.RemoteEndPoint is System.Net.IPEndPoint ipEndPoint) 
        {
            remoteEndpoint = $"{ipEndPoint.Address}:{ipEndPoint.Port}";
        }
        
        // Safely capture stream reference
        var streamToWrite = _stream;
        if (streamToWrite == null)
        {
            throw new InvalidOperationException("Stream became null after initial check.");
        }
        
        _logger.LogDebug("TcpClient: Writing {ByteCount} bytes to {RemoteEndpoint}\n{DataPreview}", 
            buffer.Length, remoteEndpoint, StringUtils.GetDataPreview(buffer));
            
        try
        {
            await streamToWrite.WriteAsync(buffer);
        }
        catch (ObjectDisposedException ex)
        {
            _logger.LogError(ex, "TcpClient: Cannot write to disposed stream");
            throw new InvalidOperationException("Cannot write to disposed stream", ex);
        }
        catch (IOException ex)
        {
            _logger.LogError(ex, "TcpClient: IO error writing to stream");
            throw new InvalidOperationException("IO error writing to stream", ex);
        }
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
        // Safely capture and clear stream reference
        var streamToDispose = _stream;
        _stream = null;
        
        await base.DisposeAsync();
        
        // Dispose stream if it exists
        if (streamToDispose != null)
        {
            try
            {
                streamToDispose.Dispose();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "TcpClient: Error disposing stream");
            }
        }
        
        // Dispose socket
        try
        {
            _socket.Dispose();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "TcpClient: Error disposing socket");
        }
    }
} 