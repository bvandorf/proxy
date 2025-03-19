using System.Net.Sockets;
using System.Net;  // Add this for Dns
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
    private Socket _socket;
    private NetworkStream? _stream;
    private readonly object _connectionLock = new object();
    private bool _isConnecting = false;
    private bool _isDisconnecting = false;
    
    // Timeout values
    private const int ConnectionWaitTimeoutMs = 30000; // 30 seconds
    private const int DisconnectionWaitTimeoutMs = 5000; // 5 seconds
    private const int SocketConnectTimeoutMs = 15000; // 15 seconds for socket connect

    public TcpClient(ILogger logger, string host, int port) 
        : base(logger, Guid.NewGuid().ToString())
    {
        _host = host;
        _port = port;
        _socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        _socket.ReceiveTimeout = 30000; // 30 seconds
        _socket.SendTimeout = 30000; // 30 seconds
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
            
            // Ensure previous socket is closed and create a new one for this connection attempt
            if (_socket != null && _socket.Connected)
            {
                try
                {
                    _socket.Close();
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "TcpClient: Error closing existing socket before reconnection");
                }
            }
            
            // Create a new socket for this connection attempt to avoid reusing a potentially bad socket
            if (_socket != null)
            {
                try 
                {
                    _socket.Dispose();
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "TcpClient: Error disposing existing socket");
                }
            }
            
            _socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            _socket.ReceiveTimeout = 30000; // 30 seconds
            _socket.SendTimeout = 30000; // 30 seconds
            
            // Create a connect task with timeout
            using var timeoutCts = new CancellationTokenSource(SocketConnectTimeoutMs);
            
            // Try to resolve hostname first to log IP address
            try 
            {
                var addresses = await Dns.GetHostAddressesAsync(_host);
                if (addresses.Length > 0)
                {
                    _logger.LogDebug("TcpClient: Resolved {Host} to {IPAddress}", _host, 
                        string.Join(", ", addresses.Select(a => a.ToString())));
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "TcpClient: Failed to resolve hostname {Host}, will try connecting directly", _host);
            }
            
            try
            {
                // Use a linked token source to combine our operation timeout with the general cancellation token
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
                    timeoutCts.Token, _cancellationTokenSource.Token);
                
                var connectTask = _socket.ConnectAsync(_host, _port, linkedCts.Token);
                await connectTask;
                
                if (!_socket.Connected)
                {
                    _logger.LogWarning("TcpClient: Socket connect completed but socket is not connected");
                    throw new TimeoutException($"Failed to connect to {_host}:{_port} - socket did not report as connected");
                }
                
                _logger.LogDebug("TcpClient: Socket connected to {Host}:{Port}", _host, _port);
            }
            catch (OperationCanceledException)
            {
                if (timeoutCts.IsCancellationRequested)
                {
                    _logger.LogError("TcpClient: Connect operation timed out after {TimeoutMs}ms", SocketConnectTimeoutMs);
                    throw new TimeoutException($"Connect operation to {_host}:{_port} timed out after {SocketConnectTimeoutMs}ms");
                }
                if (_cancellationTokenSource.IsCancellationRequested)
                {
                    _logger.LogDebug("TcpClient: Connect operation was canceled");
                    throw new OperationCanceledException("Connection was canceled");
                }
                throw;
            }
            catch (SocketException socketEx)
            {
                // Convert common socket errors to more user-friendly timeout exceptions
                if (socketEx.SocketErrorCode == SocketError.TimedOut ||
                    socketEx.SocketErrorCode == SocketError.ConnectionRefused ||
                    socketEx.SocketErrorCode == SocketError.HostUnreachable ||
                    socketEx.SocketErrorCode == SocketError.NetworkUnreachable)
                {
                    _logger.LogError(socketEx, "TcpClient: Socket error connecting to {Host}:{Port} - {ErrorCode}", 
                        _host, _port, socketEx.SocketErrorCode);
                    throw new TimeoutException($"Failed to connect to {_host}:{_port}: {socketEx.Message}", socketEx);
                }
                _logger.LogError(socketEx, "TcpClient: Socket error connecting to {Host}:{Port} - {ErrorCode}", 
                    _host, _port, socketEx.SocketErrorCode);
                throw;
            }
            
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
            
            // Try to close the socket if there was an error
            try
            {
                if (_socket != null && _socket.Connected)
                {
                    _socket.Close();
                    _logger.LogDebug("TcpClient: Closed socket after connection error");
                }
            }
            catch (Exception closeEx)
            {
                _logger.LogWarning(closeEx, "TcpClient: Error closing socket after connection error");
            }
            
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
            
            // Cancel ongoing operations
            _cancellationTokenSource.Cancel();
            
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
                    // Use a combination of shutdown and close for cleaner socket termination
                    _socket.Shutdown(SocketShutdown.Both);
                    _socket.Close(1000); // Give it 1 second to close gracefully
                }
                catch (SocketException ex)
                {
                    _logger.LogWarning(ex, "TcpClient: Socket exception when closing socket: {ErrorCode}", ex.SocketErrorCode);
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
        // Add error handling for disconnected socket
        if (!_isConnected && _socket != null && !_socket.Connected) 
        {
            _logger.LogDebug("TcpClient: Attempting to reconnect before writing data");
            try {
                await StartConnectionAsync();
                // Ensure the connection started event is triggered
                OnConnectionStarted();
                _logger.LogDebug("TcpClient: Successfully reconnected before writing data");
            } catch (Exception ex) {
                _logger.LogError(ex, "TcpClient: Failed to reconnect before writing data");
                throw new InvalidOperationException("Cannot write to socket: failed to reconnect", ex);
            }
        }
        else if (_socket == null || !_socket.Connected)
        {
            _logger.LogWarning("TcpClient: Cannot write data - socket is not connected");
            throw new InvalidOperationException("Cannot write to socket: socket is not connected");
        }
        
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