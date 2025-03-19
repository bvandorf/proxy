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
    private Socket _listener;
    private readonly List<Socket> _clients;
    private readonly object _clientsLock = new();
    private ClientFactory? _clientFactory;

    public event EventHandler<ConnectionEventArgs>? ClientConnected;
    public event EventHandler<ConnectionEventArgs>? ClientDisconnected;
    public bool IsRunning { get; private set; }

    /// <summary>
    /// Gets or sets the client factory used to create target clients for incoming connections.
    /// </summary>
    public ClientFactory? ClientFactory
    {
        get => _clientFactory;
        set => _clientFactory = value;
    }

    public TcpServer(ILogger logger, string host, int port) 
        : base(logger, Guid.NewGuid().ToString())
    {
        _host = host;
        _port = port;
        _listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        _clients = new List<Socket>();
    }
    
    /// <summary>
    /// Creates a new TcpServer with a client factory for creating target clients
    /// </summary>
    public TcpServer(ILogger logger, string host, int port, ClientFactory clientFactory) 
        : this(logger, host, port)
    {
        _clientFactory = clientFactory;
    }

    protected override async Task StartConnectionAsync()
    {
        // Parse the host and ensure we use IPv4 only
        IPAddress bindAddress;
        if (_host == "0.0.0.0" || _host == "127.0.0.1" || _host == "localhost" || _host == "::1")
        {
            // Use explicit IPv4 loopback for localhost
            bindAddress = IPAddress.Parse("127.0.0.1");
            _logger.LogDebug("TcpServer: Using IPv4 loopback address (127.0.0.1) for binding");
        }
        else if (_host == "::" || _host == "0:0:0:0:0:0:0:0")
        {
            // Use explicit IPv4 any address instead of IPv6 any
            bindAddress = IPAddress.Any;
            _logger.LogDebug("TcpServer: Using IPv4 any address (0.0.0.0) for binding");
        }
        else if (IPAddress.TryParse(_host, out var parsedAddress))
        {
            if (parsedAddress.AddressFamily == AddressFamily.InterNetworkV6)
            {
                // Convert IPv6 to equivalent IPv4 if possible, otherwise use IPv4 any
                _logger.LogWarning("TcpServer: IPv6 address specified, converting to IPv4 for consistency");
                bindAddress = IPAddress.Any;
            }
            else
            {
                bindAddress = parsedAddress;
            }
        }
        else
        {
            // Default to IPv4 any address if parsing fails
            _logger.LogWarning("TcpServer: Invalid address format: {Host}, using IPv4 any address (0.0.0.0)", _host);
            bindAddress = IPAddress.Any;
        }
        
        // Create a new IPv4 socket
        _listener.Close();
        _listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        
        // Bind to the IPv4 address
        _listener.Bind(new IPEndPoint(bindAddress, _port));
        _listener.Listen(128);
        IsRunning = true;
        _logger.LogInformation("TcpServer: Listening on {Address}:{Port} (IPv4)", bindAddress, _port);
        _ = AcceptClientsAsync();
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
            // If a client factory is set, automatically create a proxy connection
            if (_clientFactory != null)
            {
                _logger.LogDebug("Auto-creating proxy connection for client {ClientId} using client factory", clientId);
                
                // Create a socket connection wrapper for this specific client
                var socketConnection = new SocketConnection(_logger, clientId, client, clientIpPort);
                
                // Create a proxy connection using the socket connection and client factory
                var proxyConnection = new ProxyConnection(
                    _logger,
                    clientId,
                    socketConnection, // Use the socket connection as the client connection
                    _clientFactory); // Use the factory to create a target client
                
                // Start the proxy connection
                try
                {
                    await proxyConnection.Start();
                    _logger.LogInformation("Proxy connection started for client {ClientId}", clientId);
                    
                    // Wait for the socket connection to close (handled by the proxy connection)
                    await socketConnection.WaitForDisconnectAsync();
                    
                    // Cleanup when done
                    await proxyConnection.DisposeAsync();
                    await socketConnection.DisposeAsync();
                    
                    return;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to start proxy connection for client {ClientId}", clientId);
                    
                    // Cleanup resources on error
                    await proxyConnection.DisposeAsync();
                    await socketConnection.DisposeAsync();
                    
                    // If proxy connection failed, fallback to normal client handling
                }
            }

            // Normal client handling without proxy
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

    // Implementation of a Socket-specific connection wrapper
    private class SocketConnection : IConnection, IAsyncDisposable
    {
        private readonly ILogger _logger;
        private readonly Socket _socket;
        private readonly string _clientId;
        private readonly string _clientIpPort;
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        private bool _isConnected = true;
        private bool _isDisposed = false;
        private readonly TaskCompletionSource _disconnectSignal = new TaskCompletionSource();

        public SocketConnection(ILogger logger, string clientId, Socket socket, string clientIpPort)
        {
            _logger = logger;
            _clientId = clientId;
            _socket = socket;
            _clientIpPort = clientIpPort;
            
            _logger.LogDebug("SocketConnection: Created for client {ClientId} from {ClientIpPort}", _clientId, _clientIpPort);
            
            // Start reading data from the socket
            _ = ReadSocketAsync();
        }

        public string Id => _clientId;
        public bool IsConnected => _isConnected;

        public event EventHandler<ConnectionEventArgs>? ConnectionClosed;
        public event EventHandler<ConnectionEventArgs>? ConnectionStarted;
        public event EventHandler<DataReceivedEventArgs>? DataReceived;

        private async Task ReadSocketAsync()
        {
            _logger.LogDebug("SocketConnection: Starting read loop for client {ClientId}", _clientId);
            try
            {
                var buffer = new byte[8192];
                while (!_cts.Token.IsCancellationRequested)
                {
                    _logger.LogTrace("SocketConnection: Reading from socket for client {ClientId}", _clientId);
                    var bytesRead = await _socket.ReceiveAsync(buffer, _cts.Token);
                    _logger.LogTrace("SocketConnection: Read {BytesRead} bytes from client {ClientId}", bytesRead, _clientId);
                    
                    if (bytesRead == 0)
                    {
                        _logger.LogDebug("SocketConnection: End of stream reached (0 bytes read) for client {ClientId}", _clientId);
                        break;
                    }

                    var data = new ReadOnlyMemory<byte>(buffer, 0, bytesRead);
                    _logger.LogDebug("SocketConnection: Received {BytesRead} bytes from client {ClientId}\n{DataPreview}", 
                        bytesRead, _clientId, StringUtils.GetDataPreview(data));
                        
                    _logger.LogTrace("SocketConnection: Triggering DataReceived event for client {ClientId}", _clientId);
                    DataReceived?.Invoke(this, new DataReceivedEventArgs(_clientId, data, _clientIpPort));
                    _logger.LogTrace("SocketConnection: DataReceived event completed for client {ClientId}", _clientId);
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogDebug("SocketConnection: Reading operation canceled for client {ClientId}", _clientId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "SocketConnection: Error reading from socket for client {ClientId}", _clientId);
            }
            finally
            {
                _isConnected = false;
                _logger.LogDebug("SocketConnection: Marking client {ClientId} as disconnected and triggering ConnectionClosed event", _clientId);
                ConnectionClosed?.Invoke(this, new ConnectionEventArgs(_clientId, _clientIpPort));
                _logger.LogDebug("SocketConnection: Setting disconnectSignal for client {ClientId}", _clientId);
                _disconnectSignal.TrySetResult();
            }
        }

        public Task<ReadResult> ReadAsync(CancellationToken cancellationToken = default)
        {
            // This method is not used directly in our implementation
            _logger.LogWarning("SocketConnection: ReadAsync not implemented for client {ClientId}", _clientId);
            throw new NotImplementedException("ReadAsync is not implemented for SocketConnection");
        }

        public Task StartAsync(CancellationToken cancellationToken = default)
        {
            // The connection is already started when the object is created
            _logger.LogDebug("SocketConnection: StartAsync called for client {ClientId}, triggering ConnectionStarted", _clientId);
            ConnectionStarted?.Invoke(this, new ConnectionEventArgs(_clientId, _clientIpPort));
            return Task.CompletedTask;
        }

        public async Task StopAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogDebug("SocketConnection: StopAsync called for client {ClientId}, IsConnected={IsConnected}", _clientId, _isConnected);
            
            if (_isConnected)
            {
                _cts.Cancel();
                _isConnected = false;
                
                try
                {
                    _logger.LogDebug("SocketConnection: Shutting down socket for client {ClientId}", _clientId);
                    _socket.Shutdown(SocketShutdown.Both);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "SocketConnection: Error shutting down socket for client {ClientId}", _clientId);
                }
                
                _logger.LogDebug("SocketConnection: Triggering ConnectionClosed for client {ClientId}", _clientId);
                ConnectionClosed?.Invoke(this, new ConnectionEventArgs(_clientId, _clientIpPort));
            }
            
            await Task.CompletedTask;
        }

        public async Task WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (!_isConnected)
            {
                _logger.LogWarning("SocketConnection: Cannot write to a disconnected socket for client {ClientId}", _clientId);
                throw new InvalidOperationException("Cannot write to a disconnected socket");
            }
            
            try
            {
                _logger.LogDebug("SocketConnection: Writing {ByteCount} bytes to client {ClientId}\n{DataPreview}", 
                    buffer.Length, _clientId, StringUtils.GetDataPreview(buffer));
                await _socket.SendAsync(buffer, SocketFlags.None, cancellationToken);
                _logger.LogDebug("SocketConnection: Successfully wrote {ByteCount} bytes to client {ClientId}", buffer.Length, _clientId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "SocketConnection: Error writing to socket for client {ClientId}", _clientId);
                throw;
            }
        }
        
        public Task WaitForDisconnectAsync()
        {
            _logger.LogDebug("SocketConnection: WaitForDisconnectAsync called for client {ClientId}, IsConnected={IsConnected}", _clientId, _isConnected);
            return _disconnectSignal.Task;
        }

        public async ValueTask DisposeAsync()
        {
            _logger.LogDebug("SocketConnection: DisposeAsync called for client {ClientId}, IsDisposed={IsDisposed}", _clientId, _isDisposed);
            
            if (_isDisposed) return;
            
            try
            {
                _logger.LogDebug("SocketConnection: Cancelling token source for client {ClientId}", _clientId);
                _cts.Cancel();
                
                try
                {
                    if (_socket.Connected)
                    {
                        _logger.LogDebug("SocketConnection: Shutting down socket for client {ClientId}", _clientId);
                        _socket.Shutdown(SocketShutdown.Both);
                    }
                    _logger.LogDebug("SocketConnection: Closing socket for client {ClientId}", _clientId);
                    _socket.Close();
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "SocketConnection: Error closing socket for client {ClientId}", _clientId);
                }
                
                _logger.LogDebug("SocketConnection: Disposing token source for client {ClientId}", _clientId);
                _cts.Dispose();
                _isDisposed = true;
                
                // Ensure the disconnect signal is set
                _logger.LogDebug("SocketConnection: Ensuring disconnect signal is set for client {ClientId}", _clientId);
                _disconnectSignal.TrySetResult();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "SocketConnection: Error disposing resources for client {ClientId}", _clientId);
            }
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