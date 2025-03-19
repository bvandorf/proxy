using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.IO.Pipelines;
using CsProxyTools.Base;
using CsProxyTools.Interfaces;
using CsProxyTools.Helpers;
using Microsoft.Extensions.Logging;
using System.Text;

namespace CsProxyTools.Clients;

public class TlsClient : BaseConnection, ITlsClient
{
    private readonly string _host;
    private readonly int _port;
    private readonly bool _validateCertificate;
    private Socket? _socket;
    private readonly X509Certificate2? _clientCertificate;
    private NetworkStream? _stream;
    private SslStream? _sslStream;

    // Default handshake timeout increased to 30 seconds
    private readonly TimeSpan _handshakeTimeout = TimeSpan.FromSeconds(30);

    public string Host => _host;
    public int Port => _port;
    public bool ValidateCertificate => _validateCertificate;

    public TlsClient(ILogger logger, string host, int port, bool validateCertificate = true, X509Certificate2? clientCertificate = null) 
        : base(logger, Guid.NewGuid().ToString())
    {
        _host = host;
        _port = port;
        _validateCertificate = validateCertificate;
        _clientCertificate = clientCertificate;
        // Don't create the socket in the constructor, only when needed
        _socket = null;
    }

    // Implement IClient interface events
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

    private bool ValidateServerCertificate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
    {
        if (!_validateCertificate)
        {
            _logger.LogDebug("TlsClient: Certificate validation disabled, accepting certificate");
            return true;
        }

        if (sslPolicyErrors == SslPolicyErrors.None)
        {
            _logger.LogDebug("TlsClient: Certificate validation successful");
            return true;
        }

        _logger.LogWarning("TlsClient: Certificate validation failed for {Host}: {Errors}", _host, sslPolicyErrors);
        return false;
    }

    private async Task<IPAddress[]> ResolveHostToIPv4AddressesAsync(string host)
    {
        try
        {
            if (string.IsNullOrEmpty(host))
            {
                _logger.LogError("TlsClient: Host is null or empty");
                return Array.Empty<IPAddress>();
            }
            
            if (IPAddress.TryParse(host, out var ipAddress))
            {
                // If it's already an IP address, check if it's IPv4
                if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
                {
                    _logger.LogDebug("TlsClient: Using explicit IPv4 address: {IPAddress}", ipAddress);
                    return new[] { ipAddress };
                }
                else
                {
                    _logger.LogDebug("TlsClient: Converting non-IPv4 address {IPAddress} to equivalent IPv4 address", ipAddress);
                    // For IPv6 addresses, try to get equivalent IPv4 or use loopback
                    return new[] { IPAddress.Loopback };
                }
            }
            else
            {
                // Otherwise, resolve the hostname to IPv4 addresses only
                _logger.LogDebug("TlsClient: Resolving hostname: {Host}", host);
                
                try
                {
                    // Only get IPv4 addresses to ensure compatibility
                    var allAddresses = await Dns.GetHostAddressesAsync(host);
                    var ipv4Addresses = Array.FindAll(allAddresses, addr => addr != null && addr.AddressFamily == AddressFamily.InterNetwork);
                    
                    if (ipv4Addresses.Length == 0)
                    {
                        _logger.LogError("TlsClient: No IPv4 addresses found for hostname: {Host}", host);
                        // Fall back to loopback address when no IPv4 addresses are found
                        _logger.LogWarning("TlsClient: Falling back to loopback address");
                        return new[] { IPAddress.Loopback };
                    }
                    
                    _logger.LogDebug("TlsClient: Resolved {Host} to {AddressCount} IPv4 addresses", host, ipv4Addresses.Length);
                    return ipv4Addresses;
                }
                catch (Exception dnsEx)
                {
                    _logger.LogError(dnsEx, "TlsClient: DNS resolution failed for {Host}, falling back to loopback", host);
                    return new[] { IPAddress.Loopback };
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "TlsClient: Failed to resolve hostname: {Host}, falling back to loopback", host);
            return new[] { IPAddress.Loopback };
        }
    }

    private Socket CreateFreshSocket()
    {
        // Always create a new socket to avoid reuse issues
        var newSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        
        try
        {
            // Configure socket for better performance with TLS
            newSocket.ReceiveBufferSize = 16384; // Larger buffer for TLS frames
            newSocket.SendBufferSize = 16384;
            newSocket.NoDelay = true; // Disable Nagle algorithm for lower latency
            newSocket.LingerState = new LingerOption(false, 0); // Don't linger on close
            
            // IMPORTANT: Do NOT bind the client socket to a specific local endpoint
            // This is critical for outbound connections to work properly
            
            // Set adequate timeouts - validate the values are positive
            int timeout = (int)TimeSpan.FromSeconds(30).TotalMilliseconds;
            if (timeout > 0)
            {
                newSocket.ReceiveTimeout = timeout;
                newSocket.SendTimeout = timeout;
            }
            else
            {
                _logger.LogWarning("TlsClient: Invalid timeout value, not setting socket timeouts");
            }
        }
        catch (SocketException sx)
        {
            _logger.LogWarning(sx, "TlsClient: Error setting socket options, continuing anyway: {Error}", sx.SocketErrorCode);
        }
        
        return newSocket;
    }

    // Configure SSL Stream
    private async Task<SslStream> ConfigureAndAuthenticateSslStreamAsync(IPEndPoint remoteEndpoint)
    {
        _logger.LogDebug("TlsClient: Configuring SSL/TLS for connection to {Host}:{Port}", _host, _port);
        
        var sslStream = new SslStream(_stream!, true, ValidateServerCertificate);
        
        _logger.LogDebug("TlsClient: Created SSL stream, authenticating as client for {Host}:{Port}", _host, _port);
        
        try
        {
            // Create SSL client authentication options
            var options = new SslClientAuthenticationOptions
            {
                TargetHost = _host,
                ClientCertificates = _clientCertificate != null ? new X509CertificateCollection { _clientCertificate } : null,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                RemoteCertificateValidationCallback = ValidateServerCertificate
            };
            
            _logger.LogDebug("TlsClient: Starting SSL handshake with {Host}:{Port} (Endpoint: {Endpoint})", 
                _host, _port, remoteEndpoint);
            
            // Authenticate as client - this performs the SSL handshake
            await sslStream.AuthenticateAsClientAsync(options);
            
            _logger.LogDebug("TlsClient: SSL handshake successful with {Host}:{Port} using {Protocol}", 
                _host, _port, sslStream.SslProtocol);
            
            return sslStream;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "TlsClient: SSL handshake failed with {Host}:{Port}", _host, _port);
            
            // Clean up on error
            sslStream.Dispose();
            throw;
        }
    }

    protected override async Task StartConnectionAsync()
    {
        // Validate connection parameters first
        if (string.IsNullOrEmpty(_host))
        {
            throw new ArgumentException("Host cannot be null or empty", nameof(_host));
        }

        if (_port <= 0 || _port > 65535)
        {
            throw new ArgumentException($"Port must be between 1 and 65535, got {_port}", nameof(_port));
        }

        // First establish TCP connection
        _logger.LogDebug("TlsClient: Starting TCP connection to {Host}:{Port}", _host, _port);
        
        try
        {
            // Clean up any existing connection resources
            CleanupConnection();
            
            // Resolve the hostname to an IPv4 address
            IPAddress[] addresses = await ResolveHostToIPv4AddressesAsync(_host);
            
            if (addresses == null || addresses.Length == 0)
            {
                _logger.LogError("TlsClient: Failed to resolve any addresses for {Host}, cannot proceed", _host);
                throw new InvalidOperationException($"Failed to resolve any addresses for {_host}");
            }
            
            // Try to connect using the resolved addresses
            Exception? lastConnectException = null;
            bool connected = false;
            
            foreach (var address in addresses)
            {
                if (address == null)
                {
                    _logger.LogWarning("TlsClient: Skipping null address for {Host}", _host);
                    continue;
                }
                
                try
                {
                    // Create endpoint with the resolved address
                    var endpoint = new IPEndPoint(address, _port);
                    _logger.LogDebug("TlsClient: Connecting to {Endpoint} from local socket {LocalEndpoint}", 
                        endpoint, "not bound yet");
                    
                    // Create a fresh socket for each connection attempt with specific address family
                    // IMPORTANT: Ensuring the socket has the same address family as the target endpoint
                    _socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                    _logger.LogDebug("TlsClient: Created new socket for connection attempt with address family {AddressFamily}", 
                        address.AddressFamily);
                    
                    if (_socket != null)
                    {
                        // Configure socket options
                        _socket.ReceiveBufferSize = 16384;
                        _socket.SendBufferSize = 16384; 
                        _socket.NoDelay = true;
                        _socket.LingerState = new LingerOption(false, 0);
                        
                        // For dual-stack compatibility, set IPv6Only to false if this is an IPv6 socket
                        if (address.AddressFamily == AddressFamily.InterNetworkV6)
                        {
                            _logger.LogDebug("TlsClient: Setting IPv6Only to false for dual-stack compatibility");
                            _socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, false);
                        }
                    }
                    else
                    {
                        _logger.LogError("TlsClient: Failed to create socket for {Host}:{Port}", _host, _port);
                        throw new InvalidOperationException($"Failed to create socket for {_host}:{_port}");
                    }
                    
                    // Connect to the endpoint
                    await _socket.ConnectAsync(endpoint);
                    connected = _socket.Connected;
                    
                    if (connected)
                    {
                        _logger.LogDebug("TlsClient: Successfully connected to {Endpoint} from {LocalEndpoint}", 
                            endpoint, _socket.LocalEndPoint != null ? _socket.LocalEndPoint.ToString() : "unknown");
                        break;
                    }
                }
                catch (SocketException sx)
                {
                    // Log the local endpoint (if any) to help diagnose binding issues
                    _logger.LogWarning(sx, "TlsClient: Socket error connecting to {Address}:{Port}, SocketError: {Error}, LocalEndpoint: {LocalEndpoint}", 
                        address, _port, sx.SocketErrorCode, _socket?.LocalEndPoint != null ? _socket.LocalEndPoint.ToString() : "not bound");
                    
                    // Always dispose of failed socket
                    _socket?.Dispose();
                    _socket = null;
                    
                    // If this is not the last address, try the next one
                    if (address != addresses.Last())
                    {
                        _logger.LogDebug("TlsClient: Will try next address");
                        continue;
                    }
                    
                    // Otherwise, re-throw the last exception
                    throw;
                }
            }
            
            // Verify connection was successful
            if (!connected || _socket == null)
            {
                if (lastConnectException != null)
                {
                    throw lastConnectException;
                }
                throw new InvalidOperationException($"Failed to connect to {_host}:{_port}");
            }
            
            _logger.LogDebug("TlsClient: TCP socket connected successfully to {Host}:{Port}", _host, _port);
            
            // Get the remote endpoint for logging and diagnostics
            var remoteEndpoint = _socket.RemoteEndPoint as IPEndPoint;
            if (remoteEndpoint == null)
            {
                throw new InvalidOperationException("Could not determine remote endpoint");
            }
            
            // Create network stream with ownership of socket
            _stream = new NetworkStream(_socket, true);
            _logger.LogDebug("TlsClient: Created network stream");
            
            // Now perform SSL handshake
            int retryCount = 0;
            const int maxRetries = 2; // Total attempts: 3 (initial + 2 retries)
            Exception? lastException = null;
            
            while (retryCount <= maxRetries)
            {
                try
                {
                    // Create and authenticate SSL stream
                    _sslStream = await ConfigureAndAuthenticateSslStreamAsync(remoteEndpoint);
                    break; // Success, exit the retry loop
                }
                catch (IOException ioEx) when (IsRecoverableIoException(ioEx) && retryCount < maxRetries)
                {
                    lastException = ioEx;
                    retryCount++;
                    
                    _logger.LogWarning(ioEx, "TlsClient: IO error during SSL handshake (Attempt {Attempt}/{MaxAttempts}): {Message}",
                        retryCount, maxRetries + 1, ioEx.Message);
                    
                    // Perform cleanup and retry with a new stream
                    CleanupConnection();
                    
                    // Short delay before retry
                    await Task.Delay(500 * retryCount);
                    
                    // Re-establish TCP connection with a new socket
                    _logger.LogDebug("TlsClient: Retrying connection to {Host}:{Port} (Attempt {Attempt}/{MaxAttempts})", 
                        _host, _port, retryCount + 1, maxRetries + 1);
                    
                    // Try to create a new socket and connect again to the first IPv4 address
                    var retryAddresses = await ResolveHostToIPv4AddressesAsync(_host);
                    if (retryAddresses.Length > 0)
                    {
                        _socket = CreateFreshSocket();
                        var endpoint = new IPEndPoint(retryAddresses[0], _port);
                        await _socket.ConnectAsync(endpoint);
                        
                        if (!_socket.Connected)
                        {
                            throw new InvalidOperationException($"Failed to reconnect to {_host}:{_port} on retry {retryCount}");
                        }
                        
                        remoteEndpoint = _socket.RemoteEndPoint as IPEndPoint;
                        if (remoteEndpoint == null)
                        {
                            throw new InvalidOperationException("Could not determine remote endpoint on retry");
                        }
                        
                        // Create a new network stream
                        _stream = new NetworkStream(_socket, true);
                    }
                    else
                    {
                        throw new InvalidOperationException($"Could not resolve hostname: {_host} on retry");
                    }
                }
                catch (Exception ex)
                {
                    lastException = ex;
                    _logger.LogError(ex, "TlsClient: SSL handshake failed with {Host}:{Port}", _host, _port);
                    CleanupConnection();
                    throw;
                }
            }
            
            if (_sslStream == null)
            {
                _logger.LogError("TlsClient: SSL handshake failed after {MaxAttempts} attempts", maxRetries + 1);
                CleanupConnection();
                throw lastException ?? new InvalidOperationException("SSL handshake failed with unknown error");
            }
            
            _logger.LogInformation("TlsClient: Connected successfully to {Host}:{Port} using {Protocol}", 
                _host, _port, _sslStream.SslProtocol);
            
            // Now start reading from the stream
            _ = ReadStreamAsync();
            
            // Signal connection started using the base class method
            _logger.LogInformation("TlsClient: Connection established with {RemoteEndpoint}", 
                remoteEndpoint?.ToString() ?? "unknown");
            OnConnectionStarted();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "TlsClient: Failed to connect to {Host}:{Port}", _host, _port);
            CleanupConnection();
            throw;
        }
    }

    private void CleanupConnection()
    {
        _logger.LogDebug("TlsClient: Cleaning up connection resources");
        
        SslStream? sslStreamToDispose = null;
        NetworkStream? networkStreamToDispose = null;
        Socket? socketToDispose = null;
        
        // Safely capture references to disposable objects
        lock (this)
        {
            sslStreamToDispose = _sslStream;
            networkStreamToDispose = _stream;
            socketToDispose = _socket;
            
            // Clear the references to prevent reuse
            _sslStream = null;
            _stream = null;
            _socket = null;
        }
        
        // Now dispose the captured references outside the lock
        try
        {
            if (sslStreamToDispose != null)
            {
                _logger.LogDebug("TlsClient: Disposing SSL stream");
                sslStreamToDispose.Dispose();
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "TlsClient: Error disposing SSL stream");
        }
        
        try
        {
            if (networkStreamToDispose != null)
            {
                _logger.LogDebug("TlsClient: Disposing network stream");
                networkStreamToDispose.Dispose();
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "TlsClient: Error disposing network stream");
        }
        
        try
        {
            if (socketToDispose != null)
            {
                _logger.LogDebug("TlsClient: Disposing socket");
                
                try
                {
                    // Attempt to gracefully close the socket if it's connected
                    if (socketToDispose.Connected)
                    {
                        socketToDispose.Shutdown(SocketShutdown.Both);
                        _logger.LogDebug("TlsClient: Socket shutdown completed");
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "TlsClient: Error shutting down socket");
                }
                
                socketToDispose.Dispose();
                _logger.LogDebug("TlsClient: Socket disposed");
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "TlsClient: Error disposing socket");
        }
        
        _logger.LogDebug("TlsClient: Connection resources cleanup completed");
    }

    private async Task ReadStreamAsync()
    {
        _logger.LogDebug("TlsClient: Starting read stream task");
        try
        {
            // Create endpoint info string
            string remoteEndpoint = "unknown";
            if (_socket != null && _socket.Connected && _socket.RemoteEndPoint is System.Net.IPEndPoint ipEndPoint) 
            {
                remoteEndpoint = $"{ipEndPoint.Address}:{ipEndPoint.Port}";
            }
            
            var buffer = new byte[8192];
            var readTimeout = TimeSpan.FromSeconds(30);

            while (!_cancellationTokenSource.Token.IsCancellationRequested)
            {
                try
                {
                    _logger.LogTrace("TlsClient: Reading from SSL stream");
                    
                    using var readTimeoutCts = CancellationTokenSource.CreateLinkedTokenSource(_cancellationTokenSource.Token);
                    readTimeoutCts.CancelAfter(readTimeout);
                    
                    var bytesRead = await _sslStream!.ReadAsync(buffer.AsMemory(), readTimeoutCts.Token);
                    
                    _logger.LogTrace("TlsClient: Read {BytesRead} bytes from SSL stream", bytesRead);
                    
                    if (bytesRead == 0)
                    {
                        _logger.LogDebug("TlsClient: End of SSL stream reached (0 bytes read)");
                        break;
                    }
                    
                    // Process the data
                    var memory = new ReadOnlyMemory<byte>(buffer, 0, bytesRead);
                    _logger.LogDebug("TlsClient: Triggering DataReceived event for {BytesRead} bytes from {RemoteEndpoint}\n{DataPreview}", 
                        bytesRead, remoteEndpoint, StringUtils.GetDataPreview(memory));
                    OnDataReceived(memory, remoteEndpoint);
                }
                catch (OperationCanceledException)
                {
                    if (_cancellationTokenSource.Token.IsCancellationRequested)
                    {
                        _logger.LogDebug("TlsClient: Read operation was canceled by user");
                    }
                    else
                    {
                        _logger.LogDebug("TlsClient: Read operation timed out");
                    }
                    break;
                }
                catch (IOException ioEx) 
                {
                    // Common IO exceptions during network operations
                    if (ioEx.InnerException is SocketException socketEx)
                    {
                        _logger.LogDebug("TlsClient: Socket error during read: {Error} ({Code})", 
                            socketEx.Message, socketEx.SocketErrorCode);
                    }
                    else
                    {
                        _logger.LogDebug("TlsClient: IO error during read: {Message}", ioEx.Message);
                    }
                    break;
                }
                catch (ObjectDisposedException) 
                {
                    _logger.LogDebug("TlsClient: SSL stream was disposed during read");
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "TlsClient: Unexpected error during read");
                    break;
                }
            }
            _logger.LogDebug("TlsClient: Read stream loop completed normally");
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("TlsClient: Read operation was canceled");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "TlsClient: Error reading from SSL stream");
        }
        
        // Always try to disconnect when the read loop exits
        try 
        {
            _logger.LogDebug("TlsClient: Read loop exited, initiating graceful disconnect");
            await StopConnectionAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "TlsClient: Error during automatic disconnect after read loop exit");
        }
        
        _logger.LogDebug("TlsClient: Read stream task completed");
    }

    protected override async Task StopConnectionAsync()
    {
        _logger.LogDebug("TlsClient: StopConnectionAsync called");
        
        // Gracefully close the SSL connection if possible
        if (_sslStream != null)
        {
            try
            {
                _logger.LogDebug("TlsClient: Closing SSL stream");
                await _sslStream.ShutdownAsync();
                _logger.LogDebug("TlsClient: SSL stream shutdown completed successfully");
            }
            catch (ObjectDisposedException)
            {
                _logger.LogDebug("TlsClient: SSL stream was already disposed");
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "TlsClient: Error during SSL stream shutdown");
            }
        }
        
        // Clean up all connection resources
        CleanupConnection();
        _logger.LogDebug("TlsClient: Connection stopped");
    }

    // Override the correct method from BaseConnection
    protected override async Task WriteDataAsync(ReadOnlyMemory<byte> data)
    {
        // Check connection state and attempt to reconnect if needed
        if (!IsConnectionHealthy())
        {
            _logger.LogWarning("TlsClient: SSL connection is not healthy. Attempting to reconnect first.");
            try
            {
                await StartConnectionAsync();
                // Ensure the connection started event is triggered
                OnConnectionStarted();
            }
            catch (Exception ex)
            {
                var innerMsg = ex.InnerException != null ? $" Inner exception: {ex.InnerException.GetType().Name}: {ex.InnerException.Message}" : "";
                _logger.LogError(ex, "TlsClient: Failed to auto-connect before writing data - {ExceptionType}: {Message}{InnerMsg}", 
                    ex.GetType().Name, ex.Message, innerMsg);
                
                if (ex.InnerException != null)
                {
                    _logger.LogError("TlsClient: Inner exception - {InnerType}: {InnerMessage}", 
                        ex.InnerException.GetType().Name, ex.InnerException.Message);
                }
                
                throw new InvalidOperationException("Cannot write to SSL stream: failed to connect", ex);
            }
            
            // Double check that the stream was initialized
            if (_sslStream == null)
            {
                _logger.LogError("TlsClient: SSL stream is still null after auto-connect attempt");
                throw new InvalidOperationException("SSL stream is not initialized after connection attempt. Call ConnectAsync first.");
            }
        }
        
        // Get remote endpoint info for logging if available
        string remoteEndpoint = "unknown";
        if (_socket != null && _socket.Connected && _socket.RemoteEndPoint is System.Net.IPEndPoint ipEndPoint) 
        {
            remoteEndpoint = $"{ipEndPoint.Address}:{ipEndPoint.Port}";
        }
        
        _logger.LogDebug("TlsClient: Writing {ByteCount} bytes to SSL stream for {Host}:{Port} {RemoteEndpoint}\n{DataPreview}",
            data.Length, _host, _port, remoteEndpoint, StringUtils.GetDataPreview(data));
            
        await _sslStream!.WriteAsync(data);
    }

    /// <summary>
    /// Checks if the current connection is healthy and ready for data transfer
    /// </summary>
    /// <returns>True if the connection is healthy, false otherwise</returns>
    private bool IsConnectionHealthy()
    {
        // Check if we have the basic components needed for a healthy connection
        if (_sslStream == null || _stream == null || _socket == null)
        {
            _logger.LogDebug("TlsClient: Connection health check failed - missing stream or socket components");
            return false;
        }

        // Check if the socket is connected
        if (!_socket.Connected)
        {
            _logger.LogDebug("TlsClient: Connection health check failed - socket is not connected");
            return false;
        }

        // Check if the socket is usable by checking for errors
        try
        {
            // Poll the socket with a zero timeout to check if it's still usable
            if (_socket.Poll(0, SelectMode.SelectError))
            {
                var socketOption = _socket.GetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Error);
                var errorCode = socketOption is int code ? (SocketError)code : SocketError.NotSocket;
                _logger.LogDebug("TlsClient: Connection health check failed - socket has error: {ErrorCode}", errorCode);
                return false;
            }

            // Additional check: See if we can read/write data (with zero timeout - non-blocking)
            bool canRead = _socket.Poll(0, SelectMode.SelectRead);
            bool canWrite = _socket.Poll(0, SelectMode.SelectWrite);
            
            // If we can write but not read (normal for a healthy idle connection)
            // or if we can both read and write, the socket is usable
            if (canWrite)
            {
                _logger.LogDebug("TlsClient: Connection health check passed - socket is ready");
                return true;
            }
            else
            {
                _logger.LogDebug("TlsClient: Connection health check failed - socket cannot write");
                return false;
            }
        }
        catch (SocketException sx)
        {
            _logger.LogDebug(sx, "TlsClient: Connection health check failed - socket exception: {Error}", sx.SocketErrorCode);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "TlsClient: Connection health check failed - exception during check");
            return false;
        }
    }

    public async Task ConnectAsync(CancellationToken cancellationToken = default)
    {
        await StartAsync(cancellationToken);
    }

    public async Task DisconnectAsync(CancellationToken cancellationToken = default)
    {
        await StopAsync(cancellationToken);
    }

    public override async ValueTask DisposeAsync()
    {
        await StopConnectionAsync();
        CleanupConnection();
        
        // At this point _socket should be null since CleanupConnection was called
        // but we'll check anyway to avoid any NullReferenceException
        if (_socket != null)
        {
            try
            {
                _socket.Dispose();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "TlsClient: Error disposing socket during DisposeAsync");
            }
        }
        
        await base.DisposeAsync();
    }

    public async Task DisconnectAsync()
    {
        await StopAsync();
    }
    
    /// <summary>
    /// Sends an authentication header over the TLS connection.
    /// </summary>
    /// <param name="headerName">Name of the header</param>
    /// <param name="headerValue">Value of the header</param>
    /// <returns>Task representing the asynchronous operation</returns>
    /// <exception cref="InvalidOperationException">Thrown if the connection is not established</exception>
    public async Task SendAuthenticationHeaderAsync(string headerName, string headerValue)
    {
        if (_sslStream == null || !IsConnected)
        {
            throw new InvalidOperationException("Cannot send authentication header: Connection not established");
        }
        
        _logger.LogDebug("TlsClient: Sending authentication header: {HeaderName}", headerName);
        
        // Format as HTTP-style header
        var headerData = Encoding.UTF8.GetBytes($"{headerName}: {headerValue}\r\n");
        
        try
        {
            await _sslStream.WriteAsync(headerData);
            _logger.LogDebug("TlsClient: Authentication header sent successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "TlsClient: Failed to send authentication header");
            throw;
        }
    }

    // Helper method to check if an IO exception is recoverable
    private bool IsRecoverableIoException(IOException ex)
    {
        // Check if the exception is related to connection reset or aborted
        if (ex.InnerException is SocketException socketEx)
        {
            // These are errors that might be recoverable with a retry
            return socketEx.SocketErrorCode == SocketError.ConnectionReset ||
                   socketEx.SocketErrorCode == SocketError.ConnectionAborted ||
                   socketEx.SocketErrorCode == SocketError.TimedOut ||
                   socketEx.SocketErrorCode == SocketError.HostUnreachable ||
                   socketEx.SocketErrorCode == SocketError.NetworkUnreachable;
        }
        
        // Check message for common recoverable errors
        string message = ex.Message.ToLowerInvariant();
        return message.Contains("reset") ||
               message.Contains("aborted") ||
               message.Contains("closed") ||
               message.Contains("terminated");
    }

    // Override the base OnConnectionStarted method to include logging
    protected override void OnConnectionStarted()
    {
        _logger.LogInformation("TlsClient: Connection established with {Host}:{Port}", _host, _port);
        base.OnConnectionStarted();
    }
} 