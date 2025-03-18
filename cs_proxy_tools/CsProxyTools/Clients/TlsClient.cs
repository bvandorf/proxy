using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.IO.Pipelines;
using CsProxyTools.Base;
using CsProxyTools.Interfaces;
using Microsoft.Extensions.Logging;
using System.Text;
using System.Net;

namespace CsProxyTools.Clients;

public class TlsClient : BaseConnection, ITlsClient
{
    private readonly string _host;
    private readonly int _port;
    private readonly bool _validateCertificate;
    private Socket _socket;
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
        _socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        _socket.NoDelay = true; // Disable Nagle algorithm
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
            // Ensure the socket is properly created and not in an invalid state
            if (_socket == null || _socket.Connected)
            {
                // If socket exists and is connected, dispose it first
                if (_socket != null)
                {
                    _logger.LogDebug("TlsClient: Disposing existing socket before creating a new one");
                    _socket.Dispose();
                }
                
                _socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                _logger.LogDebug("TlsClient: Created new socket");
            }
            
            // Configure socket for better performance with TLS
            _logger.LogDebug("TlsClient: Configuring socket options");
            try
            {
                _socket.ReceiveBufferSize = 16384; // Larger buffer for TLS frames
                _socket.SendBufferSize = 16384;
                _socket.NoDelay = true; // Disable Nagle algorithm for lower latency
                _socket.LingerState = new LingerOption(false, 0); // Don't linger on close
                
                // Set adequate timeouts - validate the values are positive
                int timeout = (int)TimeSpan.FromSeconds(30).TotalMilliseconds;
                if (timeout > 0)
                {
                    _socket.ReceiveTimeout = timeout;
                    _socket.SendTimeout = timeout;
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
            
            // Attempt to resolve the hostname to check if it's valid before connecting
            IPAddress[] addresses;
            try
            {
                _logger.LogDebug("TlsClient: Resolving hostname: {Host}", _host);
                // Check if the host is an IP address first
                if (IPAddress.TryParse(_host, out var ipAddress))
                {
                    addresses = new[] { ipAddress };
                    _logger.LogDebug("TlsClient: Host is a valid IP address: {Address}", ipAddress);
                }
                else
                {
                    // Resolve hostname to IP addresses
                    addresses = await Dns.GetHostAddressesAsync(_host);
                    _logger.LogDebug("TlsClient: Resolved {Host} to {AddressCount} addresses", _host, addresses.Length);
                    foreach (var addr in addresses)
                    {
                        _logger.LogDebug("TlsClient: Resolved address: {Address} ({AddressFamily})", addr, addr.AddressFamily);
                    }
                }
                
                // If no addresses were resolved, throw an exception
                if (addresses.Length == 0)
                {
                    throw new InvalidOperationException($"Could not resolve hostname: {_host}");
                }
                
                // Prefer IPv4 addresses if available
                var ipv4Addresses = addresses.Where(a => a.AddressFamily == AddressFamily.InterNetwork).ToArray();
                if (ipv4Addresses.Length > 0)
                {
                    addresses = ipv4Addresses;
                    _logger.LogDebug("TlsClient: Using IPv4 addresses");
                }
                else
                {
                    _logger.LogDebug("TlsClient: No IPv4 addresses found, using all resolved addresses");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "TlsClient: Failed to resolve hostname: {Host}", _host);
                throw new InvalidOperationException($"Failed to resolve hostname: {_host}", ex);
            }
            
            // Try to connect using the resolved addresses
            Exception? lastConnectException = null;
            bool connected = false;
            
            foreach (var address in addresses)
            {
                try
                {
                    // Create endpoint with the resolved address
                    var endpoint = new IPEndPoint(address, _port);
                    _logger.LogDebug("TlsClient: Connecting to {Endpoint}", endpoint);
                    
                    // Connect to the endpoint
                    await _socket.ConnectAsync(endpoint);
                    connected = _socket.Connected;
                    
                    if (connected)
                    {
                        _logger.LogDebug("TlsClient: Successfully connected to {Endpoint}", endpoint);
                        break;
                    }
                }
                catch (SocketException sx)
                {
                    lastConnectException = sx;
                    _logger.LogWarning(sx, "TlsClient: Socket error connecting to {Address}:{Port}, SocketError: {Error}", 
                        address, _port, sx.SocketErrorCode);
                    
                    // If this is not the last address, try the next one
                    if (address != addresses.Last())
                    {
                        _logger.LogDebug("TlsClient: Will try next address");
                        continue;
                    }
                    
                    // Otherwise, re-throw the last exception
                    throw;
                }
                catch (Exception ex)
                {
                    lastConnectException = ex;
                    _logger.LogWarning(ex, "TlsClient: Error connecting to {Address}:{Port}", address, _port);
                    
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
            if (!connected)
            {
                if (lastConnectException != null)
                {
                    throw lastConnectException;
                }
                throw new InvalidOperationException($"Failed to connect to {_host}:{_port}");
            }
            
            _logger.LogDebug("TlsClient: TCP socket connected successfully to {Host}:{Port}", _host, _port);
            
            // Create network stream with ownership of socket
            _stream = new NetworkStream(_socket, true);
            _logger.LogDebug("TlsClient: Created network stream");
            
            // Create SSL stream with all necessary callbacks
            _sslStream = new SslStream(
                _stream,
                false,
                ValidateServerCertificate,
                null,
                EncryptionPolicy.RequireEncryption);
            
            _logger.LogDebug("TlsClient: Created SSL stream, starting handshake");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "TlsClient: Failed to establish TCP connection to {Host}:{Port} - {ExceptionType}: {Message}", 
                _host, _port, ex.GetType().Name, ex.Message);
            CleanupConnection();
            throw;
        }
        
        // Now perform the SSL handshake with multiple attempts if needed
        int retryCount = 0;
        const int maxRetries = 2;
        Exception? lastException = null;
        
        while (retryCount <= maxRetries)
        {
            try
            {
                // Configure SSL options with enhanced parameters
                var sslOptions = new SslClientAuthenticationOptions
                {
                    TargetHost = _host,
                    EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12,
                    RemoteCertificateValidationCallback = ValidateServerCertificate,
                    AllowRenegotiation = true,
                    EncryptionPolicy = EncryptionPolicy.RequireEncryption,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                };
                
                // If client certificate is provided, add it to the options
                if (_clientCertificate != null)
                {
                    _logger.LogDebug("TlsClient: Using client certificate for authentication: {Thumbprint}", 
                        _clientCertificate.Thumbprint);
                    
                    var clientCertificateCollection = new X509CertificateCollection
                    {
                        _clientCertificate
                    };
                    
                    sslOptions.ClientCertificates = clientCertificateCollection;
                }
                
                _logger.LogDebug("TlsClient: Beginning SSL handshake with {Host} using TLS 1.2 (Attempt {Attempt}/{MaxAttempts})", 
                    _host, retryCount + 1, maxRetries + 1);
                
                // Use a timeout for the SSL handshake
                using var handshakeTimeoutCts = CancellationTokenSource.CreateLinkedTokenSource(_cancellationTokenSource.Token);
                handshakeTimeoutCts.CancelAfter(_handshakeTimeout);
                
                _logger.LogDebug("TlsClient: Starting SSL handshake with timeout of {Seconds} seconds", _handshakeTimeout.TotalSeconds);
                
                await _sslStream.AuthenticateAsClientAsync(sslOptions, handshakeTimeoutCts.Token);
                
                // If we get here, authentication succeeded
                _logger.LogDebug("TlsClient: SSL handshake completed successfully");
                _logger.LogDebug("TlsClient: Negotiated Protocol: {Protocol}", _sslStream.SslProtocol);
                _logger.LogDebug("TlsClient: Cipher: {Cipher} ({Strength} bit)", _sslStream.CipherAlgorithm, _sslStream.CipherStrength);
                
                // If client certificate was used, log that information
                if (_clientCertificate != null && _sslStream.LocalCertificate != null)
                {
                    _logger.LogDebug("TlsClient: Client certificate was used for authentication");
                }
                
                // Authentication successful, break the retry loop
                break;
            }
            catch (OperationCanceledException) 
            {
                lastException = new TimeoutException($"SSL handshake timed out after {_handshakeTimeout.TotalSeconds} seconds");
                _logger.LogWarning("TlsClient: SSL handshake timed out after {Seconds} seconds (Attempt {Attempt}/{MaxAttempts})", 
                    _handshakeTimeout.TotalSeconds, retryCount + 1, maxRetries + 1);
            }
            catch (IOException ioEx)
            {
                lastException = ioEx;
                _logger.LogWarning(ioEx, "TlsClient: IO error during SSL handshake (Attempt {Attempt}/{MaxAttempts}): {Message}", 
                    retryCount + 1, maxRetries + 1, ioEx.Message);
            }
            catch (Exception ex)
            {
                lastException = ex;
                _logger.LogWarning(ex, "TlsClient: SSL handshake failed (Attempt {Attempt}/{MaxAttempts}): {Message}", 
                    retryCount + 1, maxRetries + 1, ex.Message);
            }
            
            retryCount++;
            
            // If we've reached max retries, clean up and throw the last exception
            if (retryCount > maxRetries)
            {
                _logger.LogError("TlsClient: SSL handshake failed after {MaxAttempts} attempts", maxRetries + 1);
                CleanupConnection();
                throw lastException!;
            }
            
            // Perform cleanup and retry with a new stream
            CleanupConnection();
            
            // Short delay before retry
            await Task.Delay(500 * retryCount);
            
            // Re-establish TCP connection with a new socket
            _logger.LogDebug("TlsClient: Retrying connection to {Host}:{Port} (Attempt {Attempt}/{MaxAttempts})", 
                _host, _port, retryCount + 1, maxRetries + 1);
            
            try
            {
                // Create a new socket for the retry
                _socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                _logger.LogDebug("TlsClient: Created new socket for retry");
                
                // Configure socket
                _socket.ReceiveBufferSize = 16384;
                _socket.SendBufferSize = 16384;
                _socket.NoDelay = true;
                _socket.LingerState = new LingerOption(false, 0);
                
                // Use a timeout for this connection attempt
                var connectTimeout = TimeSpan.FromSeconds(30);
                _logger.LogDebug("TlsClient: Connecting to {Host}:{Port} with timeout {Timeout}ms", 
                    _host, _port, connectTimeout.TotalMilliseconds);
                
                // Resolve the hostname again
                IPAddress[] addresses;
                if (IPAddress.TryParse(_host, out var ipAddress))
                {
                    addresses = new[] { ipAddress };
                }
                else
                {
                    addresses = await Dns.GetHostAddressesAsync(_host);
                    // Prefer IPv4 addresses if available
                    var ipv4Addresses = addresses.Where(a => a.AddressFamily == AddressFamily.InterNetwork).ToArray();
                    if (ipv4Addresses.Length > 0)
                    {
                        addresses = ipv4Addresses;
                    }
                }
                
                // Try to connect to the first address
                if (addresses.Length > 0)
                {
                    var endpoint = new IPEndPoint(addresses[0], _port);
                    _logger.LogDebug("TlsClient: Connecting to {Endpoint} for retry", endpoint);
                    
                    using (var cts = new CancellationTokenSource(connectTimeout))
                    {
                        try
                        {
                            await _socket.ConnectAsync(endpoint).WaitAsync(cts.Token);
                        }
                        catch (TimeoutException)
                        {
                            throw new TimeoutException($"Connection attempt timed out after {connectTimeout.TotalSeconds} seconds");
                        }
                    }
                }
                else
                {
                    throw new InvalidOperationException($"Could not resolve hostname: {_host}");
                }
                
                if (!_socket.Connected)
                {
                    throw new InvalidOperationException($"Failed to connect to {_host}:{_port} on retry {retryCount}");
                }
                
                // Create a new network stream
                _stream = new NetworkStream(_socket, true);
                _logger.LogDebug("TlsClient: Created new network stream for retry");
                
                // Create a new SSL stream
                _sslStream = new SslStream(
                    _stream,
                    false,
                    ValidateServerCertificate,
                    null,
                    EncryptionPolicy.RequireEncryption);
                _logger.LogDebug("TlsClient: Created new SSL stream for retry");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "TlsClient: Failed to re-establish TCP connection on retry {Attempt} - {ExceptionType}: {Message}", 
                    retryCount, ex.GetType().Name, ex.Message);
                CleanupConnection();
                throw;
            }
        }

        // Start reading from the stream
        _logger.LogDebug("TlsClient: Starting read stream task");
        _ = ReadStreamAsync();
        _logger.LogDebug("TlsClient: Connection started successfully");
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
            // Use a larger buffer for TLS frames
            var buffer = new byte[16384];
            
            while (!_cancellationTokenSource.Token.IsCancellationRequested && _sslStream != null)
            {
                int bytesRead;
                
                try 
                {
                    _logger.LogTrace("TlsClient: Reading from SSL stream");
                    
                    // Use cancellation token but with a timeout per read operation
                    using var readTimeoutCts = CancellationTokenSource.CreateLinkedTokenSource(_cancellationTokenSource.Token);
                    readTimeoutCts.CancelAfter(TimeSpan.FromSeconds(30)); // 30 second timeout per read
                    
                    bytesRead = await _sslStream.ReadAsync(buffer, 0, buffer.Length, readTimeoutCts.Token);
                    _logger.LogTrace("TlsClient: Read {BytesRead} bytes from SSL stream", bytesRead);
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
                
                if (bytesRead == 0) 
                {
                    _logger.LogDebug("TlsClient: End of SSL stream reached (0 bytes read)");
                    break;
                }

                // Create a memory copy of the data to avoid buffer modification in callbacks
                var data = new byte[bytesRead];
                Buffer.BlockCopy(buffer, 0, data, 0, bytesRead);
                var memory = new ReadOnlyMemory<byte>(data);
                
                _logger.LogDebug("TlsClient: Triggering DataReceived event for {BytesRead} bytes", bytesRead);
                OnDataReceived(memory);
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
        if (_sslStream == null || !IsConnectionHealthy())
        {
            _logger.LogWarning("TlsClient: SSL connection is not healthy. Attempting to reconnect first.");
            try {
                await StopConnectionAsync(); // First clean up any existing connection
                await StartConnectionAsync(); // Then establish a fresh connection
                // Ensure the connection started event is triggered
                OnConnectionStarted();
            } catch (Exception ex) {
                _logger.LogError(ex, "TlsClient: Failed to auto-connect before writing data - {ExceptionType}: {Message}", 
                    ex.GetType().Name, ex.Message);
                if (ex.InnerException != null) {
                    _logger.LogError("TlsClient: Inner exception - {InnerType}: {InnerMessage}", 
                        ex.InnerException.GetType().Name, ex.InnerException.Message);
                }
                throw new InvalidOperationException("Cannot write to SSL stream: failed to connect automatically.", ex);
            }
            
            // Double check that the stream was initialized
            if (_sslStream == null)
            {
                _logger.LogError("TlsClient: SSL stream is still null after auto-connect attempt");
                throw new InvalidOperationException("Cannot write to SSL stream: not connected");
            }
        }

        _logger.LogDebug("TlsClient: Writing {ByteCount} bytes to SSL stream for {Host}:{Port}", 
            data.Length, _host, _port);
        
        try {
            await _sslStream.WriteAsync(data, _cancellationTokenSource.Token);
            _logger.LogDebug("TlsClient: Successfully wrote {ByteCount} bytes to SSL stream", data.Length);
        } 
        catch (IOException ioEx) {
            _logger.LogError(ioEx, "TlsClient: IO error writing to SSL stream - {Message}", ioEx.Message);
            if (ioEx.InnerException != null) {
                _logger.LogError("TlsClient: Inner exception - {InnerType}: {InnerMessage}", 
                    ioEx.InnerException.GetType().Name, ioEx.InnerException.Message);
            }
            
            // Check if socket is still connected
            bool isSocketConnected = _socket != null && _socket.Connected;
            _logger.LogError("TlsClient: Socket connected status: {IsConnected}", isSocketConnected);
            
            // Try to get socket error code if available
            if (_socket != null) {
                try {
                    var socketError = (SocketError)_socket.GetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Error);
                    _logger.LogError("TlsClient: Socket error code: {SocketError}", socketError);
                } catch (Exception ex) {
                    _logger.LogError(ex, "TlsClient: Error getting socket error code");
                }
            }
            
            throw;
        }
        catch (ObjectDisposedException dispEx) {
            _logger.LogError(dispEx, "TlsClient: Stream was disposed before writing data");
            throw;
        }
        catch (InvalidOperationException opEx) {
            _logger.LogError(opEx, "TlsClient: Invalid operation writing to SSL stream - {Message}", opEx.Message);
            throw;
        }
        catch (Exception ex) {
            _logger.LogError(ex, "TlsClient: Unexpected error writing to SSL stream - {ExceptionType}: {Message}", 
                ex.GetType().Name, ex.Message);
            if (ex.InnerException != null) {
                _logger.LogError("TlsClient: Inner exception - {InnerType}: {InnerMessage}", 
                    ex.InnerException.GetType().Name, ex.InnerException.Message);
            }
            throw;
        }
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
                var errorCode = (SocketError)_socket.GetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Error);
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
} 