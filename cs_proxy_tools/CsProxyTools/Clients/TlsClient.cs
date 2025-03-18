using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.IO.Pipelines;
using CsProxyTools.Base;
using CsProxyTools.Interfaces;
using Microsoft.Extensions.Logging;
using System.Text;

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
        // First establish TCP connection
        _logger.LogDebug("TlsClient: Starting TCP connection to {Host}:{Port}", _host, _port);
        
        try
        {
            // Configure socket for better performance with TLS
            _socket.ReceiveBufferSize = 16384; // Larger buffer for TLS frames
            _socket.SendBufferSize = 16384;
            _socket.NoDelay = true; // Disable Nagle algorithm for lower latency
            _socket.LingerState = new LingerOption(false, 0); // Don't linger on close
            
            // Set adequate timeouts
            _socket.ReceiveTimeout = (int)TimeSpan.FromSeconds(30).TotalMilliseconds;
            _socket.SendTimeout = (int)TimeSpan.FromSeconds(30).TotalMilliseconds;
            
            _logger.LogDebug("TlsClient: Connecting to {Host}:{Port}", _host, _port);
            await _socket.ConnectAsync(_host, _port);
            
            if (!_socket.Connected)
            {
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
            _logger.LogError(ex, "TlsClient: Failed to establish TCP connection to {Host}:{Port}", _host, _port);
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
                _socket.Dispose();
                _socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                
                _socket.ReceiveBufferSize = 16384;
                _socket.SendBufferSize = 16384;
                _socket.NoDelay = true;
                _socket.LingerState = new LingerOption(false, 0);
                
                await _socket.ConnectAsync(_host, _port);
                
                if (!_socket.Connected)
                {
                    throw new InvalidOperationException($"Failed to connect to {_host}:{_port} on retry {retryCount}");
                }
                
                // Create a new network stream
                _stream = new NetworkStream(_socket, true);
                
                // Create a new SSL stream
                _sslStream = new SslStream(
                    _stream,
                    false,
                    ValidateServerCertificate,
                    null,
                    EncryptionPolicy.RequireEncryption);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "TlsClient: Failed to re-establish TCP connection on retry {Attempt}", retryCount);
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
        
        // Safely capture references to disposable objects
        lock (this)
        {
            sslStreamToDispose = _sslStream;
            networkStreamToDispose = _stream;
            
            // Clear the references to prevent reuse
            _sslStream = null;
            _stream = null;
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
            if (_socket.Connected)
            {
                _logger.LogDebug("TlsClient: Closing connected socket");
                try
                {
                    _socket.Shutdown(SocketShutdown.Both);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug("TlsClient: Error during socket shutdown: {Message}", ex.Message);
                }
                
                _socket.Close(0); // Close immediately without linger
            }
        }
        catch (ObjectDisposedException)
        {
            _logger.LogDebug("TlsClient: Socket was already disposed");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "TlsClient: Error during socket cleanup");
        }
        
        _logger.LogDebug("TlsClient: Connection cleanup completed");
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
        _logger.LogDebug("TlsClient: Stopping connection");
        try
        {
            if (_sslStream != null)
            {
                // Try to shut down the TLS session gracefully
                await _sslStream.ShutdownAsync();
                _logger.LogDebug("TlsClient: SSL shutdown completed");
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "TlsClient: Error during SSL shutdown");
        }
        finally
        {
            CleanupConnection();
        }
        _logger.LogDebug("TlsClient: Connection stopped");
    }

    // Override the correct method from BaseConnection
    protected override async Task WriteDataAsync(ReadOnlyMemory<byte> data)
    {
        if (_sslStream == null)
        {
            _logger.LogWarning("TlsClient: SSL stream is not initialized. Attempting to connect first.");
            try {
                await StartConnectionAsync();
                // Ensure the connection started event is triggered
                OnConnectionStarted();
            } catch (Exception ex) {
                throw new InvalidOperationException("Cannot write to SSL stream: failed to connect automatically.", ex);
            }
            
            // Double check that the stream was initialized
            if (_sslStream == null)
            {
                throw new InvalidOperationException("Cannot write to SSL stream: not connected");
            }
        }

        _logger.LogTrace("TlsClient: Writing {ByteCount} bytes to SSL stream", data.Length);
        await _sslStream.WriteAsync(data, _cancellationTokenSource.Token);
        _logger.LogTrace("TlsClient: Finished writing to SSL stream");
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
        _socket.Dispose();
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