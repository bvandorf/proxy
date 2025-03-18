using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.IO.Pipelines;
using CsProxyTools.Base;
using CsProxyTools.Interfaces;
using Microsoft.Extensions.Logging;

namespace CsProxyTools.Clients;

public class TlsClient : BaseConnection, IClient
{
    private readonly string _host;
    private readonly int _port;
    private readonly bool _validateCertificate;
    private readonly Socket _socket;
    private NetworkStream? _stream;
    private SslStream? _sslStream;

    // Default handshake timeout increased to 30 seconds
    private readonly TimeSpan _handshakeTimeout = TimeSpan.FromSeconds(30);

    public TlsClient(ILogger logger, string host, int port, bool validateCertificate = true) 
        : base(logger, Guid.NewGuid().ToString())
    {
        _host = host;
        _port = port;
        _validateCertificate = validateCertificate;
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
            await _socket.ConnectAsync(_host, _port);
            
            if (!_socket.Connected)
            {
                throw new InvalidOperationException($"Failed to connect to {_host}:{_port}");
            }
            
            _logger.LogDebug("TlsClient: TCP socket connected successfully to {Host}:{Port}", _host, _port);
            
            // Set socket options for better reliability
            _socket.NoDelay = true;
            _socket.ReceiveTimeout = (int)TimeSpan.FromSeconds(30).TotalMilliseconds;
            _socket.SendTimeout = (int)TimeSpan.FromSeconds(30).TotalMilliseconds;
            
            // Create network stream
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
            throw;
        }
        
        // Now perform the SSL handshake
        try
        {
            // Configure SSL options with relaxed security for testing
            var sslOptions = new SslClientAuthenticationOptions
            {
                TargetHost = _host,
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12,
                RemoteCertificateValidationCallback = ValidateServerCertificate,
                AllowRenegotiation = true,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption
            };
            
            _logger.LogDebug("TlsClient: Beginning SSL handshake with {Host} using TLS 1.2", _host);
            
            // Use a timeout for the SSL handshake
            using var handshakeTimeoutCts = CancellationTokenSource.CreateLinkedTokenSource(_cancellationTokenSource.Token);
            handshakeTimeoutCts.CancelAfter(_handshakeTimeout);
            
            _logger.LogDebug("TlsClient: Starting SSL handshake with timeout of {Seconds} seconds", _handshakeTimeout.TotalSeconds);
            await _sslStream.AuthenticateAsClientAsync(sslOptions, handshakeTimeoutCts.Token);
            _logger.LogDebug("TlsClient: SSL handshake completed successfully");
        }
        catch (OperationCanceledException) 
        {
            if (_cancellationTokenSource.Token.IsCancellationRequested)
                _logger.LogDebug("TlsClient: SSL handshake canceled by user");
            else
                _logger.LogWarning("TlsClient: SSL handshake timed out after {Seconds} seconds", _handshakeTimeout.TotalSeconds);
            
            CleanupConnection();
            throw;
        }
        catch (IOException ioEx)
        {
            _logger.LogError(ioEx, "TlsClient: IO error during SSL handshake: {Message}", ioEx.Message);
            CleanupConnection();
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "TlsClient: SSL handshake failed: {Message}", ex.Message);
            CleanupConnection();
            throw;
        }

        // Start reading from the stream
        _logger.LogDebug("TlsClient: Starting read stream task");
        _ = ReadStreamAsync();
        _logger.LogDebug("TlsClient: Connection started successfully");
    }

    private void CleanupConnection()
    {
        try
        {
            _sslStream?.Dispose();
            _stream?.Dispose();
            
            if (_socket.Connected)
            {
                _socket.Shutdown(SocketShutdown.Both);
                _socket.Close();
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "TlsClient: Error during connection cleanup");
        }
        finally
        {
            _sslStream = null;
            _stream = null;
        }
    }

    private async Task ReadStreamAsync()
    {
        _logger.LogDebug("TlsClient: Starting read stream task");
        try
        {
            var buffer = new byte[8192];
            while (!_cancellationTokenSource.Token.IsCancellationRequested && _sslStream != null)
            {
                _logger.LogTrace("TlsClient: Reading from SSL stream");
                int bytesRead;
                
                try {
                    bytesRead = await _sslStream.ReadAsync(buffer, 0, buffer.Length, _cancellationTokenSource.Token);
                    _logger.LogTrace("TlsClient: Read {BytesRead} bytes from SSL stream", bytesRead);
                }
                catch (IOException ioEx) {
                    _logger.LogDebug("TlsClient: IO error during read: {Message}", ioEx.Message);
                    break;
                }
                catch (ObjectDisposedException) {
                    _logger.LogDebug("TlsClient: SSL stream was disposed during read");
                    break;
                }
                
                if (bytesRead == 0) 
                {
                    _logger.LogDebug("TlsClient: End of SSL stream reached (0 bytes read)");
                    break;
                }

                var memory = new ReadOnlyMemory<byte>(buffer, 0, bytesRead);
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
            throw new InvalidOperationException("Cannot write to SSL stream: not connected");
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
} 