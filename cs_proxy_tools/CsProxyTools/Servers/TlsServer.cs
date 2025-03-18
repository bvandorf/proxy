using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.IO.Pipelines;
using CsProxyTools.Base;
using CsProxyTools.Interfaces;
using Microsoft.Extensions.Logging;
using System.Security.Authentication;
using CsProxyTools.Helpers;

namespace CsProxyTools.Servers;

public class TlsServer : BaseConnection, IServer
{
    private readonly string _host;
    private readonly int _port;
    private readonly string? _certificatePath;
    private readonly string? _certificatePassword;
    private readonly Socket _listener;
    private readonly List<SslStream> _clients;
    private readonly object _clientsLock = new();
    private X509Certificate2? _certificate;
    private readonly bool _externalCertificate;
    private readonly bool _requireClientCert;
    private readonly X509Certificate2Collection? _clientCertificates;
    private readonly Func<X509Certificate2, X509Chain, SslPolicyErrors, bool>? _clientCertValidator;

    public event EventHandler<ConnectionEventArgs>? ClientConnected;
    public event EventHandler<ConnectionEventArgs>? ClientDisconnected;
    public bool IsRunning { get; private set; }

    public TlsServer(ILogger logger, string host, int port, string certificatePath, string certificatePassword, 
        bool requireClientCert = false, X509Certificate2Collection? clientCertificates = null) 
        : base(logger, Guid.NewGuid().ToString())
    {
        _host = host;
        _port = port;
        _certificatePath = certificatePath;
        _certificatePassword = certificatePassword;
        _listener = new Socket(SocketType.Stream, ProtocolType.Tcp);
        _clients = new List<SslStream>();
        _externalCertificate = false;
        _requireClientCert = requireClientCert;
        _clientCertificates = clientCertificates;
    }

    public TlsServer(ILogger logger, string host, int port, X509Certificate2 certificate,
        bool requireClientCert = false, X509Certificate2Collection? clientCertificates = null,
        Func<X509Certificate2, X509Chain, SslPolicyErrors, bool>? clientCertValidator = null) 
        : base(logger, Guid.NewGuid().ToString())
    {
        _host = host;
        _port = port;
        _certificatePath = null;
        _certificatePassword = null;
        _listener = new Socket(SocketType.Stream, ProtocolType.Tcp);
        _clients = new List<SslStream>();
        _certificate = certificate;
        _externalCertificate = true;
        _requireClientCert = requireClientCert;
        _clientCertificates = clientCertificates;
        _clientCertValidator = clientCertValidator;
    }

    protected override async Task StartConnectionAsync()
    {
        if (!_externalCertificate && _certificatePath != null && _certificatePassword != null)
        {
            _certificate = new X509Certificate2(_certificatePath, _certificatePassword);
        }
        
        _listener.Bind(new IPEndPoint(IPAddress.Parse(_host), _port));
        _listener.Listen(128);
        IsRunning = true;
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
                    _logger.LogError(ex, "Error closing client stream");
                }
            }
            _clients.Clear();
        }

        _listener.Close();
        
        if (!_externalCertificate)
        {
            _certificate?.Dispose();
            _certificate = null;
        }
        
        await Task.CompletedTask;
    }

    protected override async Task WriteDataAsync(ReadOnlyMemory<byte> buffer)
    {
        _logger.LogDebug("TlsServer: Broadcasting {ByteCount} bytes to {ClientCount} clients\n{DataPreview}", 
            buffer.Length, _clients.Count, StringUtils.GetDataPreview(buffer));
        
        foreach (var sslStream in _clients.ToArray())
        {
            try
            {
                await sslStream.WriteAsync(buffer);
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

    private bool ValidateClientCertificate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
    {
        _logger.LogDebug("TlsServer: Validating client certificate");
        
        if (!_requireClientCert)
        {
            _logger.LogDebug("TlsServer: Client certificate not required, accepting connection");
            return true;
        }

        if (certificate == null)
        {
            _logger.LogWarning("TlsServer: Client certificate required but none provided");
            return false;
        }

        if (_clientCertValidator != null && certificate is X509Certificate2 cert2)
        {
            _logger.LogDebug("TlsServer: Using custom client certificate validator");
            return _clientCertValidator(cert2, chain!, sslPolicyErrors);
        }

        if (_clientCertificates != null && _clientCertificates.Count > 0)
        {
            var clientCert = new X509Certificate2(certificate);
            foreach (var validCert in _clientCertificates)
            {
                if (clientCert.Thumbprint == validCert.Thumbprint)
                {
                    _logger.LogDebug("TlsServer: Client certificate found in trusted certificates");
                    return true;
                }
            }
            _logger.LogWarning("TlsServer: Client certificate not found in trusted certificates");
            return false;
        }

        if (sslPolicyErrors == SslPolicyErrors.None)
        {
            _logger.LogDebug("TlsServer: Client certificate validated without policy errors");
            return true;
        }

        _logger.LogWarning("TlsServer: Client certificate validation failed with policy errors: {Errors}", sslPolicyErrors);
        return false;
    }

    private async Task HandleClientAsync(Socket client)
    {
        if (_certificate == null)
        {
            throw new InvalidOperationException("Server certificate not initialized");
        }

        // Create a meaningful clientId that includes IP:Port
        var remoteEndPoint = client.RemoteEndPoint as System.Net.IPEndPoint;
        var clientIpPort = remoteEndPoint != null 
            ? $"{remoteEndPoint.Address}:{remoteEndPoint.Port}" 
            : "unknown";
        
        var clientId = $"{Guid.NewGuid():N}";
        
        _logger.LogDebug("TLS Server: Handling new client connection {ClientIpPort}:{ClientId}", 
            clientIpPort, clientId);
        
        // Set socket options for better reliability
        client.NoDelay = true;
        client.ReceiveBufferSize = 16384; // Larger buffer for TLS frames
        client.SendBufferSize = 16384;
        client.ReceiveTimeout = 30000; // 30 seconds timeout
        client.SendTimeout = 30000;
        
        // Create network stream with ownership of socket
        var stream = new NetworkStream(client, true);
        var sslStream = new SslStream(stream, false, ValidateClientCertificate);

        try
        {
            _logger.LogDebug("TLS Server: Starting SSL authentication with client {ClientIpPort}:{ClientId}", 
                clientIpPort, clientId);
            
            // Create a cancellation token with timeout
            using var handshakeTimeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var combinedCts = CancellationTokenSource.CreateLinkedTokenSource(
                handshakeTimeoutCts.Token, 
                _cancellationTokenSource.Token);
            
            // Configure comprehensive server options
            var sslServerOptions = new SslServerAuthenticationOptions
            {
                ServerCertificate = _certificate,
                ClientCertificateRequired = _requireClientCert,
                RemoteCertificateValidationCallback = ValidateClientCertificate,
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                AllowRenegotiation = true
            };

            // Authenticate asynchronously with proper timeout and error handling
            try 
            {
                await sslStream.AuthenticateAsServerAsync(sslServerOptions, combinedCts.Token);
            }
            catch (OperationCanceledException ex)
            {
                _logger.LogWarning("TlsServer: TLS handshake timed out for client {ClientIpPort}:{ClientId}: {Message}", 
                    clientIpPort, clientId, ex.Message);
                throw;
            }
            catch (IOException ex) 
            {
                _logger.LogWarning("TlsServer: TLS handshake IO error for client {ClientIpPort}:{ClientId}: {Message}", 
                    clientIpPort, clientId, ex.Message);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogWarning("TlsServer: TLS handshake error for client {ClientIpPort}:{ClientId}: {Message}", 
                    clientIpPort, clientId, ex.Message);
                throw;
            }
            
            // Finish up SSL handshake and proceed with connection
            _logger.LogDebug("TLS Server: SSL authentication completed with client {ClientIpPort}:{ClientId}", 
                clientIpPort, clientId);
            _logger.LogDebug("TLS Server: Protocol: {Protocol}, Cipher: {Cipher} ({Strength} bit)",
                sslStream.SslProtocol, sslStream.CipherAlgorithm, sslStream.CipherStrength);

            // Check if client provided a certificate when required
            if (_requireClientCert && sslStream.RemoteCertificate == null)
            {
                _logger.LogWarning("TLS Server: Client {ClientIpPort}:{ClientId} did not provide a required certificate", 
                    clientIpPort, clientId);
            }
            else if (sslStream.RemoteCertificate != null)
            {
                _logger.LogDebug("TLS Server: Client {ClientIpPort}:{ClientId} authenticated with certificate {Subject}",
                    clientIpPort, clientId, sslStream.RemoteCertificate.Subject);
            }

            lock (_clientsLock)
            {
                _clients.Add(sslStream);
            }

            // Add remote endpoint info to connection event args
            ClientConnected?.Invoke(this, new ConnectionEventArgs(clientId, clientIpPort));

            // Use a larger buffer for TLS frames
            var buffer = new byte[16384];
            
            while (!_cancellationTokenSource.Token.IsCancellationRequested)
            {
                int bytesRead;
                try
                {
                    bytesRead = await sslStream.ReadAsync(buffer, 0, buffer.Length, _cancellationTokenSource.Token);
                    
                    if (bytesRead == 0)
                    {
                        _logger.LogDebug("TLS Server: Client {ClientIpPort}:{ClientId} closed connection (0 bytes read)", 
                            clientIpPort, clientId);
                        break;
                    }
                    
                    _logger.LogTrace("TLS Server: Read {BytesRead} bytes from client {ClientIpPort}:{ClientId}", 
                        bytesRead, clientIpPort, clientId);
                    var memory = new ReadOnlyMemory<byte>(buffer, 0, bytesRead);
                    
                    _logger.LogDebug("TLS Server: Client {ClientIpPort}:{ClientId} data received\n{DataPreview}",
                        clientIpPort, clientId, StringUtils.GetDataPreview(memory));
                    
                    // Pass endpoint info into data received event
                    OnDataReceived(new DataReceivedEventArgs(clientId, memory, clientIpPort));
                }
                catch (OperationCanceledException)
                {
                    _logger.LogDebug("TLS Server: Read operation canceled for client {ClientIpPort}:{ClientId}", 
                        clientIpPort, clientId);
                    break;
                }
                catch (IOException ioEx)
                {
                    _logger.LogDebug("TLS Server: IO exception reading from client {ClientIpPort}:{ClientId}: {Message}", 
                        clientIpPort, clientId, ioEx.Message);
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "TLS Server: Error reading from client {ClientIpPort}:{ClientId}", 
                        clientIpPort, clientId);
                    break;
                }
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("TLS Server: Operation canceled for client {ClientIpPort}:{ClientId}", 
                clientIpPort, clientId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "TLS Server: Error handling client {ClientIpPort}:{ClientId}", 
                clientIpPort, clientId);
        }
        finally
        {
            _logger.LogDebug("TLS Server: Cleaning up connection for client {ClientIpPort}:{ClientId}", 
                clientIpPort, clientId);
            await RemoveClientAsync(sslStream);
            
            // Include IP:port in disconnect event
            ClientDisconnected?.Invoke(this, new ConnectionEventArgs(clientId, clientIpPort));
        }
    }

    private async Task RemoveClientAsync(SslStream client)
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
            _logger.LogError(ex, "Error closing client stream");
        }

        await Task.CompletedTask;
    }

    public override async ValueTask DisposeAsync()
    {
        await base.DisposeAsync();
        _listener.Dispose();
        
        if (!_externalCertificate)
        {
            _certificate?.Dispose();
        }
    }
} 