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
using System.ComponentModel; // For Win32Exception

namespace CsProxyTools.Servers;

public class TlsServer : BaseConnection, IServer
{
    private readonly string _host;
    private readonly int _port;
    private readonly string? _certificatePath;
    private readonly string? _certificatePassword;
    private Socket _listener;
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
        _listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
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
        _listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
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
        
        // Parse the host and ensure we use IPv4 only
        IPAddress bindAddress;
        if (_host == "0.0.0.0" || _host == "127.0.0.1" || _host == "localhost" || _host == "::1")
        {
            // Use explicit IPv4 loopback for localhost
            bindAddress = IPAddress.Parse("127.0.0.1");
            _logger.LogDebug("TlsServer: Using IPv4 loopback address (127.0.0.1) for binding");
        }
        else if (_host == "::" || _host == "0:0:0:0:0:0:0:0")
        {
            // Use explicit IPv4 any address instead of IPv6 any
            bindAddress = IPAddress.Any;
            _logger.LogDebug("TlsServer: Using IPv4 any address (0.0.0.0) for binding");
        }
        else if (IPAddress.TryParse(_host, out var parsedAddress))
        {
            if (parsedAddress.AddressFamily == AddressFamily.InterNetworkV6)
            {
                // Convert IPv6 to equivalent IPv4 if possible, otherwise use IPv4 any
                _logger.LogWarning("TlsServer: IPv6 address specified, converting to IPv4 for consistency");
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
            _logger.LogWarning("TlsServer: Invalid address format: {Host}, using IPv4 any address (0.0.0.0)", _host);
            bindAddress = IPAddress.Any;
        }
        
        // Create a new IPv4 socket
        _listener.Close();
        _listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        
        // Bind to the IPv4 address
        _listener.Bind(new IPEndPoint(bindAddress, _port));
        _listener.Listen(128);
        IsRunning = true;
        _logger.LogInformation("TlsServer: Listening on {Address}:{Port} (IPv4)", bindAddress, _port);
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
            
            // Try different certificate format options if needed
            X509Certificate2? effectiveCert = _certificate;
            
            // Export the certificate with private key to try different format
            try
            {
                if (_certificate?.HasPrivateKey == true)
                {
                    _logger.LogDebug("TLS Server: Using certificate with private key for client {ClientIpPort}:{ClientId}", 
                        clientIpPort, clientId);
                    _logger.LogDebug("TLS Server: Certificate subject: {Subject}, Issuer: {Issuer}, HasPrivateKey: {HasPrivateKey}",
                        _certificate.Subject, _certificate.Issuer, _certificate.HasPrivateKey);
                    
                    // Check if this might be a browser connection sending plain HTTP instead of initiating TLS handshake
                    var initialByte = new byte[1];
                    if (stream.DataAvailable && stream.Read(initialByte, 0, 1) == 1)
                    {
                        if (initialByte[0] == 'G' || initialByte[0] == 'P' || initialByte[0] == 'H') // GET, POST, HEAD, etc.
                        {
                            _logger.LogWarning("TLS Server: Client appears to be sending plain HTTP rather than initiating TLS handshake");
                            throw new InvalidOperationException("Client appears to be sending plain HTTP rather than initiating TLS handshake");
                        }
                    }
                }
                else
                {
                    _logger.LogWarning("TLS Server: Certificate does not have private key accessible. Subject: {Subject}, Thumbprint: {Thumbprint}",
                        _certificate?.Subject, _certificate?.Thumbprint);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "TLS Server: Error processing certificate for client {ClientIpPort}:{ClientId}", 
                    clientIpPort, clientId);
                throw;
            }

            // Configure comprehensive server options
            var sslServerOptions = new SslServerAuthenticationOptions
            {
                ServerCertificate = effectiveCert,
                ClientCertificateRequired = _requireClientCert,
                RemoteCertificateValidationCallback = ValidateClientCertificate,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                AllowRenegotiation = true
            };

            // Authenticate asynchronously with proper timeout and error handling
            try 
            {
                await sslStream.AuthenticateAsServerAsync(sslServerOptions, combinedCts.Token);
                
                // Log successful handshake details
                _logger.LogInformation("TLS Server: Successful handshake with client {ClientIpPort}:{ClientId} using {Protocol}",
                    clientIpPort, clientId, sslStream.SslProtocol);
                _logger.LogDebug("TLS Server: Cipher: {Cipher}, Strength: {Strength} bits",
                    sslStream.CipherAlgorithm, sslStream.CipherStrength);
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
                
                // Get inner exception details for better diagnosis
                if (ex.InnerException != null)
                {
                    _logger.LogWarning("TlsServer: Inner exception: {Type} - {Message}, HResult: 0x{HResult:X8}", 
                        ex.InnerException.GetType().Name, ex.InnerException.Message, ex.InnerException.HResult);
                }
                throw;
            }
            catch (AuthenticationException ex)
            {
                _logger.LogWarning("TlsServer: TLS authentication failed for client {ClientIpPort}:{ClientId}: {Message}", 
                    clientIpPort, clientId, ex.Message);
                
                // Get inner exception details for better diagnosis
                if (ex.InnerException != null)
                {
                    _logger.LogWarning("TlsServer: Inner exception: {Type} - {Message}, HResult: 0x{HResult:X8}", 
                        ex.InnerException.GetType().Name, ex.InnerException.Message, ex.InnerException.HResult);
                    
                    if (ex.InnerException is Win32Exception win32Ex)
                    {
                        _logger.LogWarning("TlsServer: Win32 error code: 0x{ErrorCode:X8} - {NativeErrorCode}", 
                            win32Ex.ErrorCode, win32Ex.NativeErrorCode);
                    }
                }
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogWarning("TlsServer: TLS handshake error for client {ClientIpPort}:{ClientId}: {Message}", 
                    clientIpPort, clientId, ex.Message);
                
                // Get inner exception details for better diagnosis
                if (ex.InnerException != null)
                {
                    _logger.LogWarning("TlsServer: Inner exception: {Type} - {Message}, HResult: 0x{HResult:X8}", 
                        ex.InnerException.GetType().Name, ex.InnerException.Message, ex.InnerException.HResult);
                }
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