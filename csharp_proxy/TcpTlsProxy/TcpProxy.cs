using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TcpTlsProxy
{
    /// <summary>
    /// Delegate for processing data between client and server
    /// Returns the processed data and a boolean indicating whether to forward the data
    /// </summary>
    public delegate (byte[] data, bool forward) DataProcessor(string clientId, byte[] data);

    /// <summary>
    /// TCP/TLS proxy implementation
    /// </summary>
    public class TcpProxy
    {
        private readonly ProxyConfig _config;
        private readonly ProxyLogger _logger;
        private TcpListener? _listener;
        private readonly CancellationTokenSource _internalCts = new CancellationTokenSource();
        private readonly List<Task> _activeTasks = new List<Task>();
        private readonly object _tasksLock = new object();
        
        // Dictionary to track active client connections in standalone mode
        private readonly Dictionary<string, ClientConnection> _activeClients = new Dictionary<string, ClientConnection>();
        private readonly object _clientsLock = new object();
        
        // Flag to indicate whether we're in standalone mode
        private bool _standaloneMode = false;

        /// <summary>
        /// Handler for processing data from client to server
        /// </summary>
        public DataProcessor? ClientToServerHandler { get; set; }

        /// <summary>
        /// Handler for processing data from server to client
        /// </summary>
        public DataProcessor? ServerToClientHandler { get; set; }

        /// <summary>
        /// Creates a new TCP/TLS proxy
        /// </summary>
        /// <param name="config">Proxy configuration</param>
        /// <param name="logger">Logger</param>
        public TcpProxy(ProxyConfig config, ProxyLogger logger)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Loads a certificate from the Windows certificate store
        /// </summary>
        private X509Certificate2? LoadCertificateFromStore(string subjectName, StoreName storeName, StoreLocation storeLocation)
        {
            if (string.IsNullOrEmpty(subjectName))
            {
                return null;
            }

            _logger.Log($"Loading certificate from Windows store with subject: {subjectName}, store: {storeName}, location: {storeLocation}");
            
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                _logger.LogError("Windows certificate store is only supported on Windows");
                throw new PlatformNotSupportedException("Windows certificate store is only supported on Windows");
            }

            try
            {
                using (var store = new X509Store(storeName, storeLocation))
                {
                    store.Open(OpenFlags.ReadOnly);
                    
                    var certificates = store.Certificates.Find(
                        X509FindType.FindBySubjectName, subjectName, false);
                    
                    if (certificates.Count == 0)
                    {
                        _logger.LogError($"No certificate found with subject name: {subjectName} in store: {storeName}, location: {storeLocation}");
                        return null;
                    }
                    
                    _logger.Log($"Found {certificates.Count} certificates matching subject name: {subjectName}");
                    
                    // Return the first certificate that has a private key (if available)
                    foreach (var cert in certificates)
                    {
                        if (cert.HasPrivateKey)
                        {
                            _logger.Log($"Selected certificate with private key: {cert.Thumbprint}");
                            return cert;
                        }
                    }
                    
                    // Fallback to first certificate if none has a private key
                    _logger.Log($"No certificate with private key found, using first available: {certificates[0].Thumbprint}");
                    return certificates[0];
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to load certificate from Windows store", ex);
                return null;
            }
        }

        /// <summary>
        /// Sets up client-side TLS configuration
        /// </summary>
        private void SetupClientTls()
        {
            if (!_config.ClientTls)
            {
                return;
            }

            _logger.Log("Setting up client-side TLS");
            
            try
            {
                // If the certificate has already been set directly (e.g. for testing), use it
                if (_config.ServerCertificate != null)
                {
                    _logger.Log("Using pre-configured server certificate");
                    return;
                }
                
                // Load server certificate from Windows store
                if (string.IsNullOrEmpty(_config.ServerCertSubject))
                {
                    throw new InvalidOperationException("Server certificate subject name is required for client TLS");
                }
                
                _config.ServerCertificate = LoadCertificateFromStore(
                    _config.ServerCertSubject, 
                    _config.ServerCertStoreName, 
                    _config.ServerCertStoreLocation);
                
                if (_config.ServerCertificate == null)
                {
                    throw new InvalidOperationException($"Failed to load server certificate with subject: {_config.ServerCertSubject}");
                }
                
                // If client auth is enabled, load CA certificate
                if (_config.ClientAuth)
                {
                    _logger.Log("Client authentication is enabled");
                    
                    if (string.IsNullOrEmpty(_config.CACertSubject))
                    {
                        throw new InvalidOperationException("CA certificate subject name is required for client authentication");
                    }
                    
                    _config.CACertificate = LoadCertificateFromStore(
                        _config.CACertSubject, 
                        _config.CACertStoreName, 
                        _config.CACertStoreLocation);
                    
                    if (_config.CACertificate == null)
                    {
                        throw new InvalidOperationException($"Failed to load CA certificate with subject: {_config.CACertSubject}");
                    }
                    
                    // Set up certificate validation callback
                    _config.ClientCertValidationCallback = (sender, cert, chain, errors) =>
                    {
                        if (cert == null)
                        {
                            _logger.LogError("Client did not provide a certificate");
                            return false;
                        }
                        
                        _logger.Log($"Validating client certificate: {cert.Subject}");
                        
                        // If insecure client is enabled, accept any client certificate
                        if (_config.InsecureSkipVerify)
                        {
                            _logger.Log("Insecure client mode is enabled, accepting any client certificate");
                            return true;
                        }
                        
                        // Validate client certificate against CA
                        var clientCert = new X509Certificate2(cert);
                        var caChain = new X509Chain();
                        caChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                        caChain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                        caChain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                        caChain.ChainPolicy.VerificationTime = DateTime.Now;
                        
                        // Add CA certificate to chain
                        caChain.ChainPolicy.ExtraStore.Add(_config.CACertificate);
                        
                        bool valid = caChain.Build(clientCert);
                        if (!valid)
                        {
                            _logger.LogError($"Client certificate validation failed: {errors}");
                            foreach (var status in caChain.ChainStatus)
                            {
                                _logger.LogError($"Chain status: {status.Status} - {status.StatusInformation}");
                            }
                            return false;
                        }
                        
                        _logger.Log("Client certificate is valid");
                        return true;
                    };
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("Failed to set up client-side TLS", ex);
                throw;
            }
        }

        /// <summary>
        /// Sets up target-side TLS configuration
        /// </summary>
        private void SetupTargetTls()
        {
            if (!_config.TargetTls)
            {
                return;
            }

            _logger.Log("Setting up target-side TLS");
            
            try
            {
                // Set up server certificate validation callback
                _config.ServerCertValidationCallback = (sender, cert, chain, errors) =>
                {
                    if (cert == null)
                    {
                        _logger.LogError("Server did not provide a certificate");
                        return false;
                    }
                    
                    _logger.Log($"Validating server certificate: {cert.Subject}");
                    
                    // If insecure skip verify is enabled, accept any server certificate
                    if (_config.InsecureSkipVerify)
                    {
                        _logger.Log("Insecure mode is enabled, accepting server certificate");
                        return true;
                    }
                    
                    // Otherwise, validate server certificate
                    if (errors != SslPolicyErrors.None)
                    {
                        _logger.LogError($"Server certificate validation failed: {errors}");
                        return false;
                    }
                    
                    _logger.Log("Server certificate is valid");
                    return true;
                };
                
                // Load client certificate if specified
                if (_config.ClientCertificate != null)
                {
                    _logger.Log("Using pre-configured client certificate");
                }
                else if (!string.IsNullOrEmpty(_config.ClientCertSubject))
                {
                    _logger.Log($"Loading client certificate from Windows store: {_config.ClientCertSubject}");
                    
                    _config.ClientCertificate = LoadCertificateFromStore(
                        _config.ClientCertSubject, 
                        _config.ClientCertStoreName, 
                        _config.ClientCertStoreLocation);
                    
                    if (_config.ClientCertificate == null)
                    {
                        _logger.LogError($"Failed to load client certificate with subject: {_config.ClientCertSubject}");
                    }
                    else
                    {
                        _logger.Log($"Successfully loaded client certificate: {_config.ClientCertificate.Subject}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("Failed to set up target-side TLS", ex);
                throw;
            }
        }

        /// <summary>
        /// Starts the proxy
        /// </summary>
        public async Task StartAsync(CancellationToken cancellationToken)
        {
            try
            {
                // Set up TLS configurations
                SetupClientTls();
                SetupTargetTls();
                
                // Parse listener address
                string[] parts = _config.ListenerAddress.Split(':');
                if (parts.Length != 2 || !int.TryParse(parts[1], out int port))
                {
                    throw new ArgumentException($"Invalid listener address: {_config.ListenerAddress}");
                }
                
                // Create and start listener
                _listener = new TcpListener(IPAddress.Parse(parts[0]), port);
                _listener.Start();
                
                _logger.Log($"Proxy listening on {_config.ListenerAddress}");
                
                // Set up a linked token source to handle both external and internal cancellation
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
                    cancellationToken, _internalCts.Token);
                
                while (!linkedCts.Token.IsCancellationRequested)
                {
                    try
                    {
                        // Accept client connection
                        var client = await _listener.AcceptTcpClientAsync().ConfigureAwait(false);
                        client.NoDelay = true; // Disable Nagle's algorithm for better performance
                        
                        _logger.Log($"Accepted connection from {((IPEndPoint)client.Client.RemoteEndPoint!).Address}");
                        
                        // Start processing client connection in a background task
                        var task = HandleClientAsync(client, linkedCts.Token);
                        
                        lock (_tasksLock)
                        {
                            _activeTasks.Add(task);
                        }
                        
                        // Clean up completed tasks to avoid memory leak
                        CleanupCompletedTasks();
                    }
                    catch (OperationCanceledException) when (linkedCts.Token.IsCancellationRequested)
                    {
                        // Normal cancellation
                        break;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError("Error accepting client connection", ex);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("Fatal error in proxy", ex);
                throw;
            }
            finally
            {
                // Stop the listener
                _listener?.Stop();
                _logger.Log("Proxy stopped");
                
                // Wait for all active tasks to complete
                await WaitForActiveTasksAsync().ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Cleans up completed tasks from the active tasks list
        /// </summary>
        private void CleanupCompletedTasks()
        {
            lock (_tasksLock)
            {
                for (int i = _activeTasks.Count - 1; i >= 0; i--)
                {
                    if (_activeTasks[i].IsCompleted)
                    {
                        _activeTasks.RemoveAt(i);
                    }
                }
            }
        }

        /// <summary>
        /// Waits for all active tasks to complete
        /// </summary>
        private async Task WaitForActiveTasksAsync()
        {
            Task[] tasks;
            
            lock (_tasksLock)
            {
                tasks = _activeTasks.ToArray();
            }
            
            if (tasks.Length > 0)
            {
                _logger.Log($"Waiting for {tasks.Length} active connections to complete");
                await Task.WhenAll(tasks).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Handles a client connection
        /// </summary>
        private async Task HandleClientAsync(TcpClient client, CancellationToken cancellationToken)
        {
            Stream clientStream = client.GetStream();
            TcpClient? targetTcpClient = null;
            Stream? targetStream = null;
            
            // Get client ID for data processing
            var clientEndPoint = (IPEndPoint)client.Client.RemoteEndPoint!;
            string clientId = $"{clientEndPoint.Address}:{clientEndPoint.Port}";
            
            try
            {
                // Set up client TLS if enabled
                if (_config.ClientTls)
                {
                    _logger.Log("Setting up TLS for client connection");
                    
                    SslStream sslStream = new SslStream(
                        clientStream,
                        false,
                        _config.ClientCertValidationCallback);
                    
                    // Server authentication mode
                    SslServerAuthenticationOptions options = new SslServerAuthenticationOptions
                    {
                        ServerCertificate = _config.ServerCertificate,
                        ClientCertificateRequired = _config.ClientAuth,
                        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
                    };
                    
                    await sslStream.AuthenticateAsServerAsync(options, cancellationToken).ConfigureAwait(false);
                    
                    _logger.Log($"TLS handshake completed with cipher: {sslStream.SslProtocol}");
                    clientStream = sslStream;
                }
                
                // Parse target address
                string[] targetParts = _config.TargetAddress.Split(':');
                string targetHost = targetParts[0];
                int targetPort = targetParts.Length > 1 ? int.Parse(targetParts[1]) : 80;
                
                // Connect to target
                _logger.Log($"Connecting to target: {targetHost}:{targetPort}");
                targetTcpClient = new TcpClient();
                targetTcpClient.NoDelay = true; // Disable Nagle's algorithm
                
                using var timeoutCts = new CancellationTokenSource(_config.DialTimeout);
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);
                
                try
                {
                    await targetTcpClient.ConnectAsync(targetHost, targetPort, linkedCts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (timeoutCts.Token.IsCancellationRequested)
                {
                    throw new TimeoutException($"Connection to target timed out after {_config.DialTimeout}ms");
                }
                
                targetStream = targetTcpClient.GetStream();
                
                // Set up target TLS if enabled
                if (_config.TargetTls)
                {
                    _logger.Log("Setting up TLS for target connection");
                    
                    SslStream sslStream = new SslStream(
                        targetStream,
                        false,
                        _config.ServerCertValidationCallback);
                    
                    // Client authentication options
                    SslClientAuthenticationOptions options = new SslClientAuthenticationOptions
                    {
                        TargetHost = targetHost,
                        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
                    };
                    
                    // Add client certificate if available
                    if (_config.ClientCertificate != null)
                    {
                        options.ClientCertificates = new X509CertificateCollection { _config.ClientCertificate };
                    }
                    
                    await sslStream.AuthenticateAsClientAsync(options, cancellationToken).ConfigureAwait(false);
                    
                    _logger.Log($"TLS handshake with target completed with cipher: {sslStream.SslProtocol}");
                    targetStream = sslStream;
                }
                
                // Start proxying data between client and target
                Task clientToTarget = ProxyDataAsync(
                    clientId, clientStream, targetStream, ClientToServerHandler, cancellationToken, "client", "target");
                
                Task targetToClient = ProxyDataAsync(
                    clientId, targetStream, clientStream, ServerToClientHandler, cancellationToken, "target", "client");
                
                // Wait for either direction to complete (or error)
                await Task.WhenAny(clientToTarget, targetToClient).ConfigureAwait(false);
                
                // If one direction has completed/errored, cancel the token to stop the other direction
                _internalCts.Cancel();
                
                // Wait for both directions to complete
                await Task.WhenAll(clientToTarget, targetToClient).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                if (ex is OperationCanceledException && cancellationToken.IsCancellationRequested)
                {
                    _logger.Log("Connection handling cancelled");
                }
                else
                {
                    _logger.LogError("Error handling client connection", ex);
                }
            }
            finally
            {
                // Clean up resources
                targetStream?.Dispose();
                targetTcpClient?.Dispose();
                clientStream.Dispose();
                client.Dispose();
                
                _logger.Log("Connection closed");
            }
        }

        /// <summary>
        /// Proxies data between two streams
        /// </summary>
        private async Task ProxyDataAsync(
            string clientId,
            Stream source,
            Stream destination,
            DataProcessor? dataProcessor,
            CancellationToken cancellationToken,
            string sourceName,
            string destName)
        {
            const int TlsRecordHeaderSize = 5;  // TLS record header size
            const int MaxTlsRecordSize = 16384 + TlsRecordHeaderSize;  // Maximum TLS record size plus header
            byte[] buffer = new byte[MaxTlsRecordSize];
            
            try
            {
                _logger.Log($"Starting data transfer from {sourceName} to {destName}");
                
                while (!cancellationToken.IsCancellationRequested)
                {
                    int bytesRead;
                    try
                    {
                        bytesRead = await source.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                    }
                    catch (IOException ex) when (ex.InnerException is ObjectDisposedException)
                    {
                        _logger.Log($"Stream from {sourceName} was closed");
                        break;
                    }
                    
                    if (bytesRead == 0)
                    {
                        _logger.Log($"End of stream from {sourceName}");
                        break;
                    }
                    
                    byte[] data = new byte[bytesRead];
                    Array.Copy(buffer, data, bytesRead);
                    
                    // Process data if processor is available
                    bool forwardData = true;
                    if (dataProcessor != null)
                    {
                        (data, forwardData) = dataProcessor(clientId, data);
                    }
                    
                    // Forward data if not intercepted
                    if (forwardData && data.Length > 0)
                    {
                        try
                        {
                            await destination.WriteAsync(data, 0, data.Length, cancellationToken);
                            await destination.FlushAsync(cancellationToken);
                        }
                        catch (IOException ex) when (ex.InnerException is ObjectDisposedException)
                        {
                            _logger.Log($"Stream to {destName} was closed");
                            break;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                if (ex is OperationCanceledException && cancellationToken.IsCancellationRequested)
                {
                    _logger.Log($"Data transfer from {sourceName} to {destName} cancelled");
                }
                else
                {
                    _logger.LogError($"Error proxying data from {sourceName} to {destName}", ex);
                    throw;
                }
            }
        }

        /// <summary>
        /// Starts the proxy in standalone mode without forwarding to a target
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Task representing the asynchronous operation</returns>
        public async Task StartStandaloneAsync(CancellationToken cancellationToken)
        {
            if (ClientToServerHandler == null)
            {
                throw new InvalidOperationException("ClientToServerHandler must be set before starting in standalone mode");
            }
            
            _standaloneMode = true;
            
            try
            {
                // Set up client-side TLS if enabled
                SetupClientTls();
                
                // Parse listener address
                string[] parts = _config.ListenerAddress.Split(':');
                if (parts.Length != 2 || !int.TryParse(parts[1], out int port))
                {
                    throw new ArgumentException($"Invalid listener address: {_config.ListenerAddress}");
                }
                
                // Create and start listener
                _listener = new TcpListener(IPAddress.Parse(parts[0]), port);
                _listener.Start();
                
                _logger.Log($"Standalone proxy listening on {_config.ListenerAddress}");
                
                // Set up a linked token source to handle both external and internal cancellation
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
                    cancellationToken, _internalCts.Token);
                
                while (!linkedCts.Token.IsCancellationRequested)
                {
                    try
                    {
                        // Accept client connection
                        var client = await _listener.AcceptTcpClientAsync().ConfigureAwait(false);
                        client.NoDelay = true; // Disable Nagle's algorithm for better performance
                        
                        var clientEndPoint = (IPEndPoint)client.Client.RemoteEndPoint!;
                        string clientId = $"{clientEndPoint.Address}:{clientEndPoint.Port}";
                        _logger.Log($"Accepted connection from {clientId}");
                        
                        // Start processing client connection in a background task
                        var task = HandleStandaloneClientAsync(clientId, client, linkedCts.Token);
                        
                        lock (_tasksLock)
                        {
                            _activeTasks.Add(task);
                        }
                        
                        // Clean up completed tasks to avoid memory leak
                        CleanupCompletedTasks();
                    }
                    catch (OperationCanceledException) when (linkedCts.Token.IsCancellationRequested)
                    {
                        // Normal cancellation
                        break;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError("Error accepting client connection", ex);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("Fatal error in standalone proxy", ex);
                throw;
            }
            finally
            {
                // Stop the listener
                _listener?.Stop();
                _logger.Log("Standalone proxy stopped");
                
                // Wait for all active tasks to complete
                await WaitForActiveTasksAsync().ConfigureAwait(false);
                
                // Clear active clients
                lock (_clientsLock)
                {
                    _activeClients.Clear();
                }
            }
        }
        
        /// <summary>
        /// Handles a client connection in standalone mode
        /// </summary>
        private async Task HandleStandaloneClientAsync(string clientId, TcpClient client, CancellationToken cancellationToken)
        {
            Stream clientStream = client.GetStream();
            
            try
            {
                // Set up client TLS if enabled
                if (_config.ClientTls)
                {
                    _logger.Log($"Setting up TLS for client {clientId}");
                    
                    SslStream sslStream = new SslStream(
                        clientStream,
                        false,
                        _config.ClientCertValidationCallback);
                    
                    // Server authentication mode
                    SslServerAuthenticationOptions options = new SslServerAuthenticationOptions
                    {
                        ServerCertificate = _config.ServerCertificate,
                        ClientCertificateRequired = _config.ClientAuth,
                        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
                    };
                    
                    await sslStream.AuthenticateAsServerAsync(options, cancellationToken).ConfigureAwait(false);
                    
                    _logger.Log($"TLS handshake completed for client {clientId} with cipher: {sslStream.SslProtocol}");
                    clientStream = sslStream;
                }
                
                // Store the client connection for later use
                var clientConnection = new ClientConnection(clientId, client, clientStream);
                lock (_clientsLock)
                {
                    _activeClients[clientId] = clientConnection;
                }
                
                _logger.Log($"Client {clientId} registered for standalone mode");
                
                // Start processing incoming data
                const int TlsRecordHeaderSize = 5;  // TLS record header size
                const int MaxTlsRecordSize = 16384 + TlsRecordHeaderSize;  // Maximum TLS record size plus header
                byte[] buffer = new byte[MaxTlsRecordSize];
                
                while (!cancellationToken.IsCancellationRequested)
                {
                    int bytesRead;
                    try
                    {
                        bytesRead = await clientStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                    }
                    catch (IOException ex) when (ex.InnerException is ObjectDisposedException)
                    {
                        _logger.Log($"Stream from client {clientId} was closed");
                        break;
                    }
                    
                    if (bytesRead == 0)
                    {
                        _logger.Log($"End of stream from client {clientId}");
                        break;
                    }
                    
                    byte[] data = new byte[bytesRead];
                    Array.Copy(buffer, data, bytesRead);
                    
                    _logger.Log($"Received {bytesRead} bytes from client {clientId}");
                    
                    // Process the data using the ClientToServerHandler
                    if (ClientToServerHandler != null)
                    {
                        var (processedData, forward) = ClientToServerHandler(clientId, data);
                        
                        // If the handler indicates to forward the data, then we send it back to the same client
                        // This maintains the same behavior as the original StandaloneDataHandler
                        if (forward && processedData.Length > 0)
                        {
                            await SendToClientAsync(clientId, processedData, cancellationToken);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                if (ex is OperationCanceledException && cancellationToken.IsCancellationRequested)
                {
                    _logger.Log($"Connection handling for client {clientId} cancelled");
                }
                else
                {
                    _logger.LogError($"Error handling client {clientId} connection", ex);
                }
            }
            finally
            {
                // Remove client from active clients
                lock (_clientsLock)
                {
                    _activeClients.Remove(clientId);
                }
                
                // Clean up resources
                clientStream.Dispose();
                client.Dispose();
                
                _logger.Log($"Connection with client {clientId} closed");
            }
        }
        
        /// <summary>
        /// Sends data to a specific client in standalone mode
        /// </summary>
        /// <param name="clientId">ID of the client to send data to</param>
        /// <param name="data">Data to send</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>True if the data was sent successfully, false if the client is not found</returns>
        public async Task<bool> SendToClientAsync(string clientId, byte[] data, CancellationToken cancellationToken = default)
        {
            if (!_standaloneMode)
            {
                throw new InvalidOperationException("SendToClientAsync can only be used in standalone mode");
            }
            
            ClientConnection? clientConnection;
            lock (_clientsLock)
            {
                if (!_activeClients.TryGetValue(clientId, out clientConnection))
                {
                    _logger.Log($"Client {clientId} not found for sending data");
                    return false;
                }
            }
            
            try
            {
                await clientConnection.Stream.WriteAsync(data, 0, data.Length, cancellationToken);
                await clientConnection.Stream.FlushAsync(cancellationToken);
                
                _logger.Log($"Sent {data.Length} bytes to client {clientId}");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error sending data to client {clientId}", ex);
                return false;
            }
        }
        
        /// <summary>
        /// Broadcasts data to all connected clients in standalone mode
        /// </summary>
        /// <param name="data">Data to broadcast</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Number of clients the data was successfully sent to</returns>
        public async Task<int> BroadcastAsync(byte[] data, CancellationToken cancellationToken = default)
        {
            if (!_standaloneMode)
            {
                throw new InvalidOperationException("BroadcastAsync can only be used in standalone mode");
            }
            
            List<ClientConnection> clients;
            lock (_clientsLock)
            {
                clients = new List<ClientConnection>(_activeClients.Values);
            }
            
            int successCount = 0;
            
            foreach (var client in clients)
            {
                try
                {
                    await client.Stream.WriteAsync(data, 0, data.Length, cancellationToken);
                    await client.Stream.FlushAsync(cancellationToken);
                    successCount++;
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Error broadcasting to client {client.Id}", ex);
                }
            }
            
            _logger.Log($"Broadcasted {data.Length} bytes to {successCount} clients");
            return successCount;
        }
        
        /// <summary>
        /// Gets a list of currently connected client IDs in standalone mode
        /// </summary>
        /// <returns>List of client IDs</returns>
        public List<string> GetConnectedClients()
        {
            if (!_standaloneMode)
            {
                throw new InvalidOperationException("GetConnectedClients can only be used in standalone mode");
            }
            
            lock (_clientsLock)
            {
                return new List<string>(_activeClients.Keys);
            }
        }
        
        /// <summary>
        /// Disconnects a specific client in standalone mode
        /// </summary>
        /// <param name="clientId">ID of the client to disconnect</param>
        /// <returns>True if the client was disconnected, false if the client was not found</returns>
        public bool DisconnectClient(string clientId)
        {
            if (!_standaloneMode)
            {
                throw new InvalidOperationException("DisconnectClient can only be used in standalone mode");
            }
            
            ClientConnection? clientConnection;
            lock (_clientsLock)
            {
                if (!_activeClients.TryGetValue(clientId, out clientConnection))
                {
                    return false;
                }
            }
            
            try
            {
                clientConnection.Client.Close();
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error disconnecting client {clientId}", ex);
                return false;
            }
        }

        /// <summary>
        /// Stops the proxy
        /// </summary>
        public void Stop()
        {
            _logger.Log("Stopping proxy");
            _internalCts.Cancel();
            _listener?.Stop();
        }

        /// <summary>
        /// Sends a custom response to the client
        /// </summary>
        public async Task SendCustomResponseAsync(byte[] data, Stream clientStream, CancellationToken cancellationToken)
        {
            try
            {
                await clientStream.WriteAsync(data, 0, data.Length, cancellationToken).ConfigureAwait(false);
                await clientStream.FlushAsync(cancellationToken).ConfigureAwait(false);
                
                _logger.Log($"Sent custom response: {data.Length} bytes");
            }
            catch (Exception ex)
            {
                _logger.LogError("Error sending custom response", ex);
                throw;
            }
        }

        /// <summary>
        /// Sets the server certificate directly for testing purposes
        /// </summary>
        /// <param name="certificate">Server certificate</param>
        public void SetServerCertificateForTesting(X509Certificate2 certificate)
        {
            _config.ServerCertificate = certificate;
        }
        
        /// <summary>
        /// Sets the client certificate directly for testing purposes
        /// </summary>
        /// <param name="certificate">Client certificate</param>
        public void SetClientCertificateForTesting(X509Certificate2 certificate)
        {
            _config.ClientCertificate = certificate;
        }
        
        /// <summary>
        /// Sets the CA certificate directly for testing purposes
        /// </summary>
        /// <param name="certificate">CA certificate</param>
        public void SetCACertificateForTesting(X509Certificate2 certificate)
        {
            _config.CACertificate = certificate;
        }

        /// <summary>
        /// Class to track client connections in standalone mode
        /// </summary>
        private class ClientConnection
        {
            public string Id { get; }
            public TcpClient Client { get; }
            public Stream Stream { get; }
            
            public ClientConnection(string id, TcpClient client, Stream stream)
            {
                Id = id;
                Client = client;
                Stream = stream;
            }
        }
    }
} 