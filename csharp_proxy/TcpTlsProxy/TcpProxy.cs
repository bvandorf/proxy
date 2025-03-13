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
    public delegate (byte[] data, bool forward) DataProcessor(byte[] data);

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
                if (!string.IsNullOrEmpty(_config.ClientCertSubject))
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
                        RemoteCertificateValidationCallback = _config.ServerCertValidationCallback,
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
                    clientStream, targetStream, ClientToServerHandler, cancellationToken, "client", "target");
                
                Task targetToClient = ProxyDataAsync(
                    targetStream, clientStream, ServerToClientHandler, cancellationToken, "target", "client");
                
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
            Stream source, 
            Stream destination, 
            DataProcessor? dataProcessor, 
            CancellationToken cancellationToken,
            string sourceName,
            string destName)
        {
            byte[] buffer = new byte[8192];
            
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    // Read data from source
                    int bytesRead = await source.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
                    
                    if (bytesRead == 0)
                    {
                        // End of stream
                        break;
                    }
                    
                    byte[] data = new byte[bytesRead];
                    Array.Copy(buffer, data, bytesRead);
                    
                    // Process data if processor is available
                    bool forwardData = true;
                    if (dataProcessor != null)
                    {
                        (data, forwardData) = dataProcessor(data);
                    }
                    
                    // Forward data if not intercepted
                    if (forwardData && data.Length > 0)
                    {
                        await destination.WriteAsync(data, 0, data.Length, cancellationToken).ConfigureAwait(false);
                        await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
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
                }
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
    }
} 