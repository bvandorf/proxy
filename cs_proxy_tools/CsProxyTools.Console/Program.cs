using CsProxyTools.Clients;
using CsProxyTools.Servers;
using CsProxyTools.Interfaces;
using CsProxyTools.Helpers;
using Microsoft.Extensions.Logging;
using System.Text;
using System.Buffers;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;

var loggerFactory = LoggerFactory.Create(builder =>
{
    builder.AddConsole();
    builder.SetMinimumLevel(LogLevel.Information);
});

// Create specific loggers for each component
var tcpServerLogger = loggerFactory.CreateLogger<TcpServer>();
var tcpClientLogger = loggerFactory.CreateLogger<TcpClient>();
var tlsServerLogger = loggerFactory.CreateLogger<TlsServer>();
var tlsClientLogger = loggerFactory.CreateLogger<TlsClient>();
var programLogger = loggerFactory.CreateLogger<Program>();

// Configuration
var tcpServerPort = 5000;
var tlsServerPort = 5001;
var targetHost = "localhost";
var targetPort = 8080;

// Try to load certificate from store, fallback to file if not found
var certificate = await LoadCertificateFromStore("CN=localhost", StoreName.My, StoreLocation.LocalMachine);
if (certificate == null)
{
    programLogger.LogWarning("Failed to load certificate from store. Falling back to file.");
    var certificatePath = "certificate.pfx";
    var certificatePassword = "password";
    try
    {
        certificate = new X509Certificate2(certificatePath, certificatePassword);
    }
    catch (Exception ex)
    {
        programLogger.LogError(ex, "Failed to load certificate from file {Path}", certificatePath);
        throw new Exception("Failed to load certificate from both store and file");
    }
}

// Create TCP server
var tcpServer = new TcpServer(tcpServerLogger, "127.0.0.1", tcpServerPort);
var tcpClient = new TcpClient(tcpClientLogger, targetHost, targetPort);

// Create TLS server with the certificate
var tlsServer = new TlsServer(tlsServerLogger, "127.0.0.1", tlsServerPort, certificate);
var tlsClient = new TlsClient(tlsClientLogger, targetHost, targetPort, validateCertificate: false);

// Dictionary to store active proxy connections
var tcpProxyConnections = new Dictionary<string, ProxyConnection>();
var tlsProxyConnections = new Dictionary<string, ProxyConnection>();

// Handle TCP server events
tcpServer.ClientConnected += (sender, args) =>
{
    programLogger.LogInformation("TCP Client connected: {ClientId}", args.ConnectionId);
    _ = HandleTcpClientConnectionAsync(args.ConnectionId, tcpClient);
};

tcpServer.ClientDisconnected += (sender, args) =>
{
    programLogger.LogInformation("TCP Client disconnected: {ClientId}", args.ConnectionId);
    if (tcpProxyConnections.TryGetValue(args.ConnectionId, out var connection))
    {
        connection.DisposeAsync().ConfigureAwait(false);
        tcpProxyConnections.Remove(args.ConnectionId);
    }
};

tcpServer.DataReceived += async (sender, args) =>
{
    programLogger.LogInformation("TCP Received {Length} bytes from {ClientId}", args.Data.Length, args.ConnectionId);
    await tcpClient.WriteAsync(args.Data);
};

// Handle TLS server events
tlsServer.ClientConnected += (sender, args) =>
{
    programLogger.LogInformation("TLS Client connected: {ClientId}", args.ConnectionId);
    _ = HandleTlsClientConnectionAsync(args.ConnectionId, tlsClient);
};

tlsServer.ClientDisconnected += (sender, args) =>
{
    programLogger.LogInformation("TLS Client disconnected: {ClientId}", args.ConnectionId);
    if (tlsProxyConnections.TryGetValue(args.ConnectionId, out var connection))
    {
        connection.DisposeAsync().ConfigureAwait(false);
        tlsProxyConnections.Remove(args.ConnectionId);
    }
};

tlsServer.DataReceived += async (sender, args) =>
{
    programLogger.LogInformation("TLS Received {Length} bytes from {ClientId}", args.Data.Length, args.ConnectionId);
    var txt = Encoding.UTF8.GetString(args.Data.ToArray()); 
    var hex = BitConverter.ToString(args.Data.ToArray()).Replace("-", "");
    programLogger.LogInformation("TLS Received: {Txt}", txt);
    programLogger.LogInformation("TLS Received: {Hex}", hex);
    await tlsClient.WriteAsync(args.Data);
};

// Handle TCP client events
tcpClient.ConnectionStarted += (sender, args) =>
{
    programLogger.LogInformation("TCP Connected to target server");
};

tcpClient.ConnectionClosed += (sender, args) =>
{
    programLogger.LogInformation("TCP Disconnected from target server");
};

tcpClient.DataReceived += async (sender, args) =>
{
    programLogger.LogInformation("TCP Received {Length} bytes from target server", args.Data.Length);
    // Here you would need to implement logic to forward this data to the correct client
    var txt = Encoding.UTF8.GetString(args.Data.ToArray()); 
    var hex = BitConverter.ToString(args.Data.ToArray()).Replace("-", "");
    programLogger.LogInformation("TCP Received: {Txt}", txt);
    programLogger.LogInformation("TCP Received: {Hex}", hex);
    await tcpServer.WriteAsync(args.Data);
};

// Handle TLS client events
tlsClient.ConnectionStarted += (sender, args) =>
{
    programLogger.LogInformation("TLS Connected to target server");
};

tlsClient.ConnectionClosed += (sender, args) =>
{
    programLogger.LogInformation("TLS Disconnected from target server");
};

tlsClient.DataReceived += async (sender, args) =>
{
    programLogger.LogInformation("TLS Received {Length} bytes from target server", args.Data.Length);
    // Here you would need to implement logic to forward this data to the correct client
    var txt = Encoding.UTF8.GetString(args.Data.ToArray()); 
    var hex = BitConverter.ToString(args.Data.ToArray()).Replace("-", "");
    programLogger.LogInformation("TLS Received: {Txt}", txt);
    programLogger.LogInformation("TLS Received: {Hex}", hex);
    await tlsServer.WriteAsync(args.Data);
};

// Start servers
programLogger.LogInformation("Starting TCP server on port {Port}", tcpServerPort);
await tcpServer.StartAsync();

programLogger.LogInformation("Starting TLS server on port {Port}", tlsServerPort);
await tlsServer.StartAsync();

programLogger.LogInformation("Proxy servers started. Press any key to stop...");
Console.ReadKey();

// Stop servers
programLogger.LogInformation("Stopping servers...");
await tcpServer.StopAsync();
await tlsServer.StopAsync();

// Clean up all proxy connections
foreach (var connection in tcpProxyConnections.Values.Concat(tlsProxyConnections.Values))
{
    await connection.DisposeAsync();
}

programLogger.LogInformation("Servers stopped.");

async Task HandleTcpClientConnectionAsync(string clientId, TcpClient client)
{
    try
    {
        await client.StartAsync();
        var proxyConnection = new ProxyConnection(client, tcpServer, programLogger, clientId);
        tcpProxyConnections[clientId] = proxyConnection;
    }
    catch (Exception ex)
    {
        programLogger.LogError(ex, "Error handling TCP client connection {ClientId}", clientId);
    }
}

async Task HandleTlsClientConnectionAsync(string clientId, TlsClient client)
{
    try
    {
        await client.StartAsync();
        var proxyConnection = new ProxyConnection(client, tlsServer, programLogger, clientId);
        tlsProxyConnections[clientId] = proxyConnection;
    }
    catch (Exception ex)
    {
        programLogger.LogError(ex, "Error handling TLS client connection {ClientId}", clientId);
    }
} 

/// <summary>
/// Loads a certificate from the Windows certificate store
/// </summary>
async Task<X509Certificate2?> LoadCertificateFromStore(string subjectName, StoreName storeName, StoreLocation storeLocation)
{
    if (string.IsNullOrEmpty(subjectName))
    {
        return null;
    }

    programLogger.LogInformation($"Loading certificate from Windows store with subject: {subjectName}, store: {storeName}, location: {storeLocation}");
    
    if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
    {
        programLogger.LogError("Windows certificate store is only supported on Windows");
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
                programLogger.LogError($"No certificate found with subject name: {subjectName} in store: {storeName}, location: {storeLocation}");
                return null;
            }
            
            programLogger.LogInformation($"Found {certificates.Count} certificates matching subject name: {subjectName}");
            
            // Return the first certificate that has a private key (if available)
            foreach (var cert in certificates)
            {
                if (cert.HasPrivateKey)
                {
                    programLogger.LogInformation($"Selected certificate with private key: {cert.Thumbprint}");
                    return cert;
                }
            }
            
            // Fallback to first certificate if none has a private key
            programLogger.LogInformation($"No certificate with private key found, using first available: {certificates[0].Thumbprint}");
            return certificates[0];
        }
    }
    catch (Exception ex)
    {
        programLogger.LogError("Failed to load certificate from Windows store", ex);
        return null;
    }
}