using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CsProxyTools.Clients;
using CsProxyTools.Helpers;
using CsProxyTools.Interfaces;
using CsProxyTools.Servers;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Net.Security;
using System.Security.Authentication;
using Microsoft.Extensions.Logging.Console;

using Serilog;
using Serilog.Events;
using Serilog.Formatting.Display;
using TcpClient = CsProxyTools.Clients.TcpClient;

// Ensure logs directory exists
Directory.CreateDirectory("logs");

// Configure Serilog first - create a logger that writes to both console and file
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    // Console sink with custom template that removes the category/source prefix
    .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}")
    // File sink with a separate file per day, without message truncation
    .WriteTo.File(
        path: Path.Combine("logs", "proxy-log-.txt"),
        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception}",
        rollingInterval: RollingInterval.Day,
        fileSizeLimitBytes: 100 * 1024 * 1024, // 100MB size limit
        retainedFileCountLimit: 14, // Keep 14 days of logs
        shared: true, // Allow multiple processes to write to the same file
        flushToDiskInterval: TimeSpan.FromSeconds(1)) // Ensure logs are written to disk frequently
    .CreateLogger();

// Configure the Microsoft.Extensions.Logging factory to use Serilog
var loggerFactory = LoggerFactory.Create(builder =>
{
    builder.AddSerilog(dispose: true); // Use Serilog with its templates
    builder.SetMinimumLevel(LogLevel.Information);
});

// Create loggers for each component
var tcpServerLogger = loggerFactory.CreateLogger<TcpServer>();
var tcpClientLogger = loggerFactory.CreateLogger<TcpClient>();
var tlsServerLogger = loggerFactory.CreateLogger<TlsServer>();
var tlsClientLogger = loggerFactory.CreateLogger<TlsClient>();
var programLogger = loggerFactory.CreateLogger("Proxy"); // Custom name instead of type name

// Log application startup
programLogger.LogInformation("Application starting...");

// Configuration
var tcpServerPort = 5000;
var tlsServerPort = 5001;
var targetHost = "www.google.com";
var targetTcpPort = 80;
var targetTlsPort = 443;

// Certificate configuration
var certPath = "cert.pfx";
var certPassword = "password";

// Create certificate or load existing one
X509Certificate2 serverCertificate;

// Try to load server certificate from store first
programLogger.LogInformation("Attempting to load server certificate from Windows store...");
serverCertificate = await LoadCertificateFromStore("CN=localhost", StoreName.My, StoreLocation.LocalMachine);

if (serverCertificate == null)
{
    programLogger.LogWarning("Certificate not found in Windows store, checking for file...");
    if (File.Exists(certPath))
    {
        programLogger.LogInformation("Loading certificate from file {CertPath}", certPath);
        serverCertificate = new X509Certificate2(certPath, certPassword);
    }
    else
    {
        programLogger.LogInformation("Creating self-signed certificate...");
        serverCertificate = CreateSelfSignedCertificate();
        var certBytes = serverCertificate.Export(X509ContentType.Pkcs12, certPassword);
        File.WriteAllBytes(certPath, certBytes);
        programLogger.LogInformation("Self-signed certificate created and saved to {CertPath}", certPath);
    }
}
else
{
    programLogger.LogInformation("Successfully loaded certificate from Windows store: {Subject}, Thumbprint: {Thumbprint}", 
        serverCertificate.Subject, serverCertificate.Thumbprint);
}

// Attempt to create a client certificate for client auth demo
X509Certificate2? clientCertificate = null;

// Try to load client certificate from store first
programLogger.LogInformation("Attempting to load client certificate from Windows store...");
clientCertificate = await LoadCertificateFromStore("CN=localhost", StoreName.My, StoreLocation.LocalMachine);

if (clientCertificate == null)
{
    programLogger.LogInformation("Creating client certificate for demonstration...");
    try
    {
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest(
            "CN=ClientDemo", 
            rsa, 
            HashAlgorithmName.SHA256, 
            RSASignaturePadding.Pkcs1);
            
        // Add basic constraints
        certReq.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, true));
            
        // Add key usage
        certReq.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                true));
                
        // Add enhanced key usage for client authentication
        certReq.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, // Client Authentication
                true));
                
        // Create certificate that's valid for 1 year
        clientCertificate = certReq.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1));
                
        programLogger.LogInformation("Created self-signed client certificate with thumbprint: {Thumbprint}", 
            clientCertificate.Thumbprint);
    }
    catch (Exception ex)
    {
        programLogger.LogError(ex, "Failed to create client certificate");
        // Continue without client certificate if we can't create one
    }
}

// Create a collection of trusted client certificates
var trustedClientCerts = new X509Certificate2Collection();
if (clientCertificate != null)
{
    trustedClientCerts.Add(clientCertificate);
    programLogger.LogInformation("Added client certificate to trusted certificates: {Thumbprint}", 
        clientCertificate.Thumbprint);
}

// Create TCP server
var tcpServer = new TcpServer(tcpServerLogger, "127.0.0.1", tcpServerPort);

// Create TLS server with the certificate
var tlsServer = new TlsServer(tlsServerLogger, "127.0.0.1", tlsServerPort, serverCertificate);

// Create TLS server with client certificate requirement on a different port
var tlsServerWithClientAuth = new TlsServer(
    tlsServerLogger, 
    "127.0.0.1", 
    tlsServerPort + 1, 
    serverCertificate, 
    requireClientCert: true, 
    clientCertificates: trustedClientCerts,
    clientCertValidator: (cert, chain, errors) => 
    {
        programLogger.LogInformation("Validating client certificate: {Subject}, Thumbprint: {Thumbprint}", 
            cert.Subject, cert.Thumbprint);
        return errors == SslPolicyErrors.None || 
            (trustedClientCerts.Count > 0 && 
            trustedClientCerts.Cast<X509Certificate2>().Any(c => c.Thumbprint == cert.Thumbprint));
    });

// Create target clients
var tcpClient = new TcpClient(tcpClientLogger, targetHost, targetTcpPort);
var tlsClient = new TlsClient(tlsClientLogger, targetHost, targetTlsPort, validateCertificate: false);
var tlsClientWithCert = clientCertificate != null 
    ? new TlsClient(tlsClientLogger, targetHost, tlsServerPort + 1, validateCertificate: false, clientCertificate: clientCertificate)
    : new TlsClient(tlsClientLogger, targetHost, tlsServerPort + 1, validateCertificate: false);

// Dictionary to store active proxy connections
var tcpProxyConnections = new Dictionary<string, ProxyConnection>();
var tlsProxyConnections = new Dictionary<string, ProxyConnection>();
var tlsClientAuthProxyConnections = new Dictionary<string, ProxyConnection>();

// Setup TCP server event handlers
tcpServer.ClientConnected += (sender, args) =>
{
    programLogger.LogInformation("TCP Client connected: {ClientId}", args.ConnectionId);
};

tcpServer.ClientDisconnected += async (sender, args) =>
{
    programLogger.LogInformation("TCP Client disconnected: {ClientId}", args.ConnectionId);
    ProxyConnection? connection = null;
    
    lock (tcpProxyConnections)
    {
        if (tcpProxyConnections.TryGetValue(args.ConnectionId, out connection))
        {
            tcpProxyConnections.Remove(args.ConnectionId);
        }
    }
    
    if (connection != null)
    {
        try
        {
            await connection.DisposeAsync();
        }
        catch (Exception ex)
        {
            programLogger.LogError(ex, "Error disposing TCP proxy connection for client {ClientId}", args.ConnectionId);
        }
    }
};

tcpServer.DataReceived += async (sender, args) =>
{
    var txt = Encoding.UTF8.GetString(args.Data.ToArray());
    var hex = BitConverter.ToString(args.Data.ToArray()).Replace("-", "");
    programLogger.LogDebug("TCP Received from client: Text=\"{Txt}\" Hex={Hex}", txt, hex);
};

// Setup TLS server event handlers
tlsServer.ClientConnected += (sender, args) =>
{
    programLogger.LogInformation("TLS Client connected: {ClientId}", args.ConnectionId);
};

tlsServer.ClientDisconnected += async (sender, args) =>
{
    programLogger.LogInformation("TLS Client disconnected: {ClientId}", args.ConnectionId);
    ProxyConnection? connection = null;
    
    lock (tlsProxyConnections)
    {
        if (tlsProxyConnections.TryGetValue(args.ConnectionId, out connection))
        {
            tlsProxyConnections.Remove(args.ConnectionId);
        }
    }
    
    if (connection != null)
    {
        try
        {
            await connection.DisposeAsync();
        }
        catch (Exception ex)
        {
            programLogger.LogError(ex, "Error disposing TLS proxy connection for client {ClientId}", args.ConnectionId);
        }
    }
};

tlsServer.DataReceived += async (sender, args) =>
{
    var txt = Encoding.UTF8.GetString(args.Data.ToArray());
    var hex = BitConverter.ToString(args.Data.ToArray()).Replace("-", "");
    programLogger.LogDebug("TLS Received from client: Text=\"{Txt}\" Hex={Hex}", txt, hex);
};

// Setup client auth TLS server event handlers
tlsServerWithClientAuth.ClientConnected += (sender, args) =>
{
    programLogger.LogInformation("Client Auth TLS Client connected: {ClientId}", args.ConnectionId);
};

tlsServerWithClientAuth.ClientDisconnected += async (sender, args) =>
{
    programLogger.LogInformation("Client Auth TLS Client disconnected: {ClientId}", args.ConnectionId);
    ProxyConnection? connection = null;
    
    lock (tlsClientAuthProxyConnections)
    {
        if (tlsClientAuthProxyConnections.TryGetValue(args.ConnectionId, out connection))
        {
            tlsClientAuthProxyConnections.Remove(args.ConnectionId);
        }
    }
    
    if (connection != null)
    {
        try
        {
            await connection.DisposeAsync();
        }
        catch (Exception ex)
        {
            programLogger.LogError(ex, "Error disposing TLS client auth proxy connection for client {ClientId}", args.ConnectionId);
        }
    }
};

tlsServerWithClientAuth.DataReceived += async (sender, args) =>
{
    var txt = Encoding.UTF8.GetString(args.Data.ToArray());
    var hex = BitConverter.ToString(args.Data.ToArray()).Replace("-", "");
    programLogger.LogDebug("Client Auth TLS Received from client: Text=\"{Txt}\" Hex={Hex}", txt, hex);
};

// Setup TCP client event handlers
tcpClient.Connected += (sender, args) =>
{
    programLogger.LogInformation("TCP Connected to target server");
};

tcpClient.Disconnected += (sender, args) =>
{
    programLogger.LogInformation("TCP Disconnected from target server");
};

tcpClient.DataReceived += async (sender, args) =>
{
    var txt = Encoding.UTF8.GetString(args.Data.ToArray());
    var hex = BitConverter.ToString(args.Data.ToArray()).Replace("-", "");
    programLogger.LogDebug("TCP Received from target: Text=\"{Txt}\" Hex={Hex}", txt, hex);
};

// Setup TLS client event handlers
tlsClient.Connected += (sender, args) =>
{
    programLogger.LogInformation("TLS Connected to target server");
};

tlsClient.Disconnected += (sender, args) =>
{
    programLogger.LogInformation("TLS Disconnected from target server");
};

tlsClient.DataReceived += async (sender, args) =>
{
    var txt = Encoding.UTF8.GetString(args.Data.ToArray());
    var hex = BitConverter.ToString(args.Data.ToArray()).Replace("-", "");
    programLogger.LogDebug("TLS Received from target: Text=\"{Txt}\" Hex={Hex}", txt, hex);
};

// Setup client auth TLS client event handlers
tlsClientWithCert.Connected += (sender, args) =>
{
    programLogger.LogInformation("Client Auth TLS Connected to target server");
};

tlsClientWithCert.Disconnected += (sender, args) =>
{
    programLogger.LogInformation("Client Auth TLS Disconnected from target server");
};

tlsClientWithCert.DataReceived += async (sender, args) =>
{
    var txt = Encoding.UTF8.GetString(args.Data.ToArray());
    var hex = BitConverter.ToString(args.Data.ToArray()).Replace("-", "");
    programLogger.LogDebug("Client Auth TLS Received from target: Text=\"{Txt}\" Hex={Hex}", txt, hex);
};

// Setup proxy connections
// For TCP server
tcpServer.ClientConnected += async (sender, args) =>
{
    try
    {
        var proxyConnection = new ProxyConnection(
            loggerFactory.CreateLogger<ProxyConnection>(),
            args.ConnectionId,
            sender as IConnection,
            // Create a new target client for each connection to avoid sharing
            new TcpClient(tcpClientLogger, targetHost, targetTcpPort));
            
        lock (tcpProxyConnections)
        {
            tcpProxyConnections[args.ConnectionId] = proxyConnection;
        }
        
        // Start the proxy connection on the same thread to avoid concurrent access
        await proxyConnection.Start();
    }
    catch (Exception ex)
    {
        programLogger.LogError(ex, "Error setting up TCP proxy connection for client {ClientId}", args.ConnectionId);
    }
};

// For TLS server
tlsServer.ClientConnected += async (sender, args) =>
{
    try
    {
        var proxyConnection = new ProxyConnection(
            loggerFactory.CreateLogger<ProxyConnection>(),
            args.ConnectionId,
            sender as IConnection,
            // Create a new target client for each connection to avoid sharing
            new TlsClient(tlsClientLogger, targetHost, targetTlsPort, validateCertificate: false));
            
        lock (tlsProxyConnections)
        {
            tlsProxyConnections[args.ConnectionId] = proxyConnection;
        }
        
        // Start the proxy connection on the same thread to avoid concurrent access
        await proxyConnection.Start();
    }
    catch (Exception ex)
    {
        programLogger.LogError(ex, "Error setting up TLS proxy connection for client {ClientId}", args.ConnectionId);
    }
};

// For client auth TLS server
tlsServerWithClientAuth.ClientConnected += async (sender, args) =>
{
    try
    {
        // Use proper client certificate if available
        var targetClient = clientCertificate != null 
            ? new TlsClient(tlsClientLogger, targetHost, tlsServerPort + 1, validateCertificate: false, clientCertificate: clientCertificate)
            : new TlsClient(tlsClientLogger, targetHost, tlsServerPort + 1, validateCertificate: false);
            
        var proxyConnection = new ProxyConnection(
            loggerFactory.CreateLogger<ProxyConnection>(),
            args.ConnectionId,
            sender as IConnection,
            targetClient);
            
        lock (tlsClientAuthProxyConnections)
        {
            tlsClientAuthProxyConnections[args.ConnectionId] = proxyConnection;
        }
        
        // Start the proxy connection on the same thread to avoid concurrent access
        await proxyConnection.Start();
    }
    catch (Exception ex)
    {
        programLogger.LogError(ex, "Error setting up TLS client auth proxy connection for client {ClientId}", args.ConnectionId);
    }
};

// Start servers
programLogger.LogInformation("Starting TCP server on port {Port}", tcpServerPort);
await tcpServer.StartAsync();
programLogger.LogInformation("TCP server started on port {Port}", tcpServerPort);

programLogger.LogInformation("Starting TLS server on port {Port}", tlsServerPort);
await tlsServer.StartAsync();
programLogger.LogInformation("TLS server started on port {Port}", tlsServerPort);

programLogger.LogInformation("Starting Client Auth TLS server on port {Port}", tlsServerPort + 1);
await tlsServerWithClientAuth.StartAsync();
programLogger.LogInformation("Client Auth TLS server started on port {Port}", tlsServerPort + 1);

// Wait for user to exit
programLogger.LogInformation("Proxy servers started. Press Enter to exit...");
Console.ReadLine();

// Stop servers
programLogger.LogInformation("Stopping servers...");

await tcpServer.StopAsync();
programLogger.LogInformation("TCP server stopped");

await tlsServer.StopAsync();
programLogger.LogInformation("TLS server stopped");

await tlsServerWithClientAuth.StopAsync();
programLogger.LogInformation("Client Auth TLS server stopped");

// Clean up all proxy connections
programLogger.LogInformation("Cleaning up proxy connections...");

// Safely clean up TCP proxy connections
try
{
    List<ProxyConnection> connections;
    lock (tcpProxyConnections)
    {
        connections = tcpProxyConnections.Values.ToList();
        tcpProxyConnections.Clear();
    }
    
    foreach (var connection in connections)
    {
        try
        {
            await connection.DisposeAsync();
        }
        catch (Exception ex)
        {
            programLogger.LogError(ex, "Error disposing TCP proxy connection");
        }
    }
}
catch (Exception ex)
{
    programLogger.LogError(ex, "Error cleaning up TCP proxy connections");
}

// Safely clean up TLS proxy connections
try
{
    List<ProxyConnection> connections;
    lock (tlsProxyConnections)
    {
        connections = tlsProxyConnections.Values.ToList();
        tlsProxyConnections.Clear();
    }
    
    foreach (var connection in connections)
    {
        try
        {
            await connection.DisposeAsync();
        }
        catch (Exception ex)
        {
            programLogger.LogError(ex, "Error disposing TLS proxy connection");
        }
    }
}
catch (Exception ex)
{
    programLogger.LogError(ex, "Error cleaning up TLS proxy connections");
}

// Safely clean up TLS client auth proxy connections
try
{
    List<ProxyConnection> connections;
    lock (tlsClientAuthProxyConnections)
    {
        connections = tlsClientAuthProxyConnections.Values.ToList();
        tlsClientAuthProxyConnections.Clear();
    }
    
    foreach (var connection in connections)
    {
        try
        {
            await connection.DisposeAsync();
        }
        catch (Exception ex)
        {
            programLogger.LogError(ex, "Error disposing TLS client auth proxy connection");
        }
    }
}
catch (Exception ex)
{
    programLogger.LogError(ex, "Error cleaning up TLS client auth proxy connections");
}

programLogger.LogInformation("Application stopped.");

// Helper function to create a self-signed certificate
X509Certificate2 CreateSelfSignedCertificate()
{
    var subjectName = "localhost";
    
    var rsa = RSA.Create(2048);
    var request = new CertificateRequest($"CN={subjectName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    
    request.CertificateExtensions.Add(
        new X509BasicConstraintsExtension(false, false, 0, true));
    
    request.CertificateExtensions.Add(
        new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
            false));
    
    request.CertificateExtensions.Add(
        new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, // Server Authentication
            true));
    
    // Add Subject Alternative Name with DNS name
    var sanBuilder = new SubjectAlternativeNameBuilder();
    sanBuilder.AddDnsName(subjectName);
    request.CertificateExtensions.Add(sanBuilder.Build());
    
    var expireAt = DateTimeOffset.Now.AddYears(1);
    var cert = request.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), expireAt);
    // Convert to exportable certificate with private key
    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
    {
        var certWithKey = new X509Certificate2(cert.Export(X509ContentType.Cert));
        var cngKey = CngKey.Import(rsa.ExportRSAPrivateKey(), CngKeyBlobFormat.Pkcs8PrivateBlob);
        
        return new X509Certificate2(cert.Export(X509ContentType.Pkcs12, "password"));
    }
    
    return new X509Certificate2(cert.Export(X509ContentType.Pkcs12, "password"));
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

    if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
    {
        programLogger.LogWarning("Windows certificate store is only available on Windows platforms");
        return null;
    }

    programLogger.LogInformation("Loading certificate from Windows store with subject: {SubjectName}, store: {StoreName}, location: {StoreLocation}", 
        subjectName, storeName, storeLocation);
    
    try
    {
        using (var store = new X509Store(storeName, storeLocation))
        {
            store.Open(OpenFlags.ReadOnly);
            
            var certificates = store.Certificates.Find(
                X509FindType.FindBySubjectDistinguishedName, subjectName, false);
            
            if (certificates.Count == 0)
            {
                // Try finding by subject name if distinguished name fails
                certificates = store.Certificates.Find(
                    X509FindType.FindBySubjectName, subjectName.Replace("CN=", ""), false);
            }
            
            if (certificates.Count == 0)
            {
                programLogger.LogWarning("No certificate found with subject: {SubjectName} in store: {StoreName}, location: {StoreLocation}", 
                    subjectName, storeName, storeLocation);
                return null;
            }
            
            programLogger.LogInformation("Found {Count} certificates matching subject: {SubjectName}", 
                certificates.Count, subjectName);
            
            // Return the first certificate that has a private key (if available)
            foreach (var cert in certificates)
            {
                if (cert.HasPrivateKey)
                {
                    programLogger.LogInformation("Selected certificate with private key: {Thumbprint}", cert.Thumbprint);
                    return cert;
                }
            }
            
            // Fallback to first certificate if none has a private key
            if (certificates.Count > 0)
            {
                programLogger.LogWarning("No certificate with private key found, using first available: {Thumbprint}", 
                    certificates[0].Thumbprint);
                return certificates[0];
            }
            
            return null;
        }
    }
    catch (Exception ex)
    {
        programLogger.LogError(ex, "Failed to load certificate from Windows store");
        return null;
    }
}

// Define a class to run Main
public partial class Program { } 