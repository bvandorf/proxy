using CsProxyTools.Clients;
using CsProxyTools.Servers;
using CsProxyTools.Interfaces;
using CsProxyTools.Helpers;
using Microsoft.Extensions.Logging;
using System.Text;
using System.Buffers;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Net.Security;
using System.Security.Authentication;
using Microsoft.Extensions.Logging.Console;
using Serilog;
using Serilog.Events;
using Serilog.Formatting.Display;

// Ensure logs directory exists
Directory.CreateDirectory("logs");

// Configure Serilog first - create a logger that writes to both console and file
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    // Console sink with custom template that won't truncate any data
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
    // Add Serilog as the provider
    builder.AddSerilog(dispose: true);
    
    // Set minimum level
    builder.SetMinimumLevel(LogLevel.Information);
});

// Create specific loggers for each component
var tcpServerLogger = loggerFactory.CreateLogger<TcpServer>();
var tcpClientLogger = loggerFactory.CreateLogger<TcpClient>();
var tlsServerLogger = loggerFactory.CreateLogger<TlsServer>();
var tlsClientLogger = loggerFactory.CreateLogger<TlsClient>();
var programLogger = loggerFactory.CreateLogger<Program>();

// Log application startup
programLogger.LogInformation("Application starting...");

// Configuration
var tcpServerPort = 5000;
var tlsServerPort = 5001;
var targetHost = "localhost";
var targetTcpPort = 5002;
var targetTlsPort = 5003;

// Certificate configuration
var certPath = "cert.pfx";
var certPassword = "password";

// Create certificate or load existing one
X509Certificate2 serverCertificate;
if (!File.Exists(certPath))
{
    programLogger.LogInformation("Creating self-signed certificate...");
    serverCertificate = CreateSelfSignedCertificate();
    var certBytes = serverCertificate.Export(X509ContentType.Pkcs12, certPassword);
    File.WriteAllBytes(certPath, certBytes);
    programLogger.LogInformation("Self-signed certificate created and saved to {CertPath}", certPath);
}
else
{
    programLogger.LogInformation("Loading certificate from {CertPath}", certPath);
    serverCertificate = new X509Certificate2(certPath, certPassword);
}

// Create servers
var tcpServer = new TcpServer(tcpServerLogger, tcpServerPort);
var tlsServer = new TlsServer(tlsServerLogger, tlsServerPort, serverCertificate);

// Create clients
var tcpClient = new TcpClient(tcpClientLogger, targetHost, targetTcpPort);
var tlsClient = new TlsClient(tlsClientLogger, targetHost, targetTlsPort, 
    // Allow any certificate for testing
    (sender, certificate, chain, errors) => true);

// Setup TCP proxy connections
tcpServer.ConnectionAccepted += (sender, args) =>
{
    programLogger.LogInformation("TCP connection accepted from {ClientId}", args.ConnectionId);
    var proxyConnection = new ProxyConnection(loggerFactory.CreateLogger<ProxyConnection>(), args.ConnectionId, args.Connection, tcpClient);
    proxyConnection.Start();
};

// Setup TLS proxy connections  
tlsServer.ConnectionAccepted += (sender, args) =>
{
    programLogger.LogInformation("TLS connection accepted from {ClientId}", args.ConnectionId);
    var proxyConnection = new ProxyConnection(loggerFactory.CreateLogger<ProxyConnection>(), args.ConnectionId, args.Connection, tlsClient);
    proxyConnection.Start();
};

// Start servers
await tcpServer.StartAsync();
programLogger.LogInformation("TCP server started on port {Port}", tcpServerPort);

await tlsServer.StartAsync();
programLogger.LogInformation("TLS server started on port {Port}", tlsServerPort);

// Wait for user to exit
programLogger.LogInformation("Press Enter to exit...");
Console.ReadLine();

// Stop servers
await tcpServer.StopAsync();
programLogger.LogInformation("TCP server stopped");

await tlsServer.StopAsync();
programLogger.LogInformation("TLS server stopped");

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
    
    request.CertificateExtensions.Add(
        new X509SubjectAlternativeNameExtension(
            new string[] { subjectName }, false));
    
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

// Define a class to run Main
public partial class Program { }