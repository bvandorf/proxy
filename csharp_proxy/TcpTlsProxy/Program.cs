using System;
using System.Collections.Generic;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using TcpTlsProxy.Protocols;

namespace TcpTlsProxy
{
    class Program
    {
        static async Task<int> Main(string[] args)
        {
            // Setup root command
            var rootCommand = new RootCommand("TCP/TLS Proxy - A flexible TCP proxy with TLS support");

            // Add command-line options, matching the Go implementation but using Windows certificate store
            var portOption = new Option<int>(
                "--port",
                getDefaultValue: () => 8080,
                description: "Port to listen on for proxy connections");
            
            var requireClientCertOption = new Option<bool>(
                "--client-auth",
                getDefaultValue: () => false,
                description: "Require client certificate authentication (mutual TLS)");
            
            var insecureClientOption = new Option<bool>(
                "--insecure-client",
                getDefaultValue: () => false,
                description: "Accept any client certificate when client authentication is enabled");
            
            var caCertSubjectOption = new Option<string>(
                "--ca-cert-subject",
                getDefaultValue: () => "",
                description: "CA certificate subject name from Windows certificate store for verifying client certificates");
            
            var caCertStoreNameOption = new Option<StoreName>(
                "--ca-cert-store",
                getDefaultValue: () => StoreName.Root,
                description: "Windows certificate store name for CA certificate (e.g., Root, My, TrustedPeople)");
            
            var caCertStoreLocationOption = new Option<StoreLocation>(
                "--ca-cert-location",
                getDefaultValue: () => StoreLocation.CurrentUser,
                description: "Windows certificate store location for CA certificate (e.g., CurrentUser, LocalMachine)");
            
            var serverCertSubjectOption = new Option<string>(
                "--server-cert-subject",
                getDefaultValue: () => "",
                description: "Server certificate subject name from Windows certificate store for TLS connections");
            
            var serverCertStoreNameOption = new Option<StoreName>(
                "--server-cert-store",
                getDefaultValue: () => StoreName.My,
                description: "Windows certificate store name for server certificate (e.g., My, TrustedPeople)");
            
            var serverCertStoreLocationOption = new Option<StoreLocation>(
                "--server-cert-location",
                getDefaultValue: () => StoreLocation.CurrentUser,
                description: "Windows certificate store location for server certificate (e.g., CurrentUser, LocalMachine)");
            
            var targetUseTlsOption = new Option<bool>(
                "--target-tls",
                getDefaultValue: () => true,
                description: "Use TLS when connecting to target server (set to false for plain TCP targets)");
            
            var insecureSkipVerifyOption = new Option<bool>(
                "--insecure-target",
                getDefaultValue: () => true,
                description: "Skip verification of target server TLS certificates (set to false in production)");
            
            var targetHostOption = new Option<string>(
                "--target-host",
                getDefaultValue: () => "www.google.com",
                description: "Target hostname to connect to (with optional port, e.g., 'example.com:443')");
            
            var clientCertSubjectOption = new Option<string>(
                "--client-cert-subject",
                getDefaultValue: () => "",
                description: "Client certificate subject name from Windows certificate store for target server authentication");
            
            var clientCertStoreNameOption = new Option<StoreName>(
                "--client-cert-store",
                getDefaultValue: () => StoreName.My,
                description: "Windows certificate store name for client certificate (e.g., My, TrustedPeople)");
            
            var clientCertStoreLocationOption = new Option<StoreLocation>(
                "--client-cert-location",
                getDefaultValue: () => StoreLocation.CurrentUser,
                description: "Windows certificate store location for client certificate (e.g., CurrentUser, LocalMachine)");
            
            var useClientTlsOption = new Option<bool>(
                "--client-tls",
                getDefaultValue: () => false,
                description: "Require clients to use TLS when connecting to the proxy");
            
            var logFileOption = new Option<string>(
                "--log-file",
                getDefaultValue: () => "output.log",
                description: "File to write logs to (in addition to stdout)");
            
            var verboseOption = new Option<bool>(
                "--v",
                getDefaultValue: () => false,
                description: "Enable verbose logging to console");

            // Add all options to the root command
            rootCommand.AddOption(portOption);
            rootCommand.AddOption(requireClientCertOption);
            rootCommand.AddOption(insecureClientOption);
            rootCommand.AddOption(caCertSubjectOption);
            rootCommand.AddOption(caCertStoreNameOption);
            rootCommand.AddOption(caCertStoreLocationOption);
            rootCommand.AddOption(serverCertSubjectOption);
            rootCommand.AddOption(serverCertStoreNameOption);
            rootCommand.AddOption(serverCertStoreLocationOption);
            rootCommand.AddOption(targetUseTlsOption);
            rootCommand.AddOption(insecureSkipVerifyOption);
            rootCommand.AddOption(targetHostOption);
            rootCommand.AddOption(clientCertSubjectOption);
            rootCommand.AddOption(clientCertStoreNameOption);
            rootCommand.AddOption(clientCertStoreLocationOption);
            rootCommand.AddOption(useClientTlsOption);
            rootCommand.AddOption(logFileOption);
            rootCommand.AddOption(verboseOption);

            // Set up handler
            rootCommand.SetHandler(async (context) =>
            {
                // Get option values
                int port = context.ParseResult.GetValueForOption(portOption);
                bool requireClientCert = context.ParseResult.GetValueForOption(requireClientCertOption);
                bool insecureClient = context.ParseResult.GetValueForOption(insecureClientOption);
                string caCertSubject = context.ParseResult.GetValueForOption(caCertSubjectOption);
                StoreName caCertStoreName = context.ParseResult.GetValueForOption(caCertStoreNameOption);
                StoreLocation caCertStoreLocation = context.ParseResult.GetValueForOption(caCertStoreLocationOption);
                string serverCertSubject = context.ParseResult.GetValueForOption(serverCertSubjectOption);
                StoreName serverCertStoreName = context.ParseResult.GetValueForOption(serverCertStoreNameOption);
                StoreLocation serverCertStoreLocation = context.ParseResult.GetValueForOption(serverCertStoreLocationOption);
                bool targetUseTls = context.ParseResult.GetValueForOption(targetUseTlsOption);
                bool insecureSkipVerify = context.ParseResult.GetValueForOption(insecureSkipVerifyOption);
                string targetHost = context.ParseResult.GetValueForOption(targetHostOption);
                string clientCertSubject = context.ParseResult.GetValueForOption(clientCertSubjectOption);
                StoreName clientCertStoreName = context.ParseResult.GetValueForOption(clientCertStoreNameOption);
                StoreLocation clientCertStoreLocation = context.ParseResult.GetValueForOption(clientCertStoreLocationOption);
                bool useClientTls = context.ParseResult.GetValueForOption(useClientTlsOption);
                string logFile = context.ParseResult.GetValueForOption(logFileOption);
                bool verbose = context.ParseResult.GetValueForOption(verboseOption);

                // Setup logging
                var logger = new ProxyLogger(logFile);
                logger.Log($"Starting TCP/TLS Proxy on port {port}");

                // Check platform
                if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    logger.LogError("This proxy implementation requires Windows for certificate store access");
                    context.ExitCode = 1;
                    return;
                }

                // Determine target address
                string targetAddress = targetHost;
                if (!targetHost.Contains(":") && targetUseTls)
                {
                    targetAddress = $"{targetHost}:443"; // Default HTTPS port
                    logger.Log($"No port specified in target. Using default HTTPS port: {targetAddress}");
                }

                try
                {
                    // Create proxy configuration
                    var proxyConfig = new ProxyConfig
                    {
                        ListenerAddress = $"0.0.0.0:{port}",
                        TargetAddress = targetAddress,
                        ClientTls = useClientTls,
                        ServerCertSubject = serverCertSubject,
                        ServerCertStoreName = serverCertStoreName,
                        ServerCertStoreLocation = serverCertStoreLocation,
                        ClientAuth = requireClientCert,
                        CACertSubject = caCertSubject,
                        CACertStoreName = caCertStoreName,
                        CACertStoreLocation = caCertStoreLocation,
                        TargetTls = targetUseTls,
                        ClientCertSubject = clientCertSubject,
                        ClientCertStoreName = clientCertStoreName,
                        ClientCertStoreLocation = clientCertStoreLocation,
                        InsecureSkipVerify = insecureSkipVerify
                    };

                    // Create and start the proxy
                    var proxy = new TcpProxy(proxyConfig, logger);

                    // Set up data handlers for verbose logging
                    if (verbose || !string.IsNullOrEmpty(logFile))
                    {
                        proxy.ClientToServerHandler = (clientId, data) =>
                        {
                            logger.Log($"Client to server: {data.Length} bytes");
                            if (verbose)
                            {
                                // Use the DataLogger for comprehensive logging
                                DataLogger.LogData(logger, "Client to Server", data, clientId);
                            }
                            return (data, true);
                        };

                        proxy.ServerToClientHandler = (clientId, data) =>
                        {
                            logger.Log($"Server to client: {data.Length} bytes");
                            if (verbose)
                            {
                                // Use the DataLogger for comprehensive logging
                                DataLogger.LogData(logger, "Server to Client", data, clientId);
                            }
                            return (data, true);
                        };
                    }

                    logger.Log($"Proxy configured with: {port} -> {targetAddress}");
                    logger.Log($"Target TLS: {targetUseTls}, Client TLS: {useClientTls}");

                    // Start the proxy
                    await proxy.StartAsync(context.GetCancellationToken());
                }
                catch (Exception ex)
                {
                    logger.Log($"Fatal error: {ex.Message}");
                    logger.Log($"Stack trace: {ex.StackTrace}");
                    context.ExitCode = 1;
                }
            });

            // Parse the arguments and run the command
            return await rootCommand.InvokeAsync(args);
        }
    }
}
