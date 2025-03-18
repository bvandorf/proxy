using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TcpTlsProxy.Protocols;

namespace TcpTlsProxy.Examples
{
    /// <summary>
    /// Example showing the enhanced logging capabilities of the proxy
    /// </summary>
    public class EnhancedLoggingExample
    {
        private readonly TcpProxy _proxy;
        private readonly ProxyLogger _logger;
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        private readonly bool _enableDetailedLogging;

        /// <summary>
        /// Creates a new EnhancedLoggingExample
        /// </summary>
        /// <param name="listenAddress">Address to listen on (e.g., "127.0.0.1:8080")</param>
        /// <param name="enableDetailedLogging">Whether to enable detailed logging of all data</param>
        /// <param name="logFilePath">Path to log file (null for console only)</param>
        public EnhancedLoggingExample(string listenAddress, bool enableDetailedLogging, string logFilePath = null)
        {
            _enableDetailedLogging = enableDetailedLogging;
            
            // Create the proxy configuration
            var proxyConfig = new ProxyConfig
            {
                ListenerAddress = listenAddress,
                ClientTls = false // Using plain TCP for simplicity
            };

            // Create the proxy logger
            _logger = new ProxyLogger(logFilePath);

            // Create the proxy
            _proxy = new TcpProxy(proxyConfig, _logger);

            // Set up the client-to-server handler
            _proxy.ClientToServerHandler = HandleClientData;
        }

        /// <summary>
        /// Handles data received from clients
        /// </summary>
        private (byte[] data, bool forward) HandleClientData(string clientId, byte[] data)
        {
            // Always log basic information
            _logger.Log($"Processing data from client {clientId}");
            
            // For detailed logging, we use the DataLogger utility
            if (_enableDetailedLogging)
            {
                // The proxy already logs the raw data in both hex and text format
                // through the DataLogger utility, but we can add custom information here
                _logger.Log($"Client connection info: {clientId}");
                
                // Try to detect if this is one of our known binary protocols
                try
                {
                    if (data.Length >= 12) // Minimum size for our binary protocol header
                    {
                        BinaryProtocol binaryMsg = BinaryProtocol.Parse(data);
                        _logger.Log("Detected binary protocol message:");
                        _logger.Log($"  Message Type: {binaryMsg.MessageType}");
                        _logger.Log($"  Fields: {binaryMsg.Fields.Count}");
                        
                        // Create a response
                        BinaryProtocol response = new BinaryProtocol(
                            binaryMsg.MessageType + 100,
                            "Enhanced-Logging-Example",
                            "127.0.0.1",
                            "example.com"
                        );
                        
                        // Convert to binary and return
                        return (response.ToByteArray(), true);
                    }
                }
                catch
                {
                    // Not a valid binary protocol message, continue with normal processing
                    _logger.Log("Not a valid binary protocol message");
                }
            }
            
            // For text-based protocols, we can echo back with a prefix
            try
            {
                string text = Encoding.UTF8.GetString(data);
                if (text.Length > 0)
                {
                    string response = $"ECHO: {text}";
                    return (Encoding.UTF8.GetBytes(response), true);
                }
            }
            catch
            {
                // Not valid UTF-8 text
            }
            
            // For binary data or as a fallback, echo the original data unchanged
            return (data, true);
        }

        /// <summary>
        /// Starts the proxy with enhanced logging
        /// </summary>
        public async Task StartAsync()
        {
            _logger.Log($"Starting proxy with enhanced logging (detailed logging: {_enableDetailedLogging})...");
            
            // Start the proxy in standalone mode
            _ = Task.Run(async () =>
            {
                try
                {
                    await _proxy.StartStandaloneAsync(_cts.Token);
                }
                catch (OperationCanceledException)
                {
                    // Expected when stopping
                }
                catch (Exception ex)
                {
                    _logger.LogError("Proxy error", ex);
                }
            });
            
            // Wait for proxy to initialize
            await Task.Delay(500);
            
            _logger.Log("Proxy started successfully");
        }

        /// <summary>
        /// Stops the proxy
        /// </summary>
        public void Stop()
        {
            _logger.Log("Stopping proxy...");
            _cts.Cancel();
            _logger.Log("Proxy stopped");
        }
    }

    /// <summary>
    /// Usage example for EnhancedLoggingExample
    /// </summary>
    public class EnhancedLoggingUsage
    {
        /// <summary>
        /// Example of how to use the EnhancedLoggingExample
        /// </summary>
        public static async Task RunExampleAsync()
        {
            // Create and start the example with detailed logging enabled
            var example = new EnhancedLoggingExample(
                "127.0.0.1:8888",
                true, // Enable detailed logging
                "enhanced_logging.log" // Log to file
            );
            
            await example.StartAsync();
            
            Console.WriteLine("Proxy with enhanced logging is running on 127.0.0.1:8888");
            Console.WriteLine("All data flowing through the proxy will be logged in both text and hex formats");
            Console.WriteLine("Check enhanced_logging.log for detailed logs");
            Console.WriteLine("Press Enter to stop...");
            Console.ReadLine();
            
            // Stop the example
            example.Stop();
        }
    }
} 