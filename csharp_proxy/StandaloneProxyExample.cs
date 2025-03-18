using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TcpTlsProxy;

namespace StandaloneProxyExample
{
    /// <summary>
    /// Example of a standalone TCP proxy that implements a simple echo protocol
    /// </summary>
    public class EchoProxy
    {
        private readonly TcpProxy _proxy;
        private readonly ProxyLogger _logger;
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();

        public EchoProxy(string listenerAddress = "127.0.0.1:8000")
        {
            // Create a logger
            _logger = new ConsoleLogger();
            
            // Create a basic configuration for a plain TCP proxy
            var config = new ProxyConfig
            {
                ListenerAddress = listenerAddress,
                ClientTls = false, // Plain TCP, no TLS
                TargetTls = false, // Not applicable in standalone mode
                DialTimeout = 5000 // ms
            };
            
            // Create the proxy
            _proxy = new TcpProxy(config, _logger);
            
            // Set up the client handler that will implement the echo protocol
            _proxy.ClientToServerHandler = ProcessClientData;
        }

        /// <summary>
        /// Start the echo proxy server
        /// </summary>
        public async Task StartAsync()
        {
            _logger.Log("Starting Echo Proxy server...");
            
            // Start the proxy in standalone mode
            await _proxy.StartStandaloneAsync(_cts.Token);
        }

        /// <summary>
        /// Stop the echo proxy server
        /// </summary>
        public void Stop()
        {
            _logger.Log("Stopping Echo Proxy server...");
            _cts.Cancel();
            _proxy.Stop();
        }

        /// <summary>
        /// Process data from clients and implement the echo protocol
        /// </summary>
        private (byte[] data, bool forward) ProcessClientData(string clientId, byte[] data)
        {
            // Convert the received bytes to a string for easier handling in this example
            string receivedText = Encoding.UTF8.GetString(data);
            _logger.Log($"Received from client {clientId}: {receivedText.TrimEnd()}");
            
            // In a real application, you could implement more complex processing here
            // For example:
            // - Custom protocols
            // - Request routing
            // - Content transformation
            // - Authentication and authorization
            
            // Create a response with an echo prefix
            string response = $"ECHO: {receivedText}";
            byte[] responseData = Encoding.UTF8.GetBytes(response);
            
            // Return the response and true to forward it back to the client
            return (responseData, true);
        }

        /// <summary>
        /// Simple console logger implementation
        /// </summary>
        private class ConsoleLogger : ProxyLogger
        {
            public override void Log(string message)
            {
                Console.WriteLine($"[INFO] {DateTime.Now:HH:mm:ss.fff} - {message}");
            }

            public override void LogError(string message, Exception? exception = null)
            {
                Console.WriteLine($"[ERROR] {DateTime.Now:HH:mm:ss.fff} - {message}");
                if (exception != null)
                {
                    Console.WriteLine($"[ERROR] Exception: {exception.Message}");
                    Console.WriteLine($"[ERROR] StackTrace: {exception.StackTrace}");
                }
            }
        }
    }

    /// <summary>
    /// Program entry point with example usage
    /// </summary>
    public class Program
    {
        public static async Task Main(string[] args)
        {
            Console.WriteLine("Starting standalone echo proxy example");
            
            // Create the echo proxy
            var echoProxy = new EchoProxy("127.0.0.1:8000");
            
            // Handle Ctrl+C to gracefully shut down
            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true;
                echoProxy.Stop();
            };
            
            Console.WriteLine("Echo proxy listening on 127.0.0.1:8000");
            Console.WriteLine("Connect with: telnet 127.0.0.1 8000");
            Console.WriteLine("Press Ctrl+C to exit");
            
            // Start the proxy
            await echoProxy.StartAsync();
        }
    }
} 