using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TcpTlsProxy;

namespace TcpTlsProxy.Examples
{
    /// <summary>
    /// Example showing how to use the standalone proxy with a WebSocket data source
    /// </summary>
    public class StandaloneWebSocketExample
    {
        // Simulates your external WebSocket service
        private readonly ExternalWebSocketDataSource _webSocketDataSource;
        private readonly TcpProxy _proxy;
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();

        public StandaloneWebSocketExample(string listenAddress, bool useTls = false)
        {
            // Create the proxy configuration
            var proxyConfig = new ProxyConfig
            {
                ListenerAddress = listenAddress,
                ClientTls = useTls,
                InsecureSkipVerify = true // For development only
            };

            // If using TLS, you'll need to set up certificates
            if (useTls)
            {
                // Load your certificate here
                // proxyConfig.ServerCertificate = ...
            }

            // Create the proxy logger
            var logger = new ProxyLogger("proxy.log");

            // Create the proxy
            _proxy = new TcpProxy(proxyConfig, logger);

            // Create the WebSocket data source (your actual implementation would go here)
            _webSocketDataSource = new ExternalWebSocketDataSource();

            // Set up event handlers
            _webSocketDataSource.MessageReceived += OnWebSocketMessageReceived;
            _webSocketDataSource.ErrorOccurred += OnWebSocketErrorOccurred;
            _webSocketDataSource.ConnectionClosed += OnWebSocketConnectionClosed;

            // Set up the client-to-server handler for processing incoming client data
            _proxy.ClientToServerHandler = HandleClientData;
        }

        /// <summary>
        /// Starts the proxy and connects to the WebSocket service
        /// </summary>
        public async Task StartAsync()
        {
            // Connect to the WebSocket service
            await _webSocketDataSource.ConnectAsync("wss://your-websocket-service.com");

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
                    Console.WriteLine($"Proxy error: {ex.Message}");
                }
            });

            Console.WriteLine("Proxy started in standalone mode");
        }

        /// <summary>
        /// Stops the proxy and disconnects from the WebSocket service
        /// </summary>
        public async Task StopAsync()
        {
            _cts.Cancel();
            await _webSocketDataSource.DisconnectAsync();
            Console.WriteLine("Proxy stopped");
        }

        /// <summary>
        /// Handles data received from clients
        /// </summary>
        private (byte[] data, bool forward) HandleClientData(string clientId, byte[] data)
        {
            string message = Encoding.UTF8.GetString(data);
            Console.WriteLine($"Received from client {clientId}: {message}");

            // Forward client message to WebSocket service
            _webSocketDataSource.SendMessageAsync(message).ConfigureAwait(false);
            
            // Return the original data, but indicate not to forward it automatically
            // We'll handle sending any responses from the WebSocket separately in the event handler
            return (data, false);
        }

        /// <summary>
        /// Handles messages received from the WebSocket service
        /// </summary>
        private async void OnWebSocketMessageReceived(object sender, string message)
        {
            Console.WriteLine($"Received from WebSocket: {message}");

            // Forward WebSocket message to all connected clients
            byte[] data = Encoding.UTF8.GetBytes(message);
            await _proxy.BroadcastAsync(data);
        }

        /// <summary>
        /// Handles errors from the WebSocket service
        /// </summary>
        private void OnWebSocketErrorOccurred(object sender, Exception ex)
        {
            Console.WriteLine($"WebSocket error: {ex.Message}");
        }

        /// <summary>
        /// Handles WebSocket connection closure
        /// </summary>
        private void OnWebSocketConnectionClosed(object sender, EventArgs e)
        {
            Console.WriteLine("WebSocket connection closed");
        }
    }

    /// <summary>
    /// Simulated external WebSocket data source
    /// Replace this with your actual WebSocket client implementation
    /// </summary>
    public class ExternalWebSocketDataSource
    {
        // Events for WebSocket notifications
        public event EventHandler<string> MessageReceived;
        public event EventHandler<Exception> ErrorOccurred;
        public event EventHandler ConnectionClosed;

        /// <summary>
        /// Simulates connecting to a WebSocket service
        /// </summary>
        public Task ConnectAsync(string url)
        {
            Console.WriteLine($"Connecting to WebSocket at {url}");
            // Actual WebSocket connection code would go here
            return Task.CompletedTask;
        }

        /// <summary>
        /// Simulates sending a message to the WebSocket service
        /// </summary>
        public Task SendMessageAsync(string message)
        {
            Console.WriteLine($"Sending to WebSocket: {message}");
            // Actual WebSocket send code would go here
            
            // Simulate a response from the WebSocket service
            Task.Run(async () =>
            {
                await Task.Delay(100); // Simulate network latency
                MessageReceived?.Invoke(this, $"Response to: {message}");
            });
            
            return Task.CompletedTask;
        }

        /// <summary>
        /// Simulates disconnecting from the WebSocket service
        /// </summary>
        public Task DisconnectAsync()
        {
            Console.WriteLine("Disconnecting from WebSocket");
            // Actual WebSocket disconnection code would go here
            ConnectionClosed?.Invoke(this, EventArgs.Empty);
            return Task.CompletedTask;
        }
    }

    /// <summary>
    /// Example usage
    /// </summary>
    public class StandaloneExampleUsage
    {
        /// <summary>
        /// Example of how to use the StandaloneWebSocketExample class
        /// </summary>
        public static async Task RunExampleAsync()
        {
            // Create and start the example
            var example = new StandaloneWebSocketExample("127.0.0.1:8080");
            await example.StartAsync();

            Console.WriteLine("Proxy is running. Press Enter to exit.");
            Console.ReadLine();

            // Stop the example
            await example.StopAsync();
        }
    }
} 