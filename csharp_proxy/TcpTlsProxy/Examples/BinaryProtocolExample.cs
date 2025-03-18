using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TcpTlsProxy.Protocols;

namespace TcpTlsProxy.Examples
{
    /// <summary>
    /// Example showing how to use the standalone proxy with the BinaryProtocol
    /// </summary>
    public class BinaryProtocolExample
    {
        private readonly TcpProxy _proxy;
        private readonly ProxyLogger _logger;
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();

        /// <summary>
        /// Creates a new BinaryProtocolExample
        /// </summary>
        /// <param name="listenAddress">Address to listen on (e.g., "127.0.0.1:8080")</param>
        /// <param name="customHostname">Custom hostname to use in responses</param>
        /// <param name="customIp">Custom IP to use in responses</param>
        /// <param name="customDomain">Custom domain to use in responses</param>
        public BinaryProtocolExample(string listenAddress, string customHostname, string customIp, string customDomain)
        {
            // Create the proxy configuration
            var proxyConfig = new ProxyConfig
            {
                ListenerAddress = listenAddress,
                ClientTls = false // Using plain TCP for simplicity
            };

            // Create the proxy logger
            _logger = new ProxyLogger("binary_protocol_proxy.log");

            // Create the proxy
            _proxy = new TcpProxy(proxyConfig, _logger);

            // Set up the client-to-server handler for processing incoming binary protocol data
            _proxy.ClientToServerHandler = (clientId, data) =>
            {
                try
                {
                    // Parse the incoming binary protocol data
                    BinaryProtocol request = BinaryProtocol.Parse(data);
                    
                    // Log the parsed request
                    _logger.Log($"Received binary protocol message from {clientId}:");
                    _logger.Log(request.ToString());
                    _logger.Log($"Hex: {request.ToHexString()}");
                    
                    // Create a response with custom fields
                    BinaryProtocol response;
                    
                    if (request.Fields.Count >= 3)
                    {
                        // Replace the fields with custom values
                        response = new BinaryProtocol(
                            request.MessageType + 100, // Convention: response type = request type + 100
                            customHostname,
                            customIp,
                            customDomain
                        );
                    }
                    else
                    {
                        // Create a default response
                        response = request.CreateResponse();
                    }
                    
                    // Log the response
                    _logger.Log($"Sending response to {clientId}:");
                    _logger.Log(response.ToString());
                    _logger.Log($"Hex: {response.ToHexString()}");
                    
                    // Convert the response to binary and return it
                    return (response.ToByteArray(), true);
                }
                catch (Exception ex)
                {
                    // If parsing fails, log the error
                    _logger.LogError($"Error processing binary protocol data from {clientId}", ex);
                    _logger.Log($"Raw data: {BitConverter.ToString(data).Replace("-", " ")}");
                    
                    // Return the original data unchanged
                    return (data, true);
                }
            };
        }

        /// <summary>
        /// Starts the binary protocol proxy
        /// </summary>
        public async Task StartAsync()
        {
            _logger.Log("Starting binary protocol proxy...");
            
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
            
            _logger.Log("Binary protocol proxy started successfully");
        }

        /// <summary>
        /// Stops the binary protocol proxy
        /// </summary>
        public void Stop()
        {
            _logger.Log("Stopping binary protocol proxy...");
            _cts.Cancel();
            _logger.Log("Binary protocol proxy stopped");
        }
    }

    /// <summary>
    /// Usage example for BinaryProtocolExample
    /// </summary>
    public class BinaryProtocolUsage
    {
        /// <summary>
        /// Example of how to use the BinaryProtocolExample
        /// </summary>
        public static async Task RunExampleAsync()
        {
            // Create and start the example with custom values
            var example = new BinaryProtocolExample(
                "127.0.0.1:8888",
                "CUSTOM-HOST",
                "192.168.1.100",
                "example.com"
            );
            
            await example.StartAsync();
            
            Console.WriteLine("Binary protocol proxy is running on 127.0.0.1:8888");
            Console.WriteLine("Press Enter to stop...");
            Console.ReadLine();
            
            // Stop the example
            example.Stop();
        }
    }
} 