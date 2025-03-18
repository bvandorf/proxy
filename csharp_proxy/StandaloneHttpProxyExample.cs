using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TcpTlsProxy;

namespace StandaloneHttpProxyExample
{
    /// <summary>
    /// Example of a standalone TCP proxy implementing a simple HTTP server
    /// </summary>
    public class HttpServerProxy
    {
        private readonly TcpProxy _proxy;
        private readonly ProxyLogger _logger;
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        private readonly Dictionary<string, string> _routes = new Dictionary<string, string>();

        public HttpServerProxy(string listenerAddress = "127.0.0.1:8080")
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
            
            // Set up the client handler
            _proxy.ClientToServerHandler = ProcessHttpRequest;
            
            // Initialize some sample routes
            _routes["/"] = "Welcome to the HTTP Server Proxy Example!";
            _routes["/hello"] = "Hello, World!";
            _routes["/time"] = "Current server time: " + DateTime.Now.ToString();
            _routes["/echo"] = "Use POST to echo data";
        }

        /// <summary>
        /// Start the HTTP server proxy
        /// </summary>
        public async Task StartAsync()
        {
            _logger.Log("Starting HTTP Server Proxy...");
            
            // Start the proxy in standalone mode
            await _proxy.StartStandaloneAsync(_cts.Token);
        }

        /// <summary>
        /// Stop the HTTP server proxy
        /// </summary>
        public void Stop()
        {
            _logger.Log("Stopping HTTP Server Proxy...");
            _cts.Cancel();
            _proxy.Stop();
        }

        /// <summary>
        /// Process HTTP requests
        /// </summary>
        private (byte[] data, bool forward) ProcessHttpRequest(string clientId, byte[] data)
        {
            // Convert the received bytes to a string
            string requestText = Encoding.UTF8.GetString(data);
            _logger.Log($"Received HTTP request from {clientId}:\n{requestText.Substring(0, Math.Min(500, requestText.Length))}");
            
            try
            {
                // Parse the HTTP request
                var request = ParseHttpRequest(requestText);
                
                // Generate a response based on the request
                var responseBytes = GenerateHttpResponse(request);
                
                // Return the response and true to forward it back to the client
                return (responseBytes, true);
            }
            catch (Exception ex)
            {
                _logger.LogError("Error processing HTTP request", ex);
                
                // Generate a 500 Internal Server Error response
                string errorResponse = 
                    "HTTP/1.1 500 Internal Server Error\r\n" +
                    "Content-Type: text/plain\r\n" +
                    "Connection: close\r\n" +
                    $"Content-Length: {ex.Message.Length}\r\n" +
                    "\r\n" +
                    ex.Message;
                
                return (Encoding.UTF8.GetBytes(errorResponse), true);
            }
        }

        /// <summary>
        /// Parse an HTTP request
        /// </summary>
        private HttpRequest ParseHttpRequest(string requestText)
        {
            var request = new HttpRequest();
            
            // Split the request into lines
            string[] lines = requestText.Split(new[] { "\r\n" }, StringSplitOptions.None);
            
            if (lines.Length == 0)
            {
                throw new Exception("Invalid HTTP request: empty request");
            }
            
            // Parse the request line (e.g., "GET /path HTTP/1.1")
            string[] requestLineParts = lines[0].Split(' ');
            if (requestLineParts.Length != 3)
            {
                throw new Exception($"Invalid HTTP request line: {lines[0]}");
            }
            
            request.Method = requestLineParts[0];
            request.Path = requestLineParts[1];
            request.HttpVersion = requestLineParts[2];
            
            // Parse headers
            int i = 1;
            while (i < lines.Length && !string.IsNullOrEmpty(lines[i]))
            {
                string[] headerParts = lines[i].Split(new[] { ": " }, 2, StringSplitOptions.None);
                if (headerParts.Length == 2)
                {
                    request.Headers[headerParts[0]] = headerParts[1];
                }
                i++;
            }
            
            // Parse body if present
            if (i < lines.Length - 1)
            {
                request.Body = string.Join("\r\n", lines.AsSpan(i + 1).ToArray());
            }
            
            return request;
        }

        /// <summary>
        /// Generate an HTTP response based on the request
        /// </summary>
        private byte[] GenerateHttpResponse(HttpRequest request)
        {
            _logger.Log($"Processing {request.Method} request for path: {request.Path}");
            
            string responseContent;
            string statusLine;
            string contentType = "text/plain";
            
            // Handle different HTTP methods
            switch (request.Method.ToUpper())
            {
                case "GET":
                    // Check if the path exists in our routes
                    if (_routes.TryGetValue(request.Path, out string content))
                    {
                        statusLine = "HTTP/1.1 200 OK";
                        responseContent = content;
                        
                        // Special case for the time route to always return current time
                        if (request.Path == "/time")
                        {
                            responseContent = "Current server time: " + DateTime.Now.ToString();
                        }
                    }
                    else
                    {
                        statusLine = "HTTP/1.1 404 Not Found";
                        responseContent = $"Path '{request.Path}' not found";
                    }
                    break;
                    
                case "POST":
                    // Handle POST to /echo to echo back the request body
                    if (request.Path == "/echo")
                    {
                        statusLine = "HTTP/1.1 200 OK";
                        responseContent = request.Body ?? "No content provided";
                    }
                    else
                    {
                        statusLine = "HTTP/1.1 404 Not Found";
                        responseContent = $"Path '{request.Path}' not found";
                    }
                    break;
                    
                default:
                    statusLine = "HTTP/1.1 405 Method Not Allowed";
                    responseContent = $"Method '{request.Method}' not supported";
                    break;
            }
            
            // Build the HTTP response
            StringBuilder response = new StringBuilder();
            response.AppendLine(statusLine);
            response.AppendLine($"Content-Type: {contentType}");
            response.AppendLine($"Content-Length: {Encoding.UTF8.GetByteCount(responseContent)}");
            response.AppendLine("Connection: close");
            response.AppendLine(); // Empty line to separate headers from body
            response.Append(responseContent);
            
            return Encoding.UTF8.GetBytes(response.ToString());
        }

        /// <summary>
        /// Simple HTTP request representation
        /// </summary>
        private class HttpRequest
        {
            public string Method { get; set; } = string.Empty;
            public string Path { get; set; } = string.Empty;
            public string HttpVersion { get; set; } = string.Empty;
            public Dictionary<string, string> Headers { get; } = new Dictionary<string, string>();
            public string? Body { get; set; }
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
            Console.WriteLine("Starting standalone HTTP server proxy example");
            
            // Create the HTTP server proxy
            var httpProxy = new HttpServerProxy("127.0.0.1:8080");
            
            // Handle Ctrl+C to gracefully shut down
            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true;
                httpProxy.Stop();
            };
            
            Console.WriteLine("HTTP server proxy listening on http://127.0.0.1:8080");
            Console.WriteLine("Try these URLs in your browser:");
            Console.WriteLine("- http://127.0.0.1:8080/");
            Console.WriteLine("- http://127.0.0.1:8080/hello");
            Console.WriteLine("- http://127.0.0.1:8080/time");
            Console.WriteLine("- Send POST requests to http://127.0.0.1:8080/echo to echo data");
            Console.WriteLine("Press Ctrl+C to exit");
            
            // Start the proxy
            await httpProxy.StartAsync();
        }
    }
} 