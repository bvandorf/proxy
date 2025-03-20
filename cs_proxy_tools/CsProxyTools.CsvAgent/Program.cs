using System;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Events;

namespace CsProxyTools.ProtocolAgent
{
    public class Program
    {
        private static ILogger<Program> _logger;
        private static DataBuffer _dataBuffer;
        private static TcpClient _tcpClient;
        private static CancellationTokenSource _cts;
        private static string _host;
        private static int _port;
        private static bool _isConnected;
        private static Task _receiveTask;

        public static async Task Main(string[] args)
        {
            // Setup logging
            ConfigureLogging();

            var loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.AddSerilog(dispose: true);
                builder.SetMinimumLevel(LogLevel.Information);
            });

            _logger = loggerFactory.CreateLogger<Program>();
            _logger.LogInformation("TCP Protocol Agent starting...");

            // Create cancellation token source
            _cts = new CancellationTokenSource();

            // Handle Ctrl+C to gracefully exit
            Console.CancelKeyPress += (s, e) => 
            {
                e.Cancel = true; // Prevent the process from terminating immediately
                Console.WriteLine("Cancellation requested. Shutting down...");
                _cts.Cancel();
            };

            try
            {
                // Parse command line arguments
                if (args.Length < 2)
                {
                    Console.WriteLine("Usage: CsProxyTools.ProtocolAgent <host> <port>");
                    return;
                }

                _host = args[0];
                if (!int.TryParse(args[1], out _port))
                {
                    Console.WriteLine("Invalid port number");
                    return;
                }

                // Create the DataBuffer
                _dataBuffer = new DataBuffer(loggerFactory.CreateLogger<DataBuffer>());
                
                // Create and connect the TCP client
                Console.WriteLine($"Connecting to TCP server at {_host}:{_port}");
                await ConnectAsync();
                
                // Run the interactive command loop
                await RunInteractiveCommandsAsync();
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine("Operation was cancelled.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in application");
            }
            finally
            {
                // Clean up
                Disconnect();
                _cts.Dispose();
            }

            _logger.LogInformation("TCP Protocol Agent completed.");
        }

        /// <summary>
        /// Connect to the TCP server
        /// </summary>
        private static async Task ConnectAsync()
        {
            if (_isConnected)
                return;
                
            _logger.LogInformation("Connecting to {Host}:{Port}...", _host, _port);
            
            try
            {
                _tcpClient = new TcpClient();
                await _tcpClient.ConnectAsync(_host, _port);
                _isConnected = true;
                _logger.LogInformation("Connected to {Host}:{Port}", _host, _port);
                
                // Start receiving data
                _receiveTask = ReceiveDataLoopAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to connect to {Host}:{Port}", _host, _port);
                throw;
            }
        }

        /// <summary>
        /// Disconnect from the TCP server
        /// </summary>
        private static void Disconnect()
        {
            if (!_isConnected)
                return;
                
            _logger.LogInformation("Disconnecting from {Host}:{Port}...", _host, _port);
            
            try
            {
                _tcpClient?.Close();
                _isConnected = false;
                _logger.LogInformation("Disconnected from {Host}:{Port}", _host, _port);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error disconnecting from {Host}:{Port}", _host, _port);
            }
        }

        /// <summary>
        /// Loop that receives data from the TCP connection
        /// </summary>
        private static async Task ReceiveDataLoopAsync()
        {
            var buffer = new byte[4096];
            var stream = _tcpClient.GetStream();
            
            try
            {
                while (!_cts.Token.IsCancellationRequested && _tcpClient.Connected)
                {
                    // Check if data is available
                    if (!stream.DataAvailable)
                    {
                        await Task.Delay(10, _cts.Token);
                        continue;
                    }
                    
                    // Read data from the stream
                    int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, _cts.Token);
                    if (bytesRead > 0)
                    {
                        var receivedData = new byte[bytesRead];
                        Array.Copy(buffer, receivedData, bytesRead);
                        
                        // Log received data
                        _logger.LogInformation("Received {BytesRead} bytes: {HexData}", 
                            bytesRead, 
                            BitConverter.ToString(receivedData).Replace("-", ""));
                        
                        // Add data to the buffer for pattern matching
                        _dataBuffer.AddData(receivedData);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Expected when cancelling
                _logger.LogInformation("Data reception loop cancelled");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error receiving data from server");
            }
        }

        /// <summary>
        /// Send data through the TCP connection
        /// </summary>
        private static async Task SendDataAsync(byte[] data)
        {
            if (!_isConnected || data == null || data.Length == 0)
                return;
                
            try
            {
                var stream = _tcpClient.GetStream();
                
                // Log data being sent
                _logger.LogInformation("Sending {DataLength} bytes: {HexData}", 
                    data.Length, 
                    BitConverter.ToString(data).Replace("-", ""));
                
                // Send data through the TCP connection
                await stream.WriteAsync(data, 0, data.Length, _cts.Token);
                await stream.FlushAsync(_cts.Token);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Send operation was cancelled");
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending data to server");
                throw;
            }
        }

        /// <summary>
        /// Wait for specified milliseconds
        /// </summary>
        private static async Task WaitAsync(int milliseconds)
        {
            _logger.LogInformation("Waiting for {Milliseconds}ms", milliseconds);
            await Task.Delay(milliseconds, _cts.Token);
            _logger.LogInformation("Wait completed");
        }

        /// <summary>
        /// Wait for a specific hex pattern to be found in the received data
        /// </summary>
        private static async Task WaitForPatternAsync(string hexPattern)
        {
            if (string.IsNullOrWhiteSpace(hexPattern))
                throw new ArgumentException("Hex pattern cannot be null or empty", nameof(hexPattern));

            _logger.LogInformation("Waiting for pattern: {Pattern}", hexPattern);
            await _dataBuffer.WaitForHexPatternAsync(hexPattern, _cts.Token);
            _logger.LogInformation("Pattern {Pattern} found", hexPattern);
        }

        /// <summary>
        /// Send hex data with optional range parameter
        /// </summary>
        private static async Task SendAsync(string hexData, string rangeParam = null)
        {
            if (string.IsNullOrWhiteSpace(hexData))
                throw new ArgumentException("Hex data cannot be null or empty", nameof(hexData));

            string dataToSend = hexData;
            
            // Process range parameter if specified
            if (!string.IsNullOrWhiteSpace(rangeParam))
            {
                dataToSend = ProcessHexRange(hexData, rangeParam);
            }
            
            // Convert hex string to bytes and send
            byte[] bytes = HexStringToByteArray(dataToSend);
            await SendDataAsync(bytes);
        }

        /// <summary>
        /// Process a hex range parameter (e.g., "1-2" or "0-2,FF")
        /// </summary>
        private static string ProcessHexRange(string hexData, string rangeParam)
        {
            try
            {
                // Parse range formats like "12-5" or "12-5,102"
                var parts = rangeParam.Split(',', StringSplitOptions.RemoveEmptyEntries);
                
                if (parts.Length == 0)
                {
                    _logger.LogWarning("Invalid range format: {RangeParam}", rangeParam);
                    return hexData;
                }

                // Process range
                if (parts[0].Contains("-"))
                {
                    var rangeParts = parts[0].Split('-');
                    if (rangeParts.Length != 2 || 
                        !int.TryParse(rangeParts[0], out int start) || 
                        !int.TryParse(rangeParts[1], out int length))
                    {
                        _logger.LogWarning("Invalid range format: {Range}", parts[0]);
                        return hexData;
                    }

                    // Ensure start and length are valid
                    if (start < 0 || length <= 0 || start >= hexData.Length / 2)
                    {
                        _logger.LogWarning("Invalid range values: start={Start}, length={Length}", start, length);
                        return hexData;
                    }

                    // Extract the specified range (each byte is 2 hex chars)
                    int startChar = start * 2;
                    int endChar = Math.Min(startChar + (length * 2), hexData.Length);
                    
                    string result = hexData.Substring(startChar, endChar - startChar);
                    
                    // If there are additional values to append
                    if (parts.Length > 1)
                    {
                        for (int i = 1; i < parts.Length; i++)
                        {
                            if (int.TryParse(parts[i], out int byteValue))
                            {
                                result += byteValue.ToString("X2");
                            }
                            else
                            {
                                _logger.LogWarning("Invalid byte value: {ByteValue}", parts[i]);
                            }
                        }
                    }
                    
                    return result;
                }
                else
                {
                    _logger.LogWarning("Unsupported range format: {RangeParam}", rangeParam);
                    return hexData;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing hex range: {RangeParam}", rangeParam);
                return hexData;
            }
        }

        /// <summary>
        /// Convert a hex string to a byte array
        /// </summary>
        private static byte[] HexStringToByteArray(string hex)
        {
            // Remove any non-hex characters (like spaces)
            hex = new string(hex.Where(c => "0123456789ABCDEFabcdef".Contains(c)).ToArray());
            
            // If odd length, pad with a leading zero
            if (hex.Length % 2 != 0)
            {
                hex = "0" + hex;
            }

            byte[] bytes = new byte[hex.Length / 2];
            
            for (int i = 0; i < hex.Length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            
            return bytes;
        }

        /// <summary>
        /// Run the interactive command loop
        /// </summary>
        private static async Task RunInteractiveCommandsAsync()
        {
            Console.WriteLine("Starting interactive session");
            Console.WriteLine("Available commands:");
            Console.WriteLine("  wait <ms>        - Wait for specified milliseconds");
            Console.WriteLine("  waitfor <hex>    - Wait for specified hex pattern");
            Console.WriteLine("  send <hex>       - Send hex data");
            Console.WriteLine("  send <hex> <range> - Send hex data with range parameter");
            Console.WriteLine("  text <message>   - Send text as hex");
            Console.WriteLine("  exit             - End the session");
            
            while (!_cts.Token.IsCancellationRequested)
            {
                Console.Write("> ");
                string? input = Console.ReadLine();
                
                if (string.IsNullOrWhiteSpace(input))
                    continue;
                    
                if (_cts.Token.IsCancellationRequested)
                    break;
                    
                string[] parts = input.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                string command = parts[0].ToLowerInvariant();
                
                try
                {
                    switch (command)
                    {
                        case "exit":
                            return;
                            
                        case "wait":
                            if (parts.Length > 1 && int.TryParse(parts[1], out int ms))
                            {
                                await WaitAsync(ms);
                            }
                            else
                            {
                                Console.WriteLine("Invalid wait time. Usage: wait <ms>");
                            }
                            break;
                            
                        case "waitfor":
                            if (parts.Length > 1)
                            {
                                string pattern = parts[1];
                                await WaitForPatternAsync(pattern);
                            }
                            else
                            {
                                Console.WriteLine("Invalid pattern. Usage: waitfor <hex>");
                            }
                            break;
                            
                        case "send":
                            if (parts.Length > 1)
                            {
                                string hexData = parts[1];
                                string? range = parts.Length > 2 ? parts[2] : null;
                                
                                await SendAsync(hexData, range);
                            }
                            else
                            {
                                Console.WriteLine("Invalid hex data. Usage: send <hex> [range]");
                            }
                            break;
                            
                        case "text":
                            if (parts.Length > 1)
                            {
                                string text = string.Join(" ", parts.Skip(1));
                                string hexData = BitConverter.ToString(Encoding.ASCII.GetBytes(text)).Replace("-", "");
                                
                                Console.WriteLine($"Sending text as hex: {hexData}");
                                await SendAsync(hexData);
                            }
                            else
                            {
                                Console.WriteLine("Invalid text. Usage: text <message>");
                            }
                            break;
                            
                        default:
                            Console.WriteLine($"Unknown command: {command}");
                            break;
                    }
                }
                catch (OperationCanceledException)
                {
                    Console.WriteLine("Command was canceled");
                    break;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error executing command: {ex.Message}");
                }
            }
        }

        private static void ConfigureLogging()
        {
            // Ensure logs directory exists
            Directory.CreateDirectory("logs");

            // Configure Serilog
            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Information()
                .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}")
                .WriteTo.File(
                    path: Path.Combine("logs", "tcp-agent-log-.txt"),
                    outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception}",
                    rollingInterval: RollingInterval.Day,
                    fileSizeLimitBytes: 100 * 1024 * 1024,
                    retainedFileCountLimit: 14,
                    shared: true,
                    flushToDiskInterval: TimeSpan.FromSeconds(1))
                .CreateLogger();
        }
    }
} 