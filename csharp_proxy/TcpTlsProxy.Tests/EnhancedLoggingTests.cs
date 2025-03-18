using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TcpTlsProxy.Protocols;

namespace TcpTlsProxy.Tests
{
    [TestClass]
    public class EnhancedLoggingTests
    {
        private class LogCapturingLogger : ProxyLogger
        {
            public LogCapturingLogger() : base(null) { }
            
            public List<string> CapturedLogs { get; } = new List<string>();
            
            public override void Log(string message)
            {
                CapturedLogs.Add(message);
            }
        }
        
        [TestMethod]
        public async Task TcpProxy_WithEnhancedLogging_LogsAllTraffic()
        {
            // Arrange
            var logger = new LogCapturingLogger();
            var testPort = GetAvailablePort();
            
            var config = new ProxyConfig
            {
                ListenerAddress = $"127.0.0.1:{testPort}",
                ClientTls = false // Using plain TCP for testing
            };
            
            var proxy = new TcpProxy(config, logger);
            
            // Setup data handlers with enhanced logging
            string capturedClientData = null;
            
            proxy.ClientToServerHandler = (clientId, data) =>
            {
                // Verify that we're getting the correct data
                capturedClientData = Encoding.UTF8.GetString(data);
                
                // Return the data unchanged to echo it back
                return (data, true);
            };
            
            // Start proxy in standalone mode
            var cts = new CancellationTokenSource();
            cts.CancelAfter(TimeSpan.FromSeconds(30)); // Safety timeout
            
            var proxyTask = proxy.StartStandaloneAsync(cts.Token);
            
            // Give the proxy time to start
            await Task.Delay(1000);
            
            try
            {
                // Act - Connect to the proxy and send data
                using (var client = new TcpClient())
                {
                    await client.ConnectAsync("127.0.0.1", testPort);
                    
                    using (var stream = client.GetStream())
                    {
                        // Send test data
                        string testMessage = "Test message for enhanced logging";
                        byte[] data = Encoding.UTF8.GetBytes(testMessage);
                        await stream.WriteAsync(data, 0, data.Length);
                        
                        // Give the proxy time to process
                        await Task.Delay(500);
                        
                        // Read response
                        byte[] responseBuffer = new byte[1024];
                        int bytesRead = await stream.ReadAsync(responseBuffer, 0, responseBuffer.Length);
                        
                        // Verify echo response
                        string response = Encoding.UTF8.GetString(responseBuffer, 0, bytesRead);
                        Assert.AreEqual(testMessage, response, "Proxy should echo the data back");
                    }
                }
                
                // Stop the proxy
                cts.Cancel();
                
                // Assert
                Assert.AreEqual("Test message for enhanced logging", capturedClientData, "Handler should receive the correct data");
                
                // Verify enhanced logging entries
                bool foundDataLoggerEntries = false;
                bool foundHexRepresentation = false;
                bool foundTextRepresentation = false;
                
                foreach (var log in logger.CapturedLogs)
                {
                    if (log.StartsWith("Hex:"))
                    {
                        foundHexRepresentation = true;
                    }
                    else if (log.StartsWith("Text:") && log.Contains("Test message for enhanced logging"))
                    {
                        foundTextRepresentation = true;
                    }
                    else if (log.Contains("bytes from"))
                    {
                        foundDataLoggerEntries = true;
                    }
                }
                
                Assert.IsTrue(foundDataLoggerEntries, "Should log entry with byte count and client ID");
                Assert.IsTrue(foundHexRepresentation, "Should log hex representation of data");
                Assert.IsTrue(foundTextRepresentation, "Should log text representation of data");
            }
            finally
            {
                // Ensure we cancel the proxy task
                if (!cts.IsCancellationRequested)
                {
                    cts.Cancel();
                }
                
                try
                {
                    // Attempt to wait for the proxy to stop, but don't wait too long
                    await Task.WhenAny(proxyTask, Task.Delay(3000));
                }
                catch
                {
                    // Ignore any exceptions during cleanup
                }
            }
        }
        
        [TestMethod]
        public async Task TcpProxy_WithEnhancedLogging_LogsBinaryData()
        {
            // Arrange
            var logger = new LogCapturingLogger();
            var testPort = GetAvailablePort();
            
            var config = new ProxyConfig
            {
                ListenerAddress = $"127.0.0.1:{testPort}",
                ClientTls = false
            };
            
            var proxy = new TcpProxy(config, logger);
            
            // Create binary protocol message
            var binaryProtocol = new BinaryProtocol(42, "TestHost", "127.0.0.1", "example.org");
            var binaryData = binaryProtocol.ToByteArray();
            
            // Setup handlers
            proxy.ClientToServerHandler = (clientId, data) =>
            {
                // Create a response
                var parsedProtocol = BinaryProtocol.Parse(data);
                var response = parsedProtocol.CreateResponse("Binary Response: ");
                return (response.ToByteArray(), true);
            };
            
            // Start proxy
            var cts = new CancellationTokenSource();
            cts.CancelAfter(TimeSpan.FromSeconds(30));
            
            var proxyTask = proxy.StartStandaloneAsync(cts.Token);
            
            // Give the proxy time to start
            await Task.Delay(1000);
            
            try
            {
                // Act - Connect and send binary data
                using (var client = new TcpClient())
                {
                    await client.ConnectAsync("127.0.0.1", testPort);
                    
                    using (var stream = client.GetStream())
                    {
                        // Send binary data
                        await stream.WriteAsync(binaryData, 0, binaryData.Length);
                        
                        // Give the proxy time to process
                        await Task.Delay(500);
                        
                        // Read response
                        byte[] responseBuffer = new byte[1024];
                        int bytesRead = await stream.ReadAsync(responseBuffer, 0, responseBuffer.Length);
                        
                        // Verify response is a valid binary protocol message
                        byte[] responseData = new byte[bytesRead];
                        Array.Copy(responseBuffer, responseData, bytesRead);
                        
                        var responseProtocol = BinaryProtocol.Parse(responseData);
                        Assert.AreEqual(142, responseProtocol.MessageType); // 42 + 100
                        Assert.IsTrue(responseProtocol.Fields.Count > 1);
                        Assert.AreEqual("Binary Response: ", responseProtocol.Fields[0]);
                    }
                }
                
                // Stop the proxy
                cts.Cancel();
                
                // Assert logging
                bool foundBinaryDataNotation = false;
                
                foreach (var log in logger.CapturedLogs)
                {
                    if (log.Contains("[Binary data") || (log.StartsWith("Text:") && log.Contains("[Binary data")))
                    {
                        foundBinaryDataNotation = true;
                        break;
                    }
                }
                
                Assert.IsTrue(foundBinaryDataNotation, "Should identify and log binary data appropriately");
            }
            finally
            {
                // Ensure we cancel the proxy task
                if (!cts.IsCancellationRequested)
                {
                    cts.Cancel();
                }
                
                try
                {
                    // Attempt to wait for the proxy to stop, but don't wait too long
                    await Task.WhenAny(proxyTask, Task.Delay(3000));
                }
                catch
                {
                    // Ignore any exceptions during cleanup
                }
            }
        }
        
        private static int GetAvailablePort()
        {
            // Find an available port by creating a temporary listener
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }
    }
} 