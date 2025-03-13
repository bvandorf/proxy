using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TcpTlsProxy;

namespace TcpTlsProxy.Tests
{
    [TestClass]
    public class StandaloneProxyTests
    {
        [TestMethod]
        public async Task StandaloneProxy_CanProcessAndRespondToClient()
        {
            // Skip this test on CI environments
            if (Environment.GetEnvironmentVariable("CI") == "true")
            {
                Assert.Inconclusive("Skipping network tests in CI environment");
                return;
            }

            // Find an available port for our standalone proxy
            int proxyPort = FindAvailablePort();
            
            // Create a cancellation token source that will cancel all components
            using var testCts = new CancellationTokenSource();
            testCts.CancelAfter(TimeSpan.FromSeconds(30)); // Timeout after 30 seconds
            
            // Dictionary to track received messages for verification
            var receivedMessages = new Dictionary<string, List<string>>();
            var receivedMessagesLock = new object();
            
            try
            {
                // Create a standalone proxy
                var proxyConfig = new ProxyConfig
                {
                    ListenerAddress = $"127.0.0.1:{proxyPort}",
                    ClientTls = false // TCP only for incoming connections for simplicity
                };
                
                var proxyLogger = new ProxyLogger(Path.Combine(Path.GetTempPath(), $"proxy_{Guid.NewGuid()}.log"));
                var proxy = new TcpProxy(proxyConfig, proxyLogger);
                
                // Set the client-to-server handler to process incoming data
                proxy.ClientToServerHandler = (clientId, data) =>
                {
                    string message = Encoding.UTF8.GetString(data);
                    Console.WriteLine($"Received from {clientId}: {message}");
                    
                    // Store the message for verification
                    lock (receivedMessagesLock)
                    {
                        if (!receivedMessages.ContainsKey(clientId))
                        {
                            receivedMessages[clientId] = new List<string>();
                        }
                        receivedMessages[clientId].Add(message);
                    }
                    
                    // Echo the message back to the client with a prefix
                    string response = $"ECHO: {message}";
                    byte[] responseData = Encoding.UTF8.GetBytes(response);
                    
                    // Return modified data and indicate to forward it back
                    return (responseData, true);
                };
                
                // Start the standalone proxy in a background task
                var proxyTask = Task.Run(async () => 
                {
                    try 
                    {
                        await proxy.StartStandaloneAsync(testCts.Token);
                    }
                    catch (OperationCanceledException) { /* Expected */ }
                    catch (Exception ex) 
                    {
                        Console.WriteLine($"Proxy error: {ex.Message}");
                    }
                });
                
                // Wait for proxy to start
                await Task.Delay(500);
                
                // Create and connect clients to the proxy
                using var client1 = new TcpClient();
                await client1.ConnectAsync("127.0.0.1", proxyPort);
                var client1Stream = client1.GetStream();
                
                using var client2 = new TcpClient();
                await client2.ConnectAsync("127.0.0.1", proxyPort);
                var client2Stream = client2.GetStream();
                
                // Send test data from client 1
                string testMessage1 = "Hello from client 1!";
                byte[] testData1 = Encoding.UTF8.GetBytes(testMessage1);
                await client1Stream.WriteAsync(testData1, 0, testData1.Length);
                
                // Send test data from client 2
                string testMessage2 = "Hello from client 2!";
                byte[] testData2 = Encoding.UTF8.GetBytes(testMessage2);
                await client2Stream.WriteAsync(testData2, 0, testData2.Length);
                
                // Wait to ensure data is processed and responses are sent
                await Task.Delay(1000);
                
                // Read responses from clients
                byte[] responseBuffer1 = new byte[1024];
                var readTask1 = client1Stream.ReadAsync(responseBuffer1, 0, responseBuffer1.Length);
                
                byte[] responseBuffer2 = new byte[1024];
                var readTask2 = client2Stream.ReadAsync(responseBuffer2, 0, responseBuffer2.Length);
                
                // Wait for responses with timeouts
                if (await Task.WhenAny(readTask1, Task.Delay(5000)) == readTask1)
                {
                    int bytesRead1 = await readTask1;
                    string response1 = Encoding.UTF8.GetString(responseBuffer1, 0, bytesRead1);
                    Console.WriteLine($"Client 1 received: {response1}");
                    
                    // Verify the response contains the echo prefix and original message
                    Assert.IsTrue(response1.Contains("ECHO:"), "Response should contain the echo prefix");
                    Assert.IsTrue(response1.Contains(testMessage1), "Response should contain the original message");
                }
                else
                {
                    Assert.Fail("Timeout waiting for response to client 1");
                }
                
                if (await Task.WhenAny(readTask2, Task.Delay(5000)) == readTask2)
                {
                    int bytesRead2 = await readTask2;
                    string response2 = Encoding.UTF8.GetString(responseBuffer2, 0, bytesRead2);
                    Console.WriteLine($"Client 2 received: {response2}");
                    
                    // Verify the response contains the echo prefix and original message
                    Assert.IsTrue(response2.Contains("ECHO:"), "Response should contain the echo prefix");
                    Assert.IsTrue(response2.Contains(testMessage2), "Response should contain the original message");
                }
                else
                {
                    Assert.Fail("Timeout waiting for response to client 2");
                }
                
                // Test broadcasting
                string broadcastMessage = "Broadcast to all clients";
                byte[] broadcastData = Encoding.UTF8.GetBytes(broadcastMessage);
                int broadcastCount = await proxy.BroadcastAsync(broadcastData, testCts.Token);
                
                // Verify broadcast count
                Assert.AreEqual(2, broadcastCount, "Broadcast should reach both clients");
                
                // Read broadcast messages
                byte[] broadcastBuffer1 = new byte[1024];
                var broadcastReadTask1 = client1Stream.ReadAsync(broadcastBuffer1, 0, broadcastBuffer1.Length);
                
                byte[] broadcastBuffer2 = new byte[1024];
                var broadcastReadTask2 = client2Stream.ReadAsync(broadcastBuffer2, 0, broadcastBuffer2.Length);
                
                // Wait for broadcast responses with timeouts
                if (await Task.WhenAny(broadcastReadTask1, Task.Delay(5000)) == broadcastReadTask1)
                {
                    int bytesRead1 = await broadcastReadTask1;
                    string response1 = Encoding.UTF8.GetString(broadcastBuffer1, 0, bytesRead1);
                    Console.WriteLine($"Client 1 received broadcast: {response1}");
                    
                    // Verify the broadcast message
                    Assert.AreEqual(broadcastMessage, response1, "Client 1 should receive the broadcast message");
                }
                else
                {
                    Assert.Fail("Timeout waiting for broadcast to client 1");
                }
                
                if (await Task.WhenAny(broadcastReadTask2, Task.Delay(5000)) == broadcastReadTask2)
                {
                    int bytesRead2 = await broadcastReadTask2;
                    string response2 = Encoding.UTF8.GetString(broadcastBuffer2, 0, bytesRead2);
                    Console.WriteLine($"Client 2 received broadcast: {response2}");
                    
                    // Verify the broadcast message
                    Assert.AreEqual(broadcastMessage, response2, "Client 2 should receive the broadcast message");
                }
                else
                {
                    Assert.Fail("Timeout waiting for broadcast to client 2");
                }
                
                // Get connected clients and verify count
                var connectedClients = proxy.GetConnectedClients();
                Assert.AreEqual(2, connectedClients.Count, "There should be 2 connected clients");
                
                // Disconnect client 1
                string client1Id = connectedClients[0];
                bool disconnectResult = proxy.DisconnectClient(client1Id);
                Assert.IsTrue(disconnectResult, "Client 1 should be disconnected successfully");
                
                // Verify client count after disconnection
                await Task.Delay(500); // Wait for disconnection to process
                connectedClients = proxy.GetConnectedClients();
                Assert.AreEqual(1, connectedClients.Count, "There should be 1 connected client after disconnection");
            }
            finally
            {
                // Cleanup
                testCts.Cancel();
                await Task.Delay(1000); // Give components time to shut down
            }
        }

        // Helper method to find an available TCP port
        private int FindAvailablePort()
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            return ((IPEndPoint)socket.LocalEndPoint).Port;
        }
    }
} 