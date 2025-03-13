using System;
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
    public class ProxyChainTests
    {
        [TestMethod]
        public async Task BasicProxyTest_TcpToTcpTarget_DataFlowsCorrectly()
        {
            // Skip this test on CI environments
            if (Environment.GetEnvironmentVariable("CI") == "true")
            {
                Assert.Inconclusive("Skipping network tests in CI environment");
                return;
            }

            // Find available ports for our test components
            int proxyPort = FindAvailablePort();
            int targetServerPort = FindAvailablePort();
            
            // Create a cancellation token source that will cancel all components
            using var testCts = new CancellationTokenSource();
            testCts.CancelAfter(TimeSpan.FromSeconds(30)); // Timeout after 30 seconds
            
            try
            {
                // 1. Create a mock TCP echo server
                var targetServerTask = RunMockTcpServerAsync(targetServerPort, testCts.Token);
                
                // Wait for server to start
                await Task.Delay(500);
                
                // 2. Create a simple TCP proxy
                var proxyConfig = new ProxyConfig
                {
                    ListenerAddress = $"127.0.0.1:{proxyPort}",
                    TargetAddress = $"127.0.0.1:{targetServerPort}",
                    ClientTls = false, // TCP only for incoming connections
                    TargetTls = false  // TCP only for outgoing connections
                };
                
                var proxyLogger = new ProxyLogger(Path.Combine(Path.GetTempPath(), $"proxy_{Guid.NewGuid()}.log"));
                var proxy = new TcpProxy(proxyConfig, proxyLogger);
                
                // Add a data processor to verify data flows through
                bool dataPassedThroughProxy = false;
                proxy.ClientToServerHandler = (clientId, data) =>
                {
                    string text = Encoding.UTF8.GetString(data);
                    Console.WriteLine($"Proxy received: {text}");
                    dataPassedThroughProxy = true;
                    return (data, true);
                };
                
                var proxyTask = Task.Run(async () => 
                {
                    try 
                    {
                        await proxy.StartAsync(testCts.Token);
                    }
                    catch (OperationCanceledException) { /* Expected */ }
                    catch (Exception ex) 
                    {
                        Console.WriteLine($"Proxy error: {ex.Message}");
                    }
                });
                
                // Wait for proxy to start
                await Task.Delay(500);
                
                // 3. Create and connect a TCP client to the proxy
                using var client = new TcpClient();
                await client.ConnectAsync("127.0.0.1", proxyPort);
                
                // 4. Send test data and verify it's received by the target
                string testMessage = "Hello through proxy!";
                byte[] testData = Encoding.UTF8.GetBytes(testMessage);
                await client.GetStream().WriteAsync(testData);
                
                // Wait to ensure data is processed
                await Task.Delay(1000);
                
                // Check that data was processed by proxy
                Assert.IsTrue(dataPassedThroughProxy, "Data should have passed through proxy");
                
                // 5. Read response from target
                byte[] responseBuffer = new byte[1024];
                var readTask = client.GetStream().ReadAsync(responseBuffer, 0, responseBuffer.Length);
                
                // Use timeout to prevent test from hanging
                if (await Task.WhenAny(readTask, Task.Delay(5000)) == readTask)
                {
                    int bytesRead = await readTask;
                    string response = Encoding.UTF8.GetString(responseBuffer, 0, bytesRead);
                    
                    // Verify the response contains our echo
                    Assert.IsTrue(response.Contains(testMessage), 
                        "Response should contain the original message");
                    
                    Console.WriteLine($"Received response: {response}");
                }
                else
                {
                    Assert.Fail("Timeout waiting for response through proxy");
                }
            }
            finally
            {
                // Cleanup
                testCts.Cancel();
                await Task.Delay(1000); // Give components time to shut down
            }
        }

        [TestMethod]
        public async Task TlsProxyTest_ClientToTlsProxy_DataFlowsCorrectly()
        {
            // Skip this test on CI environments
            if (Environment.GetEnvironmentVariable("CI") == "true")
            {
                Assert.Inconclusive("Skipping network tests in CI environment");
                return;
            }

            // Find available ports for our test components
            int proxyPort = FindAvailablePort();
            int targetServerPort = FindAvailablePort();
            
            // Create self-signed certificates for testing
            var serverCert = CreateSelfSignedCertificate("localhost");
            
            // Create a cancellation token source that will cancel all components
            using var testCts = new CancellationTokenSource();
            testCts.CancelAfter(TimeSpan.FromSeconds(30)); // Timeout after 30 seconds
            
            try
            {
                // 1. Create a mock TLS echo server
                var targetServerTask = RunMockTlsServerAsync(targetServerPort, serverCert, testCts.Token);
                
                // Wait for server to start
                await Task.Delay(500);
                
                // 2. Create a TLS proxy
                var proxyConfig = new ProxyConfig
                {
                    ListenerAddress = $"127.0.0.1:{proxyPort}",
                    TargetAddress = $"127.0.0.1:{targetServerPort}",
                    ClientTls = true,    // TLS for incoming connections
                    TargetTls = true,    // TLS for outgoing connections
                    InsecureSkipVerify = true // Skip certificate validation for testing
                };
                
                var proxyLogger = new ProxyLogger(Path.Combine(Path.GetTempPath(), $"proxy_{Guid.NewGuid()}.log"));
                var proxy = new TcpProxy(proxyConfig, proxyLogger);
                
                // Set test certificates
                proxy.SetServerCertificateForTesting(serverCert);
                
                // Add a data processor to verify data flows through
                bool dataPassedThroughProxy = false;
                proxy.ClientToServerHandler = (clientId, data) =>
                {
                    string text = Encoding.UTF8.GetString(data);
                    Console.WriteLine($"Proxy received: {text}");
                    dataPassedThroughProxy = true;
                    return (data, true);
                };
                
                var proxyTask = Task.Run(async () => 
                {
                    try 
                    {
                        await proxy.StartAsync(testCts.Token);
                    }
                    catch (OperationCanceledException) { /* Expected */ }
                    catch (Exception ex) 
                    {
                        Console.WriteLine($"Proxy error: {ex.Message}");
                    }
                });
                
                // Wait for proxy to start
                await Task.Delay(500);
                
                // 3. Create and connect a TLS client to the proxy
                using var client = new TcpClient();
                await client.ConnectAsync("127.0.0.1", proxyPort);
                
                using var sslStream = new SslStream(
                    client.GetStream(), 
                    false);
                
                await sslStream.AuthenticateAsClientAsync(
                    new SslClientAuthenticationOptions 
                    { 
                        TargetHost = "localhost",
                        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                        RemoteCertificateValidationCallback = (sender, certificate, chain, errors) => true
                    });
                
                // 4. Send test data and verify it's received by the target
                string testMessage = "Hello through TLS proxy!";
                byte[] testData = Encoding.UTF8.GetBytes(testMessage);
                await sslStream.WriteAsync(testData);
                
                // Wait to ensure data is processed
                await Task.Delay(1000);
                
                // Check that data was processed by proxy
                Assert.IsTrue(dataPassedThroughProxy, "Data should have passed through proxy");
                
                // 5. Read response from target
                byte[] responseBuffer = new byte[1024];
                var readTask = sslStream.ReadAsync(responseBuffer, 0, responseBuffer.Length);
                
                // Use timeout to prevent test from hanging
                if (await Task.WhenAny(readTask, Task.Delay(5000)) == readTask)
                {
                    int bytesRead = await readTask;
                    string response = Encoding.UTF8.GetString(responseBuffer, 0, bytesRead);
                    
                    // Verify the response contains our echo
                    Assert.IsTrue(response.Contains(testMessage), 
                        "Response should contain the original message");
                    
                    Console.WriteLine($"Received TLS response: {response}");
                }
                else
                {
                    Assert.Fail("Timeout waiting for response through TLS proxy");
                }
            }
            finally
            {
                // Cleanup
                testCts.Cancel();
                await Task.Delay(1000); // Give components time to shut down
            }
        }

        // Helper to run a mock TCP server that echoes back received data
        private async Task RunMockTcpServerAsync(int port, CancellationToken cancellationToken)
        {
            var listener = new TcpListener(IPAddress.Loopback, port);
            listener.Start();
            
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    var client = await listener.AcceptTcpClientAsync();
                    
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            using (client)
                            {
                                var stream = client.GetStream();
                                byte[] buffer = new byte[1024];
                                int bytesRead;
                                
                                while ((bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                                {
                                    Console.WriteLine($"Target server received: {Encoding.UTF8.GetString(buffer, 0, bytesRead)}");
                                    
                                    // Echo response with prefix
                                    string response = $"ECHO: {Encoding.UTF8.GetString(buffer, 0, bytesRead)}";
                                    byte[] responseData = Encoding.UTF8.GetBytes(response);
                                    await stream.WriteAsync(responseData);
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Target server client error: {ex.Message}");
                        }
                    });
                }
            }
            finally
            {
                listener.Stop();
            }
        }

        // Helper method to run a mock TLS server that echoes back received data
        private async Task RunMockTlsServerAsync(int port, X509Certificate2 serverCertificate, CancellationToken cancellationToken)
        {
            var listener = new TcpListener(IPAddress.Loopback, port);
            listener.Start();
            
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    var client = await listener.AcceptTcpClientAsync();
                    
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            using (client)
                            {
                                using var sslStream = new SslStream(client.GetStream(), false);
                                await sslStream.AuthenticateAsServerAsync(
                                    new SslServerAuthenticationOptions
                                    {
                                        ServerCertificate = serverCertificate,
                                        ClientCertificateRequired = false,
                                        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
                                    });
                                
                                byte[] buffer = new byte[16384];
                                int bytesRead;
                                
                                while ((bytesRead = await sslStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                                {
                                    string received = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                                    Console.WriteLine($"TLS Target server received: {received}");
                                    
                                    // Echo response with prefix
                                    string response = $"ECHO-TLS: {received}";
                                    byte[] responseData = Encoding.UTF8.GetBytes(response);
                                    await sslStream.WriteAsync(responseData);
                                    await sslStream.FlushAsync();
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"TLS Target server client error: {ex.Message}");
                        }
                    });
                }
            }
            finally
            {
                listener.Stop();
            }
        }

        // Helper to create a self-signed certificate for testing
        private X509Certificate2 CreateSelfSignedCertificate(string subjectName)
        {
            // Generate a new RSA key
            using var rsa = RSA.Create(2048);
            
            // Create certificate request
            var certRequest = new CertificateRequest(
                $"CN={subjectName}",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            
            // Add usage extensions
            certRequest.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                    critical: true));
            
            certRequest.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(
                    new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, // Server authentication
                    critical: true));
            
            // Generate certificate
            var certificate = certRequest.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddDays(365));
            
            // Ensure the private key is exportable
            var certWithExportableKey = new X509Certificate2(
                certificate.Export(X509ContentType.Pfx),
                (string)null!,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
            
            return certWithExportableKey;
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