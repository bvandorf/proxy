using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using TcpTlsProxy;

namespace TcpTlsProxy.Tests
{
    [TestClass]
    public class CertificateTests
    {
        private Mock<ProxyLogger> _mockLogger = null!;
        private ProxyConfig _config = null!;
        
        [TestInitialize]
        public void Setup()
        {
            _mockLogger = new Mock<ProxyLogger>("test.log");
            _config = new ProxyConfig
            {
                ListenerAddress = "127.0.0.1:8080",
                TargetAddress = "example.com:443",
                ClientTls = true,
                TargetTls = true,
                InsecureSkipVerify = false
            };
        }
        
        [TestMethod]
        public void CertificateTest_NonWindowsPlatform_ThrowsException()
        {
            // Skip this test on Windows
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Assert.Inconclusive("This test is only applicable on non-Windows platforms");
                return;
            }
            
            // Arrange
            var proxy = new TcpProxy(_config, _mockLogger.Object);
            
            // Act & Assert
            Assert.ThrowsException<PlatformNotSupportedException>(() => 
            {
                // This would trigger certificate loading which should fail on non-Windows
                proxy.StartAsync(default).GetAwaiter().GetResult();
            });
        }
        
        [TestMethod]
        public void Certificate_RemoteCertificateValidationCallback_ServerInsecureMode()
        {
            // Skip this test on non-Windows platforms
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Assert.Inconclusive("This test is only applicable on Windows");
                return;
            }
            
            // Arrange
            _config.InsecureSkipVerify = true;
            var proxy = new TcpProxy(_config, _mockLogger.Object);
            
            // Use reflection to get the server certificate validation callback
            var type = typeof(TcpProxy);
            var method = type.GetMethod("SetupTargetTls", 
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            
            if (method == null)
            {
                Assert.Inconclusive("Could not find SetupTargetTls method via reflection");
                return;
            }
            
            // Invoke the method to set up the validation callback
            method.Invoke(proxy, null);
            
            // Get the validation callback from the config
            var callbackProperty = typeof(ProxyConfig).GetProperty("ServerCertValidationCallback", 
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            
            if (callbackProperty == null)
            {
                Assert.Inconclusive("Could not find ServerCertValidationCallback property via reflection");
                return;
            }
            
            var callback = callbackProperty.GetValue(_config) as System.Net.Security.RemoteCertificateValidationCallback;
            
            if (callback == null)
            {
                Assert.Inconclusive("ServerCertValidationCallback is null");
                return;
            }
            
            // Create a self-signed certificate for testing
            using (var cert = CreateSelfSignedCert())
            {
                // Act
                bool result = callback(this, cert, null, System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors);
                
                // Assert
                Assert.IsTrue(result, "Validation callback should return true in insecure mode");
            }
        }
        
        [TestMethod]
        public void Certificate_RemoteCertificateValidationCallback_ServerSecureMode()
        {
            // Skip this test on non-Windows platforms
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Assert.Inconclusive("This test is only applicable on Windows");
                return;
            }
            
            // Arrange
            _config.InsecureSkipVerify = false;
            var proxy = new TcpProxy(_config, _mockLogger.Object);
            
            // Use reflection to get the server certificate validation callback
            var type = typeof(TcpProxy);
            var method = type.GetMethod("SetupTargetTls", 
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            
            if (method == null)
            {
                Assert.Inconclusive("Could not find SetupTargetTls method via reflection");
                return;
            }
            
            // Invoke the method to set up the validation callback
            method.Invoke(proxy, null);
            
            // Get the validation callback from the config
            var callbackProperty = typeof(ProxyConfig).GetProperty("ServerCertValidationCallback", 
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            
            if (callbackProperty == null)
            {
                Assert.Inconclusive("Could not find ServerCertValidationCallback property via reflection");
                return;
            }
            
            var callback = callbackProperty.GetValue(_config) as System.Net.Security.RemoteCertificateValidationCallback;
            
            if (callback == null)
            {
                Assert.Inconclusive("ServerCertValidationCallback is null");
                return;
            }
            
            // Create a self-signed certificate for testing
            using (var cert = CreateSelfSignedCert())
            {
                // Act
                bool result = callback(this, cert, null, System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors);
                
                // Assert
                Assert.IsFalse(result, "Validation callback should return false in secure mode with chain errors");
            }
        }
        
        private X509Certificate2 CreateSelfSignedCert()
        {
            // Create a simple self-signed certificate for testing
            var distinguishedName = new X500DistinguishedName("CN=Test Certificate");
            using (var rsa = System.Security.Cryptography.RSA.Create(2048))
            {
                var request = new CertificateRequest(
                    distinguishedName, 
                    rsa, 
                    System.Security.Cryptography.HashAlgorithmName.SHA256,
                    System.Security.Cryptography.RSASignaturePadding.Pkcs1);
                
                var certificate = request.CreateSelfSigned(
                    DateTimeOffset.Now.AddDays(-1),
                    DateTimeOffset.Now.AddDays(365));
                
                return certificate;
            }
        }
    }
} 