using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using TcpTlsProxy;

namespace TcpTlsProxy.Tests
{
    [TestClass]
    public class TcpProxyTests
    {
        private Mock<ProxyLogger> _mockLogger = null!;
        private ProxyConfig _config = null!;
        private string _testLogFile = "test.log";
        
        [TestInitialize]
        public void Setup()
        {
            _mockLogger = new Mock<ProxyLogger>("test.log");
            _config = new ProxyConfig
            {
                ListenerAddress = "127.0.0.1:8080",
                TargetAddress = "example.com:443",
                ClientTls = false,
                TargetTls = true
            };
        }
        
        [TestMethod]
        public void TcpProxy_Constructor_ValidConfig_CreatesInstance()
        {
            // Arrange & Act
            var proxy = new TcpProxy(_config, _mockLogger.Object);
            
            // Assert
            Assert.IsNotNull(proxy);
        }
        
        [TestMethod]
        public void TcpProxy_Constructor_NullConfig_ThrowsException()
        {
            // Arrange & Act & Assert
            Assert.ThrowsException<ArgumentNullException>(() => new TcpProxy(null!, _mockLogger.Object));
        }
        
        [TestMethod]
        public void TcpProxy_DataProcessors_InitiallyNull()
        {
            // Arrange & Act
            var proxy = new TcpProxy(_config, _mockLogger.Object);
            
            // Assert
            Assert.IsNull(proxy.ClientToServerHandler);
            Assert.IsNull(proxy.ServerToClientHandler);
        }
        
        [TestMethod]
        public void TcpProxy_SetDataProcessors_SetsProperties()
        {
            // Arrange
            var proxy = new TcpProxy(_config, _mockLogger.Object);
            
            // Act
            DataProcessor clientToServerHandler = (clientId, data) => (data, true);
            DataProcessor serverToClientHandler = (clientId, data) => (data, true);
            
            proxy.ClientToServerHandler = clientToServerHandler;
            proxy.ServerToClientHandler = serverToClientHandler;
            
            // Assert
            Assert.AreEqual(clientToServerHandler, proxy.ClientToServerHandler);
            Assert.AreEqual(serverToClientHandler, proxy.ServerToClientHandler);
        }
        
        [TestMethod]
        public void TcpProxy_Stop_DoesNotThrowException()
        {
            // Arrange
            var proxy = new TcpProxy(_config, _mockLogger.Object);
            
            // Act & Assert
            try
            {
                proxy.Stop();
                Assert.IsTrue(true); // If we get here, no exception was thrown
            }
            catch (Exception ex)
            {
                Assert.Fail($"Exception was thrown: {ex.Message}");
            }
        }
        
        [TestMethod]
        public async Task TcpProxy_SendCustomResponseAsync_CallsLogMethod()
        {
            // Arrange
            var logger = new ProxyLogger(_testLogFile);
            var proxy = new TcpProxy(_config, logger);
            var mockStream = new Mock<Stream>();
            mockStream.Setup(s => s.WriteAsync(It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            
            byte[] testData = new byte[] { 1, 2, 3, 4 };
            
            // Act
            await proxy.SendCustomResponseAsync(testData, mockStream.Object, CancellationToken.None);
            
            // Assert
            mockStream.Verify(s => s.WriteAsync(It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<int>(), It.IsAny<CancellationToken>()), Times.Once);
            
            // Check if the log file contains the expected message
            if (File.Exists(_testLogFile))
            {
                string logContent = File.ReadAllText(_testLogFile);
                Assert.IsTrue(logContent.Contains("Sent custom response: 4 bytes"), 
                    "Log should contain message about sent custom response");
            }
        }
    }
} 