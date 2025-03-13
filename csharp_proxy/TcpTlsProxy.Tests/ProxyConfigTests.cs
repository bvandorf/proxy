using System;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TcpTlsProxy;

namespace TcpTlsProxy.Tests
{
    [TestClass]
    public class ProxyConfigTests
    {
        [TestMethod]
        public void ProxyConfig_DefaultValues_ShouldBeCorrect()
        {
            // Arrange & Act
            var config = new ProxyConfig();
            
            // Assert
            Assert.AreEqual("0.0.0.0:8080", config.ListenerAddress);
            Assert.AreEqual("www.google.com:443", config.TargetAddress);
            Assert.IsFalse(config.ClientTls);
            Assert.AreEqual("", config.ServerCertSubject);
            Assert.AreEqual(StoreLocation.CurrentUser, config.ServerCertStoreLocation);
            Assert.AreEqual(StoreName.My, config.ServerCertStoreName);
            Assert.IsFalse(config.ClientAuth);
            Assert.AreEqual("", config.CACertSubject);
            Assert.AreEqual(StoreLocation.CurrentUser, config.CACertStoreLocation);
            Assert.AreEqual(StoreName.Root, config.CACertStoreName);
            Assert.IsTrue(config.TargetTls);
            Assert.AreEqual("", config.ClientCertSubject);
            Assert.AreEqual(StoreLocation.CurrentUser, config.ClientCertStoreLocation);
            Assert.AreEqual(StoreName.My, config.ClientCertStoreName);
            Assert.IsTrue(config.InsecureSkipVerify);
            Assert.AreEqual(30000, config.DialTimeout);
            Assert.IsFalse(config.OverrideTargetForCONNECT);
        }

        [TestMethod]
        public void ProxyConfig_CustomValues_ShouldBeCorrect()
        {
            // Arrange
            var config = new ProxyConfig
            {
                ListenerAddress = "127.0.0.1:9090",
                TargetAddress = "example.com:8443",
                ClientTls = true,
                ServerCertSubject = "CN=TestServer",
                ServerCertStoreLocation = StoreLocation.LocalMachine,
                ServerCertStoreName = StoreName.TrustedPeople,
                ClientAuth = true,
                CACertSubject = "CN=TestCA",
                CACertStoreLocation = StoreLocation.LocalMachine,
                CACertStoreName = StoreName.CertificateAuthority,
                TargetTls = false,
                ClientCertSubject = "CN=TestClient",
                ClientCertStoreLocation = StoreLocation.LocalMachine,
                ClientCertStoreName = StoreName.TrustedPeople,
                InsecureSkipVerify = false,
                DialTimeout = 15000,
                OverrideTargetForCONNECT = true
            };
            
            // Assert
            Assert.AreEqual("127.0.0.1:9090", config.ListenerAddress);
            Assert.AreEqual("example.com:8443", config.TargetAddress);
            Assert.IsTrue(config.ClientTls);
            Assert.AreEqual("CN=TestServer", config.ServerCertSubject);
            Assert.AreEqual(StoreLocation.LocalMachine, config.ServerCertStoreLocation);
            Assert.AreEqual(StoreName.TrustedPeople, config.ServerCertStoreName);
            Assert.IsTrue(config.ClientAuth);
            Assert.AreEqual("CN=TestCA", config.CACertSubject);
            Assert.AreEqual(StoreLocation.LocalMachine, config.CACertStoreLocation);
            Assert.AreEqual(StoreName.CertificateAuthority, config.CACertStoreName);
            Assert.IsFalse(config.TargetTls);
            Assert.AreEqual("CN=TestClient", config.ClientCertSubject);
            Assert.AreEqual(StoreLocation.LocalMachine, config.ClientCertStoreLocation);
            Assert.AreEqual(StoreName.TrustedPeople, config.ClientCertStoreName);
            Assert.IsFalse(config.InsecureSkipVerify);
            Assert.AreEqual(15000, config.DialTimeout);
            Assert.IsTrue(config.OverrideTargetForCONNECT);
        }

        [TestMethod]
        public void ProxyConfig_InternalCertificateProperties_InitiallyNull()
        {
            // Arrange & Act
            var config = new ProxyConfig();
            
            // Assert - using reflection to access internal properties
            var type = typeof(ProxyConfig);
            var serverCertProperty = type.GetProperty("ServerCertificate", 
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            var clientCertProperty = type.GetProperty("ClientCertificate", 
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            var caCertProperty = type.GetProperty("CACertificate", 
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            var clientValidationProperty = type.GetProperty("ClientCertValidationCallback", 
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            var serverValidationProperty = type.GetProperty("ServerCertValidationCallback", 
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            
            Assert.IsNotNull(serverCertProperty, "ServerCertificate property should exist");
            Assert.IsNotNull(clientCertProperty, "ClientCertificate property should exist");
            Assert.IsNotNull(caCertProperty, "CACertificate property should exist");
            Assert.IsNotNull(clientValidationProperty, "ClientCertValidationCallback property should exist");
            Assert.IsNotNull(serverValidationProperty, "ServerCertValidationCallback property should exist");
            
            Assert.IsNull(serverCertProperty.GetValue(config), "ServerCertificate should be null initially");
            Assert.IsNull(clientCertProperty.GetValue(config), "ClientCertificate should be null initially");
            Assert.IsNull(caCertProperty.GetValue(config), "CACertificate should be null initially");
            Assert.IsNull(clientValidationProperty.GetValue(config), "ClientCertValidationCallback should be null initially");
            Assert.IsNull(serverValidationProperty.GetValue(config), "ServerCertValidationCallback should be null initially");
        }
    }
} 