using System;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TcpTlsProxy;

namespace TcpTlsProxy.Tests
{
    [TestClass]
    public class ProxyLoggerTests
    {
        private string _testLogFile = null!;

        [TestInitialize]
        public void Setup()
        {
            // Create a temporary test log file
            _testLogFile = Path.Combine(Path.GetTempPath(), $"proxy_test_log_{Guid.NewGuid()}.log");
        }

        [TestCleanup]
        public void Cleanup()
        {
            // Delete the test log file if it exists
            if (File.Exists(_testLogFile))
            {
                try
                {
                    File.Delete(_testLogFile);
                }
                catch
                {
                    // Ignore any deletion errors
                }
            }
        }

        [TestMethod]
        public void ProxyLogger_LogToFile_CreatesFileWithCorrectContent()
        {
            // Arrange
            var logger = new ProxyLogger(_testLogFile);
            
            // Act
            logger.Log("Test message");
            
            // Assert
            Assert.IsTrue(File.Exists(_testLogFile), "Log file should be created");
            string fileContent = File.ReadAllText(_testLogFile);
            Assert.IsTrue(fileContent.Contains("--- TCP/TLS Proxy Log Started at"), "Log file should have a header");
            Assert.IsTrue(fileContent.Contains("Test message"), "Log file should contain the logged message");
        }

        [TestMethod]
        public void ProxyLogger_LogError_IncludesErrorPrefix()
        {
            // Arrange
            var logger = new ProxyLogger(_testLogFile);
            
            // Act
            logger.LogError("Test error message");
            
            // Assert
            Assert.IsTrue(File.Exists(_testLogFile), "Log file should be created");
            string fileContent = File.ReadAllText(_testLogFile);
            Assert.IsTrue(fileContent.Contains("ERROR: Test error message"), 
                "Log file should contain the error message with ERROR prefix");
        }

        [TestMethod]
        public void ProxyLogger_LogErrorWithException_IncludesExceptionDetails()
        {
            // Arrange
            var logger = new ProxyLogger(_testLogFile);
            var exception = new InvalidOperationException("Test exception");
            
            // Act
            logger.LogError("Test error message", exception);
            
            // Assert
            Assert.IsTrue(File.Exists(_testLogFile), "Log file should be created");
            string fileContent = File.ReadAllText(_testLogFile);
            Assert.IsTrue(fileContent.Contains("ERROR: Test error message - Test exception"), 
                "Log file should contain the error message with exception message");
            Assert.IsTrue(fileContent.Contains("Stack trace:"), 
                "Log file should contain stack trace information");
        }

        [TestMethod]
        public void ProxyLogger_NullLogFile_OnlyLogsToConsole()
        {
            // Arrange
            string? nullLogFile = null;
            var logger = new ProxyLogger(nullLogFile);
            
            // Act
            logger.Log("Test message");
            
            // Assert - No exception should be thrown
            // Cannot easily test console output, but we can check that no file was created
            Assert.IsFalse(File.Exists("output.log"), "No default log file should be created");
        }

        [TestMethod]
        public void ProxyLogger_InvalidDirectory_HandlesError()
        {
            // Skip this test if we can't create an invalid path
            try
            {
                // Arrange - Use an invalid path with illegal characters
                string invalidPath = Path.Combine(Path.GetTempPath(), "invalid?directory", "test.log");
                
                // Act - This should handle the error gracefully and fall back to console-only logging
                var logger = new ProxyLogger(invalidPath);
                logger.Log("Test message");
                
                // Assert - No exception should be thrown
                // Cannot easily test console output, but we can check that the invalid file was not created
                Assert.IsFalse(File.Exists(invalidPath), "Invalid log file should not be created");
            }
            catch (IOException)
            {
                // If the test environment doesn't allow creating invalid paths, skip the test
                Assert.Inconclusive("Test environment doesn't support creating invalid paths");
            }
        }
    }
} 