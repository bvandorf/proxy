using System;
using System.IO;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TcpTlsProxy.Protocols;

namespace TcpTlsProxy.Tests
{
    [TestClass]
    public class DataLoggerTests
    {
        private class MockLogger : ProxyLogger
        {
            public MockLogger() : base(null) { }
            
            public System.Collections.Generic.List<string> LoggedMessages { get; } = new System.Collections.Generic.List<string>();
            
            public override void Log(string message)
            {
                LoggedMessages.Add(message);
            }
        }
        
        [TestMethod]
        public void DataLogger_LogsTextData_Correctly()
        {
            // Arrange
            var mockLogger = new MockLogger();
            var textData = Encoding.UTF8.GetBytes("This is plain text for testing");
            var clientId = "client1";
            
            // Act
            DataLogger.LogData(mockLogger, "Received", textData, clientId);
            
            // Assert
            Assert.IsTrue(mockLogger.LoggedMessages.Count >= 3, "Should have logged at least 3 messages");
            
            // Check basic log entry
            Assert.IsTrue(mockLogger.LoggedMessages[0].Contains("Received"), "Should contain prefix");
            Assert.IsTrue(mockLogger.LoggedMessages[0].Contains("client1"), "Should contain client ID");
            
            // Check hex representation
            Assert.IsTrue(mockLogger.LoggedMessages[1].StartsWith("Hex:"), "Should contain hex representation");
            string expectedHexStart = BitConverter.ToString(textData, 0, Math.Min(10, textData.Length)).Replace("-", " ");
            Assert.IsTrue(mockLogger.LoggedMessages[1].Contains(expectedHexStart), "Should contain correct hex values");
            
            // Check text representation
            Assert.IsTrue(mockLogger.LoggedMessages[2].StartsWith("Text:"), "Should contain text representation");
            Assert.IsTrue(mockLogger.LoggedMessages[2].Contains("This is plain text"), "Should contain correct text");
        }
        
        [TestMethod]
        public void DataLogger_LogsBinaryData_Correctly()
        {
            // Arrange
            var mockLogger = new MockLogger();
            // Create binary data that doesn't look like text
            var binaryData = new byte[100];
            var random = new Random(42); // Fixed seed for reproducibility
            random.NextBytes(binaryData);
            var clientId = "client2";
            
            // Act
            DataLogger.LogData(mockLogger, "Received binary", binaryData, clientId);
            
            // Assert
            Assert.IsTrue(mockLogger.LoggedMessages.Count >= 3, "Should have logged at least 3 messages");
            
            // Check binary notation
            Assert.IsTrue(mockLogger.LoggedMessages[2].Contains("[Binary data"), "Should identify as binary data");
        }
        
        [TestMethod]
        public void DataLogger_HandlesControlCharacters_Correctly()
        {
            // Arrange
            var mockLogger = new MockLogger();
            // Text with control characters
            var textWithControls = "Hello\u0001World\u0002\u0003Testing";
            var data = Encoding.UTF8.GetBytes(textWithControls);
            var clientId = "client3";
            
            // Act
            DataLogger.LogData(mockLogger, "Received with controls", data, clientId);
            
            // Assert
            Assert.IsTrue(mockLogger.LoggedMessages.Count >= 3, "Should have logged at least 3 messages");
            
            // Check for control character cleanup
            string textLog = mockLogger.LoggedMessages[2];
            Assert.IsTrue(textLog.Contains("[01]"), "Should convert control chars to [XX] format");
            Assert.IsTrue(textLog.Contains("[02]"), "Should convert control chars to [XX] format");
            Assert.IsTrue(textLog.Contains("[03]"), "Should convert control chars to [XX] format");
        }
        
        [TestMethod]
        public void DataLogger_HandlesTruncation_ForLargeData()
        {
            // Arrange
            var mockLogger = new MockLogger();
            // Create large text data (larger than MaxTextBytes constant in DataLogger)
            var largeText = new StringBuilder();
            for (int i = 0; i < 2000; i++)
            {
                largeText.Append($"Line {i} of test data. ");
            }
            var data = Encoding.UTF8.GetBytes(largeText.ToString());
            var clientId = "client4";
            
            // Act
            DataLogger.LogData(mockLogger, "Received large data", data, clientId);
            
            // Assert
            Assert.IsTrue(mockLogger.LoggedMessages.Count >= 3, "Should have logged at least 3 messages");
            
            // Check for truncation
            string textLog = mockLogger.LoggedMessages[2];
            Assert.IsTrue(textLog.Contains("truncated"), "Should indicate that text was truncated");
            Assert.IsTrue(textLog.EndsWith("..."), "Should end with ellipsis for truncated text");
        }
        
        [TestMethod]
        public void DataLogger_HandlesInvalidUtf8_Gracefully()
        {
            // Arrange
            var mockLogger = new MockLogger();
            // Create invalid UTF-8 sequence
            var invalidUtf8 = new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0xC0, 0xC1, 0xF5, 0xF6 }; // "Hello" followed by invalid UTF-8
            var clientId = "client5";
            
            // Act
            DataLogger.LogData(mockLogger, "Received invalid UTF-8", invalidUtf8, clientId);
            
            // Assert
            Assert.IsTrue(mockLogger.LoggedMessages.Count >= 3, "Should have logged at least 3 messages");
            
            // Should still log hex representation correctly
            Assert.IsTrue(mockLogger.LoggedMessages[1].StartsWith("Hex:"), "Should contain hex representation");
            string expectedHexStart = BitConverter.ToString(invalidUtf8, 0, Math.Min(5, invalidUtf8.Length)).Replace("-", " ");
            Assert.IsTrue(mockLogger.LoggedMessages[1].Contains(expectedHexStart), "Should contain correct hex values");
        }
    }
} 