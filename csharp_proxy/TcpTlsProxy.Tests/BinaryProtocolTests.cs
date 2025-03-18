using System;
using System.IO;
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TcpTlsProxy.Protocols;

namespace TcpTlsProxy.Tests
{
    [TestClass]
    public class BinaryProtocolTests
    {
        [TestMethod]
        public void BinaryProtocol_Parse_ValidData_ShouldParseCorrectly()
        {
            // Arrange
            // The binary data from the example: 00 00 00 86 00 00 00 06 00 00 00 26 00 06 4C 54 2D32 32 33 00 0B 31 30 2E 31 30 2E 32 35 32 00 0F 43 6F 76 61 6E 74 61 67 65 63 75 2E 72 67
            byte[] testData = new byte[]
            {
                0x00, 0x00, 0x00, 0x86, // Total length (134)
                0x00, 0x00, 0x00, 0x06, // Message type (6)
                0x00, 0x00, 0x00, 0x26, // Data section length (38)
                0x00, 0x06, // Field 1 length (6)
                0x4C, 0x54, 0x2D, 0x32, 0x33, 0x33, // Field 1 data ("LT-233")
                0x00, 0x0B, // Field 2 length (11)
                0x31, 0x30, 0x2E, 0x31, 0x30, 0x2E, 0x35, 0x2E, 0x32, 0x35, 0x32, // Field 2 data ("10.10.5.252")
                0x00, 0x0F, // Field 3 length (15)
                0x43, 0x6F, 0x76, 0x61, 0x6E, 0x74, 0x61, 0x67, 0x65, 0x63, 0x75, 0x2E, 0x6F, 0x72, 0x67 // Field 3 data ("Covantagecu.org")
            };

            // Act
            BinaryProtocol result = BinaryProtocol.Parse(testData);

            // Assert
            Assert.AreEqual(134, result.TotalLength);
            Assert.AreEqual(6, result.MessageType);
            Assert.AreEqual(38, result.DataSectionLength);
            
            Assert.AreEqual(3, result.Fields.Count);
            Assert.AreEqual("LT-233", result.Fields[0]);
            Assert.AreEqual("10.10.5.252", result.Fields[1]);
            Assert.AreEqual("Covantagecu.org", result.Fields[2]);
        }

        [TestMethod]
        public void BinaryProtocol_CreateResponse_ShouldCreateValidResponse()
        {
            // Arrange
            BinaryProtocol original = new BinaryProtocol(6, "LT-233", "10.10.5.252", "Covantagecu.org");

            // Act
            BinaryProtocol response = original.CreateResponse();

            // Assert
            Assert.AreEqual(106, response.MessageType); // 6 + 100
            Assert.AreEqual(4, response.Fields.Count); // prefix + 3 original fields
            Assert.AreEqual("Response to: ", response.Fields[0]);
            Assert.AreEqual("LT-233", response.Fields[1]);
            Assert.AreEqual("10.10.5.252", response.Fields[2]);
            Assert.AreEqual("Covantagecu.org", response.Fields[3]);
        }

        [TestMethod]
        public void BinaryProtocol_ToByteArray_ShouldGenerateCorrectBinaryData()
        {
            // Arrange
            BinaryProtocol protocol = new BinaryProtocol(6, "LT-233", "10.10.5.252", "Covantagecu.org");

            // Act
            byte[] result = protocol.ToByteArray();

            // Assert
            Assert.AreEqual(12 + 2 + 6 + 2 + 11 + 2 + 15, result.Length); // Header + field lengths + field data
            
            // Parse the generated binary data to verify it's correct
            BinaryProtocol parsedResult = BinaryProtocol.Parse(result);
            
            Assert.AreEqual(protocol.MessageType, parsedResult.MessageType);
            Assert.AreEqual(protocol.Fields.Count, parsedResult.Fields.Count);
            
            for (int i = 0; i < protocol.Fields.Count; i++)
            {
                Assert.AreEqual(protocol.Fields[i], parsedResult.Fields[i]);
            }
        }

        [TestMethod]
        public void BinaryProtocol_RoundTrip_ShouldPreserveData()
        {
            // Arrange
            BinaryProtocol original = new BinaryProtocol(42, "Hostname", "192.168.1.100", "example.com");

            // Act
            byte[] binaryData = original.ToByteArray();
            BinaryProtocol result = BinaryProtocol.Parse(binaryData);

            // Assert
            Assert.AreEqual(original.MessageType, result.MessageType);
            Assert.AreEqual(original.Fields.Count, result.Fields.Count);
            
            for (int i = 0; i < original.Fields.Count; i++)
            {
                Assert.AreEqual(original.Fields[i], result.Fields[i]);
            }
        }
        
        [TestMethod]
        public void BinaryProtocol_Parse_EmptyData_ShouldHandleGracefully()
        {
            // Arrange
            byte[] emptyData = new byte[0];
            
            // Act & Assert
            try
            {
                BinaryProtocol result = BinaryProtocol.Parse(emptyData);
                // If no exception is thrown, ensure we have default/empty values
                Assert.AreEqual(0, result.Fields.Count);
            }
            catch (Exception ex)
            {
                Assert.Fail($"Should handle empty data gracefully, but threw: {ex.Message}");
            }
        }
        
        [TestMethod]
        public void BinaryProtocol_Parse_IncompleteHeader_ShouldHandleGracefully()
        {
            // Arrange - only 6 bytes, not enough for the 12-byte header
            byte[] incompleteData = new byte[] { 0x00, 0x00, 0x00, 0x06, 0x00, 0x00 };
            
            // Act & Assert
            try
            {
                BinaryProtocol result = BinaryProtocol.Parse(incompleteData);
                // The parser should not throw but may return incomplete results
                Assert.AreEqual(0, result.Fields.Count);
            }
            catch (Exception ex)
            {
                Assert.Fail($"Should handle incomplete header gracefully, but threw: {ex.Message}");
            }
        }
        
        [TestMethod]
        public void BinaryProtocol_WithSpecialChars_ShouldRoundTripCorrectly()
        {
            // Arrange
            string specialChars = "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?`~";
            BinaryProtocol original = new BinaryProtocol(99, specialChars);
            
            // Act
            byte[] binaryData = original.ToByteArray();
            BinaryProtocol result = BinaryProtocol.Parse(binaryData);
            
            // Assert
            Assert.AreEqual(original.MessageType, result.MessageType);
            Assert.AreEqual(1, result.Fields.Count);
            Assert.AreEqual(specialChars, result.Fields[0]);
        }
        
        [TestMethod]
        public void BinaryProtocol_WithEmptyField_ShouldRoundTripCorrectly()
        {
            // Arrange
            BinaryProtocol original = new BinaryProtocol(1, "Field1", "", "Field3");
            
            // Act
            byte[] binaryData = original.ToByteArray();
            BinaryProtocol result = BinaryProtocol.Parse(binaryData);
            
            // Assert
            Assert.AreEqual(original.MessageType, result.MessageType);
            Assert.AreEqual(3, result.Fields.Count);
            Assert.AreEqual("Field1", result.Fields[0]);
            Assert.AreEqual("", result.Fields[1]);
            Assert.AreEqual("Field3", result.Fields[2]);
        }
        
        [TestMethod]
        public void BinaryProtocol_CreateResponse_WithCustomPrefix_ShouldUseProvidedPrefix()
        {
            // Arrange
            BinaryProtocol original = new BinaryProtocol(55, "TestField");
            string customPrefix = "CUSTOM_PREFIX:";
            
            // Act
            BinaryProtocol response = original.CreateResponse(customPrefix);
            
            // Assert
            Assert.AreEqual(155, response.MessageType); // 55 + 100
            Assert.AreEqual(2, response.Fields.Count);
            Assert.AreEqual(customPrefix, response.Fields[0]);
            Assert.AreEqual("TestField", response.Fields[1]);
        }
        
        [TestMethod]
        public void BinaryProtocol_ToHexString_ShouldReturnCorrectHexRepresentation()
        {
            // Arrange
            BinaryProtocol protocol = new BinaryProtocol(1, "AB");
            
            // Act
            string hexString = protocol.ToHexString();
            
            // Assert
            // Header (12 bytes) + field length (2 bytes) + field data (2 bytes) = 16 bytes
            Assert.AreEqual(16 * 3 - 1, hexString.Length); // Each byte becomes 2 hex chars + 1 space, minus the last space
            Assert.IsTrue(hexString.Contains("41 42")); // Hex for "AB"
        }
        
        [TestMethod]
        public void BinaryProtocol_ToString_ShouldIncludeAllRelevantInfo()
        {
            // Arrange
            BinaryProtocol protocol = new BinaryProtocol(7, "Field1", "Field2");
            
            // Act
            string result = protocol.ToString();
            
            // Assert
            Assert.IsTrue(result.Contains("Type: 7"), "Should include message type");
            Assert.IsTrue(result.Contains("Field1"), "Should include first field");
            Assert.IsTrue(result.Contains("Field2"), "Should include second field");
            Assert.IsTrue(result.Contains("[0]"), "Should include field indices");
            Assert.IsTrue(result.Contains("[1]"), "Should include field indices");
        }
    }
} 