using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace TcpTlsProxy.Protocols
{
    /// <summary>
    /// Parser and builder for a binary protocol with the format:
    /// [4 bytes total length][4 bytes message type][4 bytes data section length]
    /// followed by multiple text fields, each with:
    /// [2 bytes field length][field data]
    /// </summary>
    public class BinaryProtocol
    {
        public int TotalLength { get; set; }
        public int MessageType { get; set; }
        public int DataSectionLength { get; set; }
        public List<string> Fields { get; set; } = new List<string>();

        /// <summary>
        /// Creates a new empty binary protocol message
        /// </summary>
        public BinaryProtocol()
        {
        }

        /// <summary>
        /// Creates a new binary protocol message with specified values
        /// </summary>
        public BinaryProtocol(int messageType, params string[] fields)
        {
            MessageType = messageType;
            Fields = new List<string>(fields ?? Array.Empty<string>());
        }

        /// <summary>
        /// Parses binary data into a BinaryProtocol object
        /// </summary>
        public static BinaryProtocol Parse(byte[] data)
        {
            BinaryProtocol result = new BinaryProtocol();
            
            // Handle null or empty data
            if (data == null || data.Length == 0)
            {
                return result;
            }
            
            try
            {
                using (MemoryStream ms = new MemoryStream(data))
                using (BinaryReader reader = new BinaryReader(ms))
                {
                    // Check if we have enough data for the header
                    if (data.Length < 12)
                    {
                        return result;
                    }
                    
                    // Read header values (big endian)
                    result.TotalLength = ReadInt32BigEndian(reader);
                    result.MessageType = ReadInt32BigEndian(reader);
                    result.DataSectionLength = ReadInt32BigEndian(reader);
                    
                    // Read fields
                    while (ms.Position < ms.Length)
                    {
                        try
                        {
                            // Check if we have enough data for field length
                            if (ms.Length - ms.Position < 2)
                                break;
                                
                            // Read field length (2 bytes, big endian)
                            int fieldLength = ReadInt16BigEndian(reader);
                            
                            // Validate field length
                            if (fieldLength < 0 || fieldLength > 1024 || // Sanity check
                                ms.Length - ms.Position < fieldLength) // Check if we have enough data
                            {
                                break;
                            }
                            
                            // Read field data
                            if (fieldLength == 0)
                            {
                                result.Fields.Add(string.Empty);
                            }
                            else
                            {
                                byte[] fieldData = reader.ReadBytes(fieldLength);
                                string fieldValue = Encoding.ASCII.GetString(fieldData);
                                result.Fields.Add(fieldValue);
                            }
                        }
                        catch (EndOfStreamException)
                        {
                            // End of data
                            break;
                        }
                    }
                }
            }
            catch (Exception)
            {
                // Return empty protocol object on any parsing error
                result = new BinaryProtocol();
            }
            
            return result;
        }

        /// <summary>
        /// Builds a byte array from this BinaryProtocol object
        /// </summary>
        public byte[] ToByteArray()
        {
            using (MemoryStream ms = new MemoryStream())
            using (BinaryWriter writer = new BinaryWriter(ms))
            {
                // Calculate data section length
                int dataLength = 0;
                foreach (var field in Fields)
                {
                    dataLength += 2; // field length (2 bytes)
                    dataLength += field?.Length ?? 0; // field data (handle null fields as empty)
                }
                
                DataSectionLength = dataLength;
                
                // Calculate total length
                TotalLength = 12 + dataLength; // 12 bytes header + data section
                
                // Write header
                WriteInt32BigEndian(writer, TotalLength);
                WriteInt32BigEndian(writer, MessageType);
                WriteInt32BigEndian(writer, DataSectionLength);
                
                // Write fields
                foreach (var field in Fields)
                {
                    string fieldValue = field ?? string.Empty;
                    
                    // Write field length (2 bytes, big endian)
                    WriteInt16BigEndian(writer, (short)fieldValue.Length);
                    
                    // Write field data (if not empty)
                    if (fieldValue.Length > 0)
                    {
                        byte[] fieldData = Encoding.ASCII.GetBytes(fieldValue);
                        writer.Write(fieldData);
                    }
                }
                
                return ms.ToArray();
            }
        }

        /// <summary>
        /// Creates a response protocol message to an incoming message
        /// </summary>
        public BinaryProtocol CreateResponse(string prefix = "Response to: ")
        {
            BinaryProtocol response = new BinaryProtocol();
            response.MessageType = this.MessageType + 100; // Convention: response type = request type + 100
            
            // Add prefix as first field
            response.Fields.Add(prefix);
            
            // Copy all fields from the original message
            response.Fields.AddRange(this.Fields);
            
            return response;
        }

        /// <summary>
        /// Get a human-readable hexadecimal representation of the message
        /// </summary>
        public string ToHexString()
        {
            byte[] data = ToByteArray();
            return BitConverter.ToString(data).Replace("-", " ");
        }

        /// <summary>
        /// Get a human-readable representation of the message
        /// </summary>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine($"BinaryProtocol [Type: {MessageType}, Length: {TotalLength}]");
            sb.AppendLine($"Data Section Length: {DataSectionLength}");
            sb.AppendLine("Fields:");
            
            for (int i = 0; i < Fields.Count; i++)
            {
                sb.AppendLine($"  [{i}] Length: {Fields[i]?.Length ?? 0}, Value: '{Fields[i] ?? string.Empty}'");
            }
            
            return sb.ToString();
        }

        #region Helper Methods for Big Endian Reading/Writing

        private static int ReadInt32BigEndian(BinaryReader reader)
        {
            try
            {
                byte[] bytes = reader.ReadBytes(4);
                if (bytes.Length < 4)
                    return 0;
                    
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(bytes);
                return BitConverter.ToInt32(bytes, 0);
            }
            catch
            {
                return 0;
            }
        }

        private static short ReadInt16BigEndian(BinaryReader reader)
        {
            try
            {
                byte[] bytes = reader.ReadBytes(2);
                if (bytes.Length < 2)
                    return 0;
                    
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(bytes);
                return BitConverter.ToInt16(bytes, 0);
            }
            catch
            {
                return 0;
            }
        }

        private static void WriteInt32BigEndian(BinaryWriter writer, int value)
        {
            byte[] bytes = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);
            writer.Write(bytes);
        }

        private static void WriteInt16BigEndian(BinaryWriter writer, short value)
        {
            byte[] bytes = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);
            writer.Write(bytes);
        }

        #endregion
    }
} 