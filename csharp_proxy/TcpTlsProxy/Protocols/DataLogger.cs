using System;
using System.Text;

namespace TcpTlsProxy.Protocols
{
    /// <summary>
    /// Utility class for logging binary data in various formats
    /// </summary>
    public static class DataLogger
    {
        /// <summary>
        /// Maximum number of bytes to include in text representation
        /// </summary>
        private const int MaxTextBytes = 1024;

        /// <summary>
        /// Logs binary data in both text and hex formats
        /// </summary>
        /// <param name="logger">The logger to use</param>
        /// <param name="prefix">Message prefix</param>
        /// <param name="data">Binary data to log</param>
        /// <param name="clientId">Client ID for the connection</param>
        public static void LogData(ProxyLogger logger, string prefix, byte[] data, string clientId)
        {
            // Basic information about the data
            logger.Log($"{prefix} {data.Length} bytes from {clientId}");
            
            // Hex representation (always logged)
            logger.Log($"Hex: {BitConverter.ToString(data).Replace("-", " ")}");
            
            // Check if this is binary data
            bool isBinary = !MightBeText(data);
            
            if (isBinary)
            {
                logger.Log("Text: [Binary data, not displayed]");
            }
            else
            {
                try
                {
                    // For very large data, truncate the text representation
                    int bytesToLog = Math.Min(data.Length, MaxTextBytes);
                    string text = Encoding.UTF8.GetString(data, 0, bytesToLog);
                    
                    // Clean up control characters for better logging
                    string cleanText = CleanControlChars(text);
                    
                    if (data.Length > MaxTextBytes)
                    {
                        logger.Log($"Text (truncated): {cleanText}...");
                    }
                    else
                    {
                        logger.Log($"Text: {cleanText}");
                    }
                }
                catch
                {
                    // If UTF-8 decoding fails, log that it's not valid text
                    logger.Log("Text: [Not valid UTF-8 text]");
                }
            }
            
            // Add a separator for readability
            logger.Log("---------------------------------------------");
        }

        /// <summary>
        /// Determines if the data might be text based on content
        /// </summary>
        private static bool MightBeText(byte[] data)
        {
            // If empty, it's not meaningful text
            if (data == null || data.Length == 0)
                return false;
            
            // Check for binary protocol patterns first
            if (IsBinaryProtocolData(data))
                return false;
                
            // Check a sample of bytes to see if they fall within common text ranges
            int samplesToCheck = Math.Min(data.Length, 100);
            int textCharCount = 0;
            int nullByteCount = 0;
            int consecutiveControlChars = 0;
            int maxConsecutiveControlChars = 0;
            
            for (int i = 0; i < samplesToCheck; i++)
            {
                byte b = data[i];
                
                // Count null bytes
                if (b == 0)
                {
                    nullByteCount++;
                    consecutiveControlChars++;
                }
                // Count control characters (except common whitespace)
                else if (b < 32 && b != 9 && b != 10 && b != 13)
                {
                    // Don't count control characters against text chars
                    // since we want to display them in [XX] format
                    textCharCount++;
                    consecutiveControlChars = 0;
                }
                // ASCII printable chars, tabs, newlines
                else if ((b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13)
                {
                    textCharCount++;
                    maxConsecutiveControlChars = Math.Max(maxConsecutiveControlChars, consecutiveControlChars);
                    consecutiveControlChars = 0;
                }
            }
            
            maxConsecutiveControlChars = Math.Max(maxConsecutiveControlChars, consecutiveControlChars);
            
            // If any of these conditions are met, consider it binary:
            // 1. Multiple null bytes
            // 2. Long sequences of consecutive control characters
            // 3. Not enough text characters
            if (nullByteCount > 1 || 
                maxConsecutiveControlChars > 3 ||
                textCharCount < samplesToCheck * 0.7)
            {
                return false;
            }
            
            return true;
        }
        
        /// <summary>
        /// Checks for specific patterns that indicate binary protocol data
        /// </summary>
        private static bool IsBinaryProtocolData(byte[] data)
        {
            // Need at least 8 bytes for basic checks
            if (data.Length < 8)
                return false;
                
            // Check for common binary protocol patterns
            bool hasSequentialNulls = false;
            bool hasLengthIndicator = false;
            bool hasRepeatingPattern = false;
            
            // Check for sequences of null bytes (common in binary headers)
            for (int i = 0; i < data.Length - 3; i++)
            {
                if (data[i] == 0 && data[i+1] == 0 && data[i+2] == 0)
                {
                    hasSequentialNulls = true;
                    break;
                }
            }
            
            // Check for length indicators (common in binary protocols)
            // Pattern: 00 00 00 XX where XX is non-zero
            if (data.Length >= 4)
            {
                hasLengthIndicator = data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] != 0;
            }
            
            // Check for repeating patterns (common in binary protocols)
            if (data.Length >= 16)
            {
                // Look for repeating byte patterns in the header
                bool pattern1 = data[0] == data[4] && data[4] == data[8];
                bool pattern2 = data[1] == data[5] && data[5] == data[9];
                hasRepeatingPattern = pattern1 && pattern2;
            }
            
            // Additional binary indicators
            bool hasHighBitBytes = false;
            int highBitCount = 0;
            
            // Check first 32 bytes for high-bit patterns
            for (int i = 0; i < Math.Min(data.Length, 32); i++)
            {
                if ((data[i] & 0x80) != 0)
                {
                    highBitCount++;
                }
            }
            
            // If more than 25% of the first 32 bytes have high bits set, likely binary
            hasHighBitBytes = highBitCount > Math.Min(data.Length, 32) * 0.25;
            
            // If any of these binary indicators are present, consider it binary
            return hasSequentialNulls || hasLengthIndicator || hasRepeatingPattern || hasHighBitBytes;
        }

        /// <summary>
        /// Replaces control characters with visible representations for better logging
        /// </summary>
        private static string CleanControlChars(string text)
        {
            if (string.IsNullOrEmpty(text))
                return text;
                
            StringBuilder sb = new StringBuilder(text.Length * 2); // Pre-allocate more space for control char replacements
            
            for (int i = 0; i < text.Length; i++)
            {
                char c = text[i];
                if (c < 32) // All control characters (0-31)
                {
                    // Convert all control characters to [XX] format, including whitespace
                    sb.Append($"[{((int)c):X2}]");
                }
                else
                {
                    sb.Append(c);
                }
            }
            
            return sb.ToString();
        }
    }
} 

