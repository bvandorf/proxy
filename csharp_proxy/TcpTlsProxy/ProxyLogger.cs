using System;
using System.IO;

namespace TcpTlsProxy
{
    /// <summary>
    /// Logger class for the TCP/TLS proxy
    /// </summary>
    public class ProxyLogger
    {
        private readonly string _logFilePath;
        private readonly object _lockObject = new object();

        /// <summary>
        /// Creates a new ProxyLogger
        /// </summary>
        /// <param name="logFilePath">Path to log file (optional)</param>
        public ProxyLogger(string logFilePath = null)
        {
            _logFilePath = logFilePath;
            
            if (!string.IsNullOrEmpty(_logFilePath))
            {
                // Ensure the directory exists
                string directory = Path.GetDirectoryName(_logFilePath);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }
                
                // Initialize log file with a header
                try
                {
                    File.WriteAllText(_logFilePath, $"--- TCP/TLS Proxy Log Started at {DateTime.Now} ---\r\n");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning: Could not initialize log file: {ex.Message}");
                    _logFilePath = null; // Disable file logging
                }
            }
        }

        /// <summary>
        /// Log a message to console and log file (if specified)
        /// </summary>
        /// <param name="message">The message to log</param>
        public virtual void Log(string message)
        {
            string formattedMessage = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {message}";
            
            // Always write to console
            Console.WriteLine(formattedMessage);
            
            // Write to file if enabled
            if (!string.IsNullOrEmpty(_logFilePath))
            {
                lock (_lockObject)
                {
                    try
                    {
                        File.AppendAllText(_logFilePath, formattedMessage + Environment.NewLine);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Warning: Failed to write to log file: {ex.Message}");
                    }
                }
            }
        }
        
        /// <summary>
        /// Log an error message to console and log file (if specified)
        /// </summary>
        /// <param name="message">The error message to log</param>
        /// <param name="ex">Optional exception to include in the log</param>
        public virtual void LogError(string message, Exception ex = null)
        {
            string errorMessage = $"ERROR: {message}";
            if (ex != null)
            {
                errorMessage += $" - {ex.Message}";
            }
            
            Log(errorMessage);
            
            // Log stack trace if exception provided
            if (ex != null)
            {
                Log($"Stack trace: {ex.StackTrace}");
            }
        }
    }
} 