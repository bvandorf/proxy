using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace CsProxyTools.ProtocolAgent
{
    /// <summary>
    /// Represents a data buffer that can accumulate bytes and provide pattern matching capabilities
    /// </summary>
    public class DataBuffer
    {
        private readonly ILogger<DataBuffer> _logger;
        private readonly ConcurrentQueue<byte> _buffer = new ConcurrentQueue<byte>();
        private readonly List<PatternWaiter> _waiters = new List<PatternWaiter>();
        private readonly object _waitersLock = new object();

        public DataBuffer(ILogger<DataBuffer> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Adds data to the buffer and checks for pattern matches
        /// </summary>
        public void AddData(byte[] data)
        {
            if (data == null || data.Length == 0)
                return;

            // Add all bytes to the buffer
            foreach (var b in data)
            {
                _buffer.Enqueue(b);
            }

            _logger.LogDebug("Added {Count} bytes to buffer. Total buffer size: {BufferSize}", 
                data.Length, _buffer.Count);

            // Check for pattern matches
            CheckPatternMatches();
        }

        /// <summary>
        /// Adds a hex string to the buffer
        /// </summary>
        public void AddHexData(string hexString)
        {
            if (string.IsNullOrWhiteSpace(hexString))
                return;

            var data = HexStringToByteArray(hexString);
            AddData(data);
        }

        /// <summary>
        /// Waits for a specific pattern to be found in the buffer
        /// </summary>
        public async Task WaitForPatternAsync(byte[] pattern, CancellationToken cancellationToken = default)
        {
            if (pattern == null || pattern.Length == 0)
                throw new ArgumentException("Pattern cannot be null or empty", nameof(pattern));

            _logger.LogInformation("Waiting for pattern: {Pattern}", 
                BitConverter.ToString(pattern).Replace("-", ""));

            // Check if the pattern is already in the buffer
            if (IsPatternInBuffer(pattern))
            {
                _logger.LogInformation("Pattern already found in buffer");
                return;
            }

            // Create a TaskCompletionSource that will be completed when the pattern is found
            var tcs = new TaskCompletionSource<bool>();
            var waiter = new PatternWaiter
            {
                Pattern = pattern,
                CompletionSource = tcs
            };

            // Register for cancellation
            using var registration = cancellationToken.Register(() => 
            {
                _logger.LogWarning("Waiting for pattern was cancelled");
                tcs.TrySetCanceled();
                
                // Remove the waiter from the list
                lock (_waitersLock)
                {
                    _waiters.Remove(waiter);
                }
            });

            // Add the waiter to the list
            lock (_waitersLock)
            {
                _waiters.Add(waiter);
            }

            // Check again in case the pattern arrived between the initial check and adding the waiter
            CheckPatternMatches();

            // Wait for the pattern to be found or cancellation
            await tcs.Task;
        }

        /// <summary>
        /// Waits for a specific hex pattern to be found in the buffer
        /// </summary>
        public Task WaitForHexPatternAsync(string hexPattern, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(hexPattern))
                throw new ArgumentException("Hex pattern cannot be null or empty", nameof(hexPattern));

            var pattern = HexStringToByteArray(hexPattern);
            return WaitForPatternAsync(pattern, cancellationToken);
        }

        /// <summary>
        /// Gets a snapshot of the current buffer contents
        /// </summary>
        public byte[] GetBufferSnapshot()
        {
            return _buffer.ToArray();
        }

        /// <summary>
        /// Gets the current buffer size
        /// </summary>
        public int BufferSize => _buffer.Count;

        /// <summary>
        /// Clears the buffer
        /// </summary>
        public void Clear()
        {
            while (_buffer.TryDequeue(out _)) { }
            _logger.LogInformation("Buffer cleared");
        }

        /// <summary>
        /// Checks if any registered patterns match the current buffer
        /// </summary>
        private void CheckPatternMatches()
        {
            PatternWaiter[] waitersToCheck;
            
            // Get a snapshot of the current waiters
            lock (_waitersLock)
            {
                if (_waiters.Count == 0)
                    return;
                    
                waitersToCheck = _waiters.ToArray();
            }

            foreach (var waiter in waitersToCheck)
            {
                if (IsPatternInBuffer(waiter.Pattern))
                {
                    _logger.LogInformation("Pattern match found: {Pattern}", 
                        BitConverter.ToString(waiter.Pattern).Replace("-", ""));
                        
                    // Complete the waiter's task
                    waiter.CompletionSource.TrySetResult(true);
                    
                    // Remove the waiter from the list
                    lock (_waitersLock)
                    {
                        _waiters.Remove(waiter);
                    }
                }
            }
        }

        /// <summary>
        /// Checks if a pattern exists in the current buffer
        /// </summary>
        private bool IsPatternInBuffer(byte[] pattern)
        {
            if (pattern.Length > _buffer.Count)
                return false;

            var bufferArray = _buffer.ToArray();
            
            // Simple pattern matching - could be optimized with more advanced algorithms
            for (int i = 0; i <= bufferArray.Length - pattern.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (bufferArray[i + j] != pattern[j])
                    {
                        match = false;
                        break;
                    }
                }
                
                if (match)
                    return true;
            }
            
            return false;
        }

        /// <summary>
        /// Converts a hex string to a byte array
        /// </summary>
        private byte[] HexStringToByteArray(string hex)
        {
            // Remove any non-hex characters (like spaces)
            hex = new string(hex.Where(c => "0123456789ABCDEFabcdef".Contains(c)).ToArray());
            
            // If odd length, pad with a leading zero
            if (hex.Length % 2 != 0)
            {
                hex = "0" + hex;
            }

            byte[] bytes = new byte[hex.Length / 2];
            
            for (int i = 0; i < hex.Length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            
            return bytes;
        }

        /// <summary>
        /// Class to track patterns that are being waited for
        /// </summary>
        private class PatternWaiter
        {
            public byte[] Pattern { get; set; }
            public TaskCompletionSource<bool> CompletionSource { get; set; }
        }
    }
} 