using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using CsProxyTools.ProtocolAgent;

namespace CsProxyTools.CsvAgent.Tests
{
    public class DataBufferTests
    {
        private readonly Mock<ILogger<DataBuffer>> _loggerMock;
        private readonly DataBuffer _buffer;

        public DataBufferTests()
        {
            _loggerMock = new Mock<ILogger<DataBuffer>>();
            _buffer = new DataBuffer(_loggerMock.Object);
        }

        [Fact]
        public void AddData_IncreasesBufferSize()
        {
            // Arrange
            var data = new byte[] { 0x01, 0x02, 0x03 };

            // Act
            _buffer.AddData(data);

            // Assert
            Assert.Equal(3, _buffer.BufferSize);
        }

        [Fact]
        public void AddHexData_IncreasesBufferSize()
        {
            // Arrange
            var hexData = "010203";

            // Act
            _buffer.AddHexData(hexData);

            // Assert
            Assert.Equal(3, _buffer.BufferSize);
        }

        [Fact]
        public void GetBufferSnapshot_ReturnsCorrectData()
        {
            // Arrange
            var data = new byte[] { 0x01, 0x02, 0x03 };
            _buffer.AddData(data);

            // Act
            var snapshot = _buffer.GetBufferSnapshot();

            // Assert
            Assert.Equal(data, snapshot);
        }

        [Fact]
        public void Clear_EmptiesBuffer()
        {
            // Arrange
            _buffer.AddData(new byte[] { 0x01, 0x02, 0x03 });
            Assert.Equal(3, _buffer.BufferSize);

            // Act
            _buffer.Clear();

            // Assert
            Assert.Equal(0, _buffer.BufferSize);
        }

        [Fact]
        public async Task WaitForPatternAsync_PatternAlreadyExists_CompletesImmediately()
        {
            // Arrange
            _buffer.AddData(new byte[] { 0x01, 0x02, 0x03, 0x04 });
            var pattern = new byte[] { 0x02, 0x03 };

            // Act
            var startTime = DateTime.Now;
            await _buffer.WaitForPatternAsync(pattern);
            var elapsed = DateTime.Now - startTime;

            // Assert
            Assert.True(elapsed.TotalMilliseconds < 100, "Should complete very quickly");
        }

        [Fact]
        public async Task WaitForPatternAsync_PatternAddedLater_CompleteWhenFound()
        {
            // Arrange
            var cts = new CancellationTokenSource(3000); // 3 second timeout
            var pattern = new byte[] { 0xAA, 0xBB };

            // Act - Start waiting for pattern in background
            var waitTask = _buffer.WaitForPatternAsync(pattern, cts.Token);
            
            // Wait briefly to ensure task is waiting
            await Task.Delay(100);
            
            // Add the pattern data
            _buffer.AddData(new byte[] { 0x01, 0x02, 0xAA, 0xBB, 0x03 });
            
            // Assert - waitTask should complete without throwing
            await waitTask;
        }

        [Fact]
        public async Task WaitForHexPatternAsync_PatternAddedLater_CompleteWhenFound()
        {
            // Arrange
            var cts = new CancellationTokenSource(3000); // 3 second timeout
            var hexPattern = "AABB";

            // Act - Start waiting for pattern in background
            var waitTask = _buffer.WaitForHexPatternAsync(hexPattern, cts.Token);
            
            // Wait briefly to ensure task is waiting
            await Task.Delay(100);
            
            // Add the pattern data
            _buffer.AddHexData("0102AABB03");
            
            // Assert - waitTask should complete without throwing
            await waitTask;
        }

        [Fact]
        public async Task WaitForPatternAsync_Cancelled_ThrowsOperationCanceledException()
        {
            // Arrange
            var cts = new CancellationTokenSource();
            var pattern = new byte[] { 0xAA, 0xBB };

            // Act
            var waitTask = _buffer.WaitForPatternAsync(pattern, cts.Token);
            
            // Wait briefly to ensure task is waiting
            await Task.Delay(100);
            
            // Cancel the operation
            cts.Cancel();
            
            // Assert - TaskCanceledException is a subclass of OperationCanceledException
            // so we should accept either one
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waitTask);
        }

        [Fact]
        public void AddData_WithEmptyData_DoesNotChangeBuffer()
        {
            // Arrange
            _buffer.Clear();
            var emptyData = new byte[0];

            // Act
            _buffer.AddData(emptyData);

            // Assert
            Assert.Equal(0, _buffer.BufferSize);
        }

        [Fact]
        public void AddHexData_WithEmptyString_DoesNotChangeBuffer()
        {
            // Arrange
            _buffer.Clear();

            // Act
            _buffer.AddHexData("");
            _buffer.AddHexData(null);
            _buffer.AddHexData("   ");

            // Assert
            Assert.Equal(0, _buffer.BufferSize);
        }

        [Fact]
        public void AddHexData_WithOddLength_PadsWithLeadingZero()
        {
            // Arrange
            _buffer.Clear();
            var oddLengthHex = "123"; // 3 chars = 1.5 bytes

            // Act
            _buffer.AddHexData(oddLengthHex);

            // Assert
            var result = _buffer.GetBufferSnapshot();
            Assert.Equal(2, result.Length); // Should be padded to 2 bytes
            Assert.Equal(0x01, result[0]); // First byte should be 0x01
            Assert.Equal(0x23, result[1]); // Second byte should be 0x23
        }

        [Fact]
        public void AddHexData_WithNonHexChars_IgnoresNonHexChars()
        {
            // Arrange
            _buffer.Clear();
            var hexWithSpaces = "01 02 03";
            var hexWithInvalidChars = "01XY02ZZ03";

            // Act
            _buffer.AddHexData(hexWithSpaces);
            var result1 = _buffer.GetBufferSnapshot();
            
            _buffer.Clear();
            _buffer.AddHexData(hexWithInvalidChars);
            var result2 = _buffer.GetBufferSnapshot();

            // Assert
            Assert.Equal(new byte[] { 0x01, 0x02, 0x03 }, result1);
            Assert.Equal(new byte[] { 0x01, 0x02, 0x03 }, result2);
        }

        [Fact]
        public async Task WaitForPatternAsync_WithEmptyPattern_ThrowsArgumentException()
        {
            // Arrange
            var emptyPattern = new byte[0];

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(() => 
                _buffer.WaitForPatternAsync(emptyPattern));
        }

        [Fact]
        public async Task WaitForHexPatternAsync_WithEmptyPattern_ThrowsArgumentException()
        {
            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(() => 
                _buffer.WaitForHexPatternAsync(""));
            
            await Assert.ThrowsAsync<ArgumentException>(() => 
                _buffer.WaitForHexPatternAsync(null));
            
            await Assert.ThrowsAsync<ArgumentException>(() => 
                _buffer.WaitForHexPatternAsync("   "));
        }

        [Fact]
        public async Task WaitForPatternAsync_WithOverlappingPatterns_FindsBothPatterns()
        {
            // Arrange
            _buffer.Clear();
            var pattern1 = new byte[] { 0x01, 0x02 };
            var pattern2 = new byte[] { 0x02, 0x03 };

            // Act
            _buffer.AddData(new byte[] { 0x01, 0x02, 0x03, 0x04 });
            
            // Assert
            // Both patterns should be found
            await _buffer.WaitForPatternAsync(pattern1);
            await _buffer.WaitForPatternAsync(pattern2);
        }

        [Fact]
        public async Task WaitForPatternAsync_WithMultipleWaiters_NotifiesAllWaiters()
        {
            // Arrange
            _buffer.Clear();
            var pattern = new byte[] { 0x01, 0x02 };
            var cts = new CancellationTokenSource(3000);

            // Act
            var task1 = _buffer.WaitForPatternAsync(pattern, cts.Token);
            var task2 = _buffer.WaitForPatternAsync(pattern, cts.Token);
            var task3 = _buffer.WaitForPatternAsync(pattern, cts.Token);
            
            await Task.Delay(100); // Ensure all waiters are registered
            
            _buffer.AddData(new byte[] { 0x00, 0x01, 0x02, 0x03 });
            
            // Assert
            await Task.WhenAll(task1, task2, task3);
            // If we reach here without timeout, all tasks completed successfully
        }

        [Fact]
        public async Task WaitForPatternAsync_WithPatternSpanningMultipleAdds_FindsPattern()
        {
            // Arrange
            _buffer.Clear();
            var pattern = new byte[] { 0x02, 0x03, 0x04 };
            var cts = new CancellationTokenSource(3000);

            // Act
            var waitTask = _buffer.WaitForPatternAsync(pattern, cts.Token);
            
            await Task.Delay(100); // Ensure waiter is registered
            
            // Add data in chunks that split the pattern
            _buffer.AddData(new byte[] { 0x01, 0x02 });
            _buffer.AddData(new byte[] { 0x03 });
            _buffer.AddData(new byte[] { 0x04, 0x05 });
            
            // Assert
            await waitTask; // Should complete without timeout
        }

        [Fact]
        public async Task Clear_WithActiveWaiter_WaiterStillWaits()
        {
            // Arrange
            _buffer.Clear();
            var pattern = new byte[] { 0x01, 0x02 };
            var cts = new CancellationTokenSource(3000);

            // Act
            var waitTask = _buffer.WaitForPatternAsync(pattern, cts.Token);
            
            await Task.Delay(100); // Ensure waiter is registered
            
            _buffer.Clear(); // Clear the buffer
            
            // Add the pattern after clearing
            _buffer.AddData(new byte[] { 0x01, 0x02, 0x03 });
            
            // Assert
            await waitTask; // Should still complete when pattern is found
        }

        [Fact]
        public void LargeDataHandling_BufferGrowsCorrectly()
        {
            // Arrange
            _buffer.Clear();
            var largeData = new byte[10000]; // 10KB data
            for (int i = 0; i < largeData.Length; i++)
            {
                largeData[i] = (byte)(i % 256);
            }

            // Act
            _buffer.AddData(largeData);

            // Assert
            Assert.Equal(10000, _buffer.BufferSize);
            var snapshot = _buffer.GetBufferSnapshot();
            Assert.Equal(largeData, snapshot);
        }

        [Fact]
        public async Task ConcurrentAccess_HandlesMultipleThreads()
        {
            // Arrange
            _buffer.Clear();
            var tasks = new List<Task>();
            var random = new Random();
            var patterns = new byte[][]
            {
                new byte[] { 0x01, 0x02 },
                new byte[] { 0x03, 0x04 },
                new byte[] { 0x05, 0x06 },
                new byte[] { 0x07, 0x08 },
                new byte[] { 0x09, 0x0A }
            };

            // Create tasks to add data from multiple threads
            for (int i = 0; i < 5; i++)
            {
                var taskNum = i;
                tasks.Add(Task.Run(() =>
                {
                    var data = new byte[100];
                    for (int j = 0; j < 100; j++)
                    {
                        data[j] = (byte)((taskNum * 100 + j) % 256);
                    }
                    _buffer.AddData(data);
                }));
            }

            // Create tasks to wait for patterns
            var patternTasks = new List<Task>();
            for (int i = 0; i < patterns.Length; i++)
            {
                var pattern = patterns[i];
                patternTasks.Add(Task.Run(async () =>
                {
                    var cts = new CancellationTokenSource(5000); // 5 second timeout
                    // Add the pattern we're looking for to ensure it will be found
                    _buffer.AddData(pattern);
                    await _buffer.WaitForPatternAsync(pattern, cts.Token);
                }));
            }

            // Create tasks to get snapshots and clear the buffer occasionally
            for (int i = 0; i < 3; i++)
            {
                tasks.Add(Task.Run(() =>
                {
                    Thread.Sleep(random.Next(10, 50));
                    var snapshot = _buffer.GetBufferSnapshot();
                    // Don't clear the buffer as it would affect the pattern tasks
                }));
            }

            // Act - run all tasks concurrently
            var allTasks = tasks.Concat(patternTasks).ToList();
            
            // Assert - no exceptions should be thrown
            await Task.WhenAll(allTasks);
        }

        [Fact]
        public async Task WaitForPatternAsync_WithPatternAtBufferBoundary_FindsPattern()
        {
            // Arrange
            _buffer.Clear();
            var pattern = new byte[] { 0xAA, 0xBB };
            var cts = new CancellationTokenSource(3000);
            
            // Act
            var waitTask = _buffer.WaitForPatternAsync(pattern, cts.Token);
            
            await Task.Delay(100); // Ensure waiter is registered
            
            // Add data where pattern spans the end of one add and beginning of next
            _buffer.AddData(new byte[] { 0x01, 0x02, 0xAA });
            _buffer.AddData(new byte[] { 0xBB, 0x03, 0x04 });
            
            // Assert
            await waitTask; // Should complete without timeout
        }
    }
} 