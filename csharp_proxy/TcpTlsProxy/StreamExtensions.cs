using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace TcpTlsProxy
{
    /// <summary>
    /// Extension methods for Stream
    /// </summary>
    public static class StreamExtensions
    {
        /// <summary>
        /// Reads all bytes from a stream
        /// </summary>
        /// <param name="stream">The stream to read from</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>The bytes read from the stream</returns>
        public static async Task<byte[]> ReadAllBytesAsync(this Stream stream, CancellationToken cancellationToken = default)
        {
            // If the stream is seekable, use the stream length to allocate the buffer
            if (stream.CanSeek)
            {
                var buffer = new byte[stream.Length];
                await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                return buffer;
            }
            
            // If the stream is not seekable, read chunks and combine them
            const int chunkSize = 4096;
            using var memoryStream = new MemoryStream();
            var chunkBuffer = new byte[chunkSize];
            
            int bytesRead;
            while ((bytesRead = await stream.ReadAsync(chunkBuffer, 0, chunkBuffer.Length, cancellationToken)) > 0)
            {
                await memoryStream.WriteAsync(chunkBuffer, 0, bytesRead, cancellationToken);
            }
            
            return memoryStream.ToArray();
        }
    }
} 