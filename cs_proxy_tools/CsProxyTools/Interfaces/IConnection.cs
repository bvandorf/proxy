using System.IO.Pipelines;

namespace CsProxyTools.Interfaces;

public interface IConnection : IAsyncDisposable
{
    bool IsConnected { get; }
    string Id { get; }
    Task StartAsync(CancellationToken cancellationToken = default);
    Task StopAsync(CancellationToken cancellationToken = default);
    Task<ReadResult> ReadAsync(CancellationToken cancellationToken = default);
    Task WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default);
    event EventHandler<ConnectionEventArgs>? ConnectionClosed;
    event EventHandler<ConnectionEventArgs>? ConnectionStarted;
    event EventHandler<DataReceivedEventArgs>? DataReceived;
}

public class ConnectionEventArgs : EventArgs
{
    public string ConnectionId { get; }
    public DateTime Timestamp { get; }

    public ConnectionEventArgs(string connectionId)
    {
        ConnectionId = connectionId;
        Timestamp = DateTime.UtcNow;
    }
}

public class DataReceivedEventArgs : EventArgs
{
    public string ConnectionId { get; }
    public ReadOnlyMemory<byte> Data { get; }
    public DateTime Timestamp { get; }

    public DataReceivedEventArgs(string connectionId, ReadOnlyMemory<byte> data)
    {
        ConnectionId = connectionId;
        Data = data;
        Timestamp = DateTime.UtcNow;
    }
} 