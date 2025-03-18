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
    public string? RemoteEndpoint { get; }

    public ConnectionEventArgs(string connectionId)
    {
        ConnectionId = connectionId;
        RemoteEndpoint = null;
    }
    
    public ConnectionEventArgs(string connectionId, string remoteEndpoint)
    {
        ConnectionId = connectionId;
        RemoteEndpoint = remoteEndpoint;
    }
}

public class DataReceivedEventArgs : EventArgs
{
    public string ConnectionId { get; }
    public ReadOnlyMemory<byte> Data { get; }
    public string? RemoteEndpoint { get; }

    public DataReceivedEventArgs(string connectionId, ReadOnlyMemory<byte> data)
    {
        ConnectionId = connectionId;
        Data = data;
        RemoteEndpoint = null;
    }
    
    public DataReceivedEventArgs(string connectionId, ReadOnlyMemory<byte> data, string remoteEndpoint)
    {
        ConnectionId = connectionId;
        Data = data;
        RemoteEndpoint = remoteEndpoint;
    }
} 