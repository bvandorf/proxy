using System.IO.Pipelines;
using CsProxyTools.Interfaces;

namespace CsProxyTools.Interfaces;

public interface IClient : IAsyncDisposable
{
    string Id { get; }
    bool IsConnected { get; }
    Task ConnectAsync(CancellationToken cancellationToken = default);
    Task DisconnectAsync(CancellationToken cancellationToken = default);
    Task<ReadResult> ReadAsync(CancellationToken cancellationToken = default);
    Task WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default);
    event EventHandler<ConnectionEventArgs>? Connected;
    event EventHandler<ConnectionEventArgs>? Disconnected;
    event EventHandler<DataReceivedEventArgs>? DataReceived;
}

public interface ITcpClient : IClient
{
    string Host { get; }
    int Port { get; }
}

public interface ITlsClient : IClient
{
    string Host { get; }
    int Port { get; }
    bool ValidateCertificate { get; }
} 