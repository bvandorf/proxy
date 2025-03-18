using CsProxyTools.Interfaces;

namespace CsProxyTools.Interfaces;

public interface IServer : IAsyncDisposable
{
    string Id { get; }
    bool IsRunning { get; }
    Task StartAsync(CancellationToken cancellationToken = default);
    Task StopAsync(CancellationToken cancellationToken = default);
    event EventHandler<ConnectionEventArgs>? ClientConnected;
    event EventHandler<ConnectionEventArgs>? ClientDisconnected;
    event EventHandler<DataReceivedEventArgs>? DataReceived;
}

public interface ITcpServer : IServer
{
    int Port { get; }
    string Host { get; }
}

public interface ITlsServer : IServer
{
    int Port { get; }
    string Host { get; }
    string CertificatePath { get; }
    string CertificatePassword { get; }
} 