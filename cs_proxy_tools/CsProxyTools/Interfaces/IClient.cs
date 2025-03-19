using System.IO.Pipelines;
using CsProxyTools.Interfaces;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace CsProxyTools.Interfaces;

/// <summary>
/// Represents a client that can connect to a remote server
/// </summary>
public interface IClient : IConnection
{
    /// <summary>
    /// Connects to the remote server
    /// </summary>
    Task ConnectAsync(CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Disconnects from the remote server
    /// </summary>
    Task DisconnectAsync(CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Event that is raised when the connection is established
    /// </summary>
    event EventHandler<ConnectionEventArgs>? Connected;
    
    /// <summary>
    /// Event that is raised when the connection is closed
    /// </summary>
    event EventHandler<ConnectionEventArgs>? Disconnected;
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
    Task SendAuthenticationHeaderAsync(string headerName, string headerValue);
} 