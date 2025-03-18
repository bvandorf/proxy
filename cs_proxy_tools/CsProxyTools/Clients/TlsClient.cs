using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.IO.Pipelines;
using CsProxyTools.Base;
using CsProxyTools.Interfaces;
using Microsoft.Extensions.Logging;

namespace CsProxyTools.Clients;

public class TlsClient : BaseConnection, IClient
{
    private readonly string _host;
    private readonly int _port;
    private readonly bool _validateCertificate;
    private readonly Socket _socket;
    private readonly NetworkStream _stream;
    private readonly SslStream _sslStream;

    public TlsClient(ILogger logger, string host, int port, bool validateCertificate = true) 
        : base(logger, Guid.NewGuid().ToString())
    {
        _host = host;
        _port = port;
        _validateCertificate = validateCertificate;
        _socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        _stream = new NetworkStream(_socket);
        _sslStream = new SslStream(_stream, false, ValidateServerCertificate);
    }

    private bool ValidateServerCertificate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
    {
        if (!_validateCertificate)
        {
            return true;
        }

        if (sslPolicyErrors == SslPolicyErrors.None)
        {
            return true;
        }

        _logger.LogWarning("Certificate validation failed for {Host}: {Errors}", _host, sslPolicyErrors);
        return false;
    }

    protected override async Task StartConnectionAsync()
    {
        await _socket.ConnectAsync(_host, _port);
        await _sslStream.AuthenticateAsClientAsync(_host);
        _ = ProcessStreamAsync();
    }

    protected override async Task StopConnectionAsync()
    {
        _sslStream.Close();
        _stream.Close();
        _socket.Close();
        await Task.CompletedTask;
    }

    protected override async Task WriteDataAsync(ReadOnlyMemory<byte> buffer)
    {
        await _sslStream.WriteAsync(buffer);
    }

    public async Task ConnectAsync(CancellationToken cancellationToken = default)
    {
        await StartAsync(cancellationToken);
    }

    public async Task DisconnectAsync(CancellationToken cancellationToken = default)
    {
        await StopAsync(cancellationToken);
    }

    public event EventHandler<ConnectionEventArgs>? Connected
    {
        add => ConnectionStarted += value;
        remove => ConnectionStarted -= value;
    }

    public event EventHandler<ConnectionEventArgs>? Disconnected
    {
        add => ConnectionClosed += value;
        remove => ConnectionClosed -= value;
    }

    public override async ValueTask DisposeAsync()
    {
        await base.DisposeAsync();
        _sslStream.Dispose();
        _stream.Dispose();
        _socket.Dispose();
    }
} 