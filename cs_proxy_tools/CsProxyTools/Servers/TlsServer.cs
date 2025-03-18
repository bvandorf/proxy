using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.IO.Pipelines;
using CsProxyTools.Base;
using CsProxyTools.Interfaces;
using Microsoft.Extensions.Logging;

namespace CsProxyTools.Servers;

public class TlsServer : BaseConnection, IServer
{
    private readonly string _host;
    private readonly int _port;
    private readonly string _certificatePath;
    private readonly string _certificatePassword;
    private readonly X509Certificate2 _certificate;
    private readonly Socket _listener;
    private readonly List<SslStream> _clients;
    private readonly object _clientsLock = new();

    public event EventHandler<ConnectionEventArgs>? ClientConnected;
    public event EventHandler<ConnectionEventArgs>? ClientDisconnected;
    public bool IsRunning { get; private set; }

    public TlsServer(ILogger logger, string host, int port, string certificatePath, string certificatePassword) 
        : base(logger, Guid.NewGuid().ToString())
    {
        _host = host;
        _port = port;
        _certificatePath = certificatePath;
        _certificatePassword = certificatePassword;
        _certificate = null;
        _listener = new Socket(SocketType.Stream, ProtocolType.Tcp);
        _clients = new List<SslStream>();
    }

    public TlsServer(ILogger logger, string host, int port, X509Certificate2 certificate) 
        : base(logger, Guid.NewGuid().ToString())
    {
        _host = host;
        _port = port;
        _certificate = certificate;
        _certificatePath = "";
        _certificatePassword = "";
        _listener = new Socket(SocketType.Stream, ProtocolType.Tcp);
        _clients = new List<SslStream>();
    }

    protected override async Task StartConnectionAsync()
    {
        _listener.Bind(new IPEndPoint(IPAddress.Parse(_host), _port));
        _listener.Listen(128);
        IsRunning = true;
        _ = AcceptClientsAsync();
        await Task.CompletedTask;
    }

    protected override async Task StopConnectionAsync()
    {
        IsRunning = false;
        lock (_clientsLock)
        {
            foreach (var client in _clients)
            {
                try
                {
                    client.Close();
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error closing client stream");
                }
            }
            _clients.Clear();
        }

        _listener.Close();
        await Task.CompletedTask;
    }

    protected override async Task WriteDataAsync(ReadOnlyMemory<byte> buffer)
    {
        var clients = new List<SslStream>();
        lock (_clientsLock)
        {
            clients.AddRange(_clients);
        }

        foreach (var client in clients)
        {
            try
            {
                await client.WriteAsync(buffer);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error writing to client");
                await RemoveClientAsync(client);
            }
        }
    }

    private async Task AcceptClientsAsync()
    {
        while (!_cancellationTokenSource.Token.IsCancellationRequested)
        {
            try
            {
                var client = await _listener.AcceptAsync(_cancellationTokenSource.Token);
                _ = HandleClientAsync(client);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error accepting client");
            }
        }
    }

    private async Task HandleClientAsync(Socket client)
    {
        var clientId = Guid.NewGuid().ToString();
        var stream = new NetworkStream(client);
        var sslStream = new SslStream(stream, false);

        try
        {
            if (_certificate != null)
            {
                await sslStream.AuthenticateAsServerAsync(_certificate);
            }
            else if (_certificatePath != null && _certificatePassword != null)
            {
                var certificate = new X509Certificate2(_certificatePath, _certificatePassword);
                await sslStream.AuthenticateAsServerAsync(certificate);
            }
            else
            {
                throw new InvalidOperationException("Certificate or certificate path and password must be provided");
            }

            lock (_clientsLock)
            {
                _clients.Add(sslStream);
            }

            ClientConnected?.Invoke(this, new ConnectionEventArgs(clientId));

            var buffer = new byte[8192];
            while (!_cancellationTokenSource.Token.IsCancellationRequested)
            {
                var bytesRead = await sslStream.ReadAsync(buffer, _cancellationTokenSource.Token);
                if (bytesRead == 0) break;

                var data = new byte[bytesRead];
                Array.Copy(buffer, data, bytesRead);
                OnDataReceived(data);
            }
        }
        catch (OperationCanceledException)
        {
            // Normal cancellation, ignore
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error handling client {ClientId}", clientId);
        }
        finally
        {
            await RemoveClientAsync(sslStream);
            ClientDisconnected?.Invoke(this, new ConnectionEventArgs(clientId));
        }
    }

    private async Task RemoveClientAsync(SslStream client)
    {
        lock (_clientsLock)
        {
            _clients.Remove(client);
        }

        try
        {
            client.Close();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error closing client stream");
        }

        await Task.CompletedTask;
    }

    public override async ValueTask DisposeAsync()
    {
        await base.DisposeAsync();
        _listener.Dispose();
    }
} 