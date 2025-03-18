using System.IO.Pipelines;
using CsProxyTools.Interfaces;
using Microsoft.Extensions.Logging;
using System.Buffers;

namespace CsProxyTools.Base;

public abstract class BaseConnection : IConnection
{
    protected readonly ILogger _logger;
    protected readonly Pipe _pipe;
    protected readonly CancellationTokenSource _cancellationTokenSource;
    protected bool _isConnected;
    protected bool _isDisposed;

    public string Id { get; }

    protected BaseConnection(ILogger logger, string id)
    {
        _logger = logger;
        Id = id;
        _pipe = new Pipe();
        _cancellationTokenSource = new CancellationTokenSource();
    }

    public virtual bool IsConnected => _isConnected;

    public event EventHandler<ConnectionEventArgs>? ConnectionStarted;
    public event EventHandler<ConnectionEventArgs>? ConnectionClosed;
    public event EventHandler<DataReceivedEventArgs>? DataReceived;

    protected virtual void OnConnectionStarted()
    {
        _isConnected = true;
        ConnectionStarted?.Invoke(this, new ConnectionEventArgs(Id));
    }

    protected virtual void OnConnectionClosed()
    {
        _isConnected = false;
        ConnectionClosed?.Invoke(this, new ConnectionEventArgs(Id));
    }

    protected virtual void OnDataReceived(ReadOnlyMemory<byte> data)
    {
        DataReceived?.Invoke(this, new DataReceivedEventArgs(Id, data));
    }

    public virtual async Task StartAsync(CancellationToken cancellationToken = default)
    {
        if (_isDisposed)
        {
            throw new ObjectDisposedException(nameof(BaseConnection));
        }

        try
        {
            await StartConnectionAsync();
            OnConnectionStarted();
            _ = ProcessStreamAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error starting connection {Id}", Id);
            throw;
        }
    }

    public virtual async Task StopAsync(CancellationToken cancellationToken = default)
    {
        if (_isDisposed)
        {
            return;
        }

        try
        {
            _cancellationTokenSource.Cancel();
            await StopConnectionAsync();
            OnConnectionClosed();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error stopping connection {Id}", Id);
            throw;
        }
    }

    public virtual async Task<ReadResult> ReadAsync(CancellationToken cancellationToken = default)
    {
        if (_isDisposed)
        {
            throw new ObjectDisposedException(nameof(BaseConnection));
        }

        try
        {
            return await _pipe.Reader.ReadAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error reading from connection {Id}", Id);
            throw;
        }
    }

    public virtual async Task WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (_isDisposed)
        {
            throw new ObjectDisposedException(nameof(BaseConnection));
        }

        try
        {
            await WriteDataAsync(buffer);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error writing to connection {Id}", Id);
            throw;
        }
    }

    protected abstract Task StartConnectionAsync();
    protected abstract Task StopConnectionAsync();
    protected abstract Task WriteDataAsync(ReadOnlyMemory<byte> buffer);

    protected virtual async Task ProcessStreamAsync()
    {
        try
        {
            while (!_cancellationTokenSource.Token.IsCancellationRequested)
            {
                var result = await ReadAsync();
                if (result.IsCompleted)
                {
                    break;
                }

                OnDataReceived(result.Buffer.ToArray());
                _pipe.Reader.AdvanceTo(result.Buffer.End);
            }
        }
        catch (OperationCanceledException)
        {
            // Normal cancellation, ignore
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing stream for connection {Id}", Id);
        }
    }

    public virtual async ValueTask DisposeAsync()
    {
        if (_isDisposed)
        {
            return;
        }

        try
        {
            await StopAsync();
            _cancellationTokenSource.Dispose();
            _pipe.Reader.Complete();
            _pipe.Writer.Complete();
            _isDisposed = true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error disposing connection {Id}", Id);
            throw;
        }
    }
} 