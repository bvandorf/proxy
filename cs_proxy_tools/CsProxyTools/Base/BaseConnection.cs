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
        _logger.LogDebug("BaseConnection: OnConnectionStarted for {Id}", Id);
        _isConnected = true;
        ConnectionStarted?.Invoke(this, new ConnectionEventArgs(Id));
        _logger.LogDebug("BaseConnection: IsConnected set to true for {Id}", Id);
    }

    protected virtual void OnConnectionClosed()
    {
        _logger.LogDebug("BaseConnection: OnConnectionClosed for {Id}", Id);
        _isConnected = false;
        ConnectionClosed?.Invoke(this, new ConnectionEventArgs(Id));
        _logger.LogDebug("BaseConnection: IsConnected set to false for {Id}", Id);
    }

    protected virtual void OnDataReceived(ReadOnlyMemory<byte> data, string? remoteEndpoint = null)
    {
        if (remoteEndpoint != null)
        {
            DataReceived?.Invoke(this, new DataReceivedEventArgs(Id, data, remoteEndpoint));
        }
        else
        {
            DataReceived?.Invoke(this, new DataReceivedEventArgs(Id, data));
        }
    }

    protected virtual void OnDataReceived(DataReceivedEventArgs args)
    {
        DataReceived?.Invoke(this, args);
    }

    public virtual async Task StartAsync(CancellationToken cancellationToken = default)
    {
        _logger.LogDebug("BaseConnection: StartAsync called for {Id}", Id);
        if (_isDisposed)
        {
            _logger.LogWarning("BaseConnection: StartAsync called on disposed object {Id}", Id);
            throw new ObjectDisposedException(nameof(BaseConnection));
        }

        try
        {
            _logger.LogDebug("BaseConnection: Calling StartConnectionAsync for {Id}", Id);
            await StartConnectionAsync();
            _logger.LogDebug("BaseConnection: StartConnectionAsync completed for {Id}", Id);
            _logger.LogDebug("BaseConnection: Triggering ConnectionStarted event for {Id}", Id);
            OnConnectionStarted();
            _logger.LogDebug("BaseConnection: Starting ProcessStreamAsync for {Id}", Id);
            _ = ProcessStreamAsync();
            _logger.LogDebug("BaseConnection: StartAsync completed for {Id}", Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "BaseConnection: Error starting connection {Id}", Id);
            throw;
        }
    }

    public virtual async Task StopAsync(CancellationToken cancellationToken = default)
    {
        _logger.LogDebug("BaseConnection: StopAsync called for {Id}", Id);
        if (_isDisposed)
        {
            _logger.LogDebug("BaseConnection: StopAsync called on disposed object {Id}, ignoring", Id);
            return;
        }

        try
        {
            _logger.LogDebug("BaseConnection: Cancelling token source for {Id}", Id);
            _cancellationTokenSource.Cancel();
            _logger.LogDebug("BaseConnection: Calling StopConnectionAsync for {Id}", Id);
            await StopConnectionAsync();
            _logger.LogDebug("BaseConnection: StopConnectionAsync completed for {Id}", Id);
            _logger.LogDebug("BaseConnection: Triggering ConnectionClosed event for {Id}", Id);
            OnConnectionClosed();
            _logger.LogDebug("BaseConnection: StopAsync completed for {Id}", Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "BaseConnection: Error stopping connection {Id}", Id);
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
        _logger.LogDebug("BaseConnection: ProcessStreamAsync started for {Id}", Id);
        try
        {
            while (!_cancellationTokenSource.Token.IsCancellationRequested)
            {
                _logger.LogTrace("BaseConnection: Reading from pipe for {Id}", Id);
                var result = await ReadAsync();
                if (result.IsCompleted)
                {
                    _logger.LogDebug("BaseConnection: Pipe read completed for {Id}", Id);
                    break;
                }

                _logger.LogDebug("BaseConnection: Processing {Length} bytes for {Id}", result.Buffer.Length, Id);
                OnDataReceived(result.Buffer.ToArray());
                _pipe.Reader.AdvanceTo(result.Buffer.End);
            }
            _logger.LogDebug("BaseConnection: ProcessStreamAsync normal exit for {Id}", Id);
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("BaseConnection: ProcessStreamAsync canceled for {Id}", Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "BaseConnection: Error processing stream for connection {Id}", Id);
        }
        _logger.LogDebug("BaseConnection: ProcessStreamAsync completed for {Id}", Id);
    }

    public virtual async ValueTask DisposeAsync()
    {
        _logger.LogDebug("BaseConnection: DisposeAsync called for {Id}", Id);
        if (_isDisposed)
        {
            _logger.LogDebug("BaseConnection: DisposeAsync called on already disposed object {Id}, ignoring", Id);
            return;
        }

        try
        {
            _logger.LogDebug("BaseConnection: Calling StopAsync for {Id}", Id);
            await StopAsync();
            _logger.LogDebug("BaseConnection: Disposing cancellation token for {Id}", Id);
            _cancellationTokenSource.Dispose();
            _logger.LogDebug("BaseConnection: Completing pipe reader and writer for {Id}", Id);
            _pipe.Reader.Complete();
            _pipe.Writer.Complete();
            _isDisposed = true;
            _logger.LogDebug("BaseConnection: DisposeAsync completed for {Id}", Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "BaseConnection: Error disposing connection {Id}", Id);
            throw;
        }
    }
} 