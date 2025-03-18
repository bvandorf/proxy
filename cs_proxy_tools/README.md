# CsProxyTools

A C# library providing asynchronous TCP and TLS server/client implementations for proxy tools.

## Features

- Asynchronous TCP Server
- Asynchronous TLS Server
- Asynchronous TCP Client
- Asynchronous TLS Client
- Support for multiple concurrent connections
- Event-based communication
- Proper resource cleanup and disposal
- Comprehensive error handling and logging

## Requirements

- .NET 7.0 or later
- For TLS functionality, valid X.509 certificates

## Installation

Add the package to your project using NuGet:

```bash
dotnet add package CsProxyTools
```

## Usage

### TCP Server

```csharp
using CsProxyTools.Servers;
using Microsoft.Extensions.Logging;

var logger = LoggerFactory.Create(builder => builder.AddConsole()).CreateLogger<TcpServer>();
var server = new TcpServer(logger, "127.0.0.1", 5000);

server.ClientConnected += (sender, args) => Console.WriteLine($"Client connected: {args.ConnectionId}");
server.ClientDisconnected += (sender, args) => Console.WriteLine($"Client disconnected: {args.ConnectionId}");
server.DataReceived += (sender, args) => Console.WriteLine($"Received {args.Data.Length} bytes from {args.ConnectionId}");

await server.StartAsync();
```

### TLS Server

```csharp
using CsProxyTools.Servers;
using Microsoft.Extensions.Logging;

var logger = LoggerFactory.Create(builder => builder.AddConsole()).CreateLogger<TlsServer>();
var server = new TlsServer(logger, "127.0.0.1", 5000, "certificate.pfx", "password");

server.ClientConnected += (sender, args) => Console.WriteLine($"Client connected: {args.ConnectionId}");
server.ClientDisconnected += (sender, args) => Console.WriteLine($"Client disconnected: {args.ConnectionId}");
server.DataReceived += (sender, args) => Console.WriteLine($"Received {args.Data.Length} bytes from {args.ConnectionId}");

await server.StartAsync();
```

### TCP Client

```csharp
using CsProxyTools.Clients;
using Microsoft.Extensions.Logging;

var logger = LoggerFactory.Create(builder => builder.AddConsole()).CreateLogger<TcpClient>();
var client = new TcpClient(logger, "127.0.0.1", 5000);

client.Connected += (sender, args) => Console.WriteLine("Connected to server");
client.Disconnected += (sender, args) => Console.WriteLine("Disconnected from server");
client.DataReceived += (sender, args) => Console.WriteLine($"Received {args.Data.Length} bytes");

await client.ConnectAsync();
```

### TLS Client

```csharp
using CsProxyTools.Clients;
using Microsoft.Extensions.Logging;

var logger = LoggerFactory.Create(builder => builder.AddConsole()).CreateLogger<TlsClient>();
var client = new TlsClient(logger, "127.0.0.1", 5000, validateCertificate: true);

client.Connected += (sender, args) => Console.WriteLine("Connected to server");
client.Disconnected += (sender, args) => Console.WriteLine("Disconnected from server");
client.DataReceived += (sender, args) => Console.WriteLine($"Received {args.Data.Length} bytes");

await client.ConnectAsync();
```

## Events

All components provide the following events:

- `ConnectionStarted`/`Connected`: Fired when a connection is established
- `ConnectionClosed`/`Disconnected`: Fired when a connection is closed
- `DataReceived`: Fired when data is received from the remote endpoint

## Error Handling

The library includes comprehensive error handling and logging. All operations are wrapped in try-catch blocks and log errors using the provided logger.

## Resource Management

All components implement `IAsyncDisposable` and should be properly disposed when no longer needed:

```csharp
await using var server = new TcpServer(logger, "127.0.0.1", 5000);
// ... use the server ...
// Will be automatically disposed when the using block ends
```

## License

MIT License 