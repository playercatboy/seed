# Seed Architecture Documentation

This document describes the current architecture and implementation details of the Seed reverse proxy software.

## System Overview

Seed is implemented as a high-performance, event-driven reverse proxy using a client-server architecture. The system is built in C with cross-platform support for Windows and Linux.

### Core Design Principles

1. **Asynchronous I/O**: Uses libuv for non-blocking network operations
2. **Event-Driven**: Single-threaded event loop architecture
3. **Binary Protocol**: Custom binary protocol with integrity checking
4. **Security First**: JWT authentication with strong cryptography
5. **Configuration-Driven**: INI-based configuration for flexibility

## Architecture Layers

### Layer 1: Foundation Infrastructure

#### Logging System (`src/log.c`, `include/log.h`)
- **Features**: Multiple log levels (ERROR, WARNING, INFO, DEBUG)
- **Output**: Colored console output with timestamps
- **Thread Safety**: Safe for single-threaded event loop model
- **Format**: `[YYYY-MM-DD HH:MM:SS](L) Message [file:line]`

#### Configuration Management (`src/config.c`, `include/config.h`)
- **Parser**: INI format using inih library
- **Validation**: Comprehensive configuration validation
- **Support**: Server and client mode configurations
- **Structure**: Hierarchical configuration with sections

#### Command Line Interface (`src/cmdline.c`, `include/cmdline.h`)
- **Options**: Help, version, config file, password hashing
- **Compatibility**: Custom getopt implementation for Windows
- **Integration**: Direct integration with JWT token generation

### Layer 2: Security and Authentication

#### JWT Authentication (`src/jwt.c`, `include/jwt.h`)
- **Algorithm**: HMAC-SHA256 signatures
- **Format**: Standard JWT with header.payload.signature
- **Hashing**: SHA256 for password hashing
- **Platform**: Windows CryptoAPI and OpenSSL support

#### Authentication Database (`src/auth.c`, `include/auth.h`)
- **Format**: Simple text file with username:token pairs
- **Storage**: In-memory database with file persistence
- **Capacity**: Support for up to 100 users (configurable)

### Layer 3: Network Protocol

#### Protocol Definition (`src/protocol.c`, `include/protocol.h`)
- **Format**: Binary protocol with fixed headers
- **Integrity**: CRC32 checksums for all messages
- **Versioning**: Protocol version negotiation
- **Types**: Hello, Auth, Proxy requests, Data transfer, Keepalive, Error

```c
struct protocol_header {
    uint32_t magic;          // Protocol magic number
    uint16_t version;        // Protocol version  
    uint16_t type;           // Message type
    uint32_t flags;          // Message flags
    uint32_t sequence;       // Sequence number
    uint32_t length;         // Payload length
    uint32_t checksum;       // Header checksum
};
```

#### Network Core (`src/network.c`, `include/network.h`)
- **Engine**: libuv-based async networking
- **Connections**: Support for 1024 concurrent connections
- **Buffers**: 64KB receive/send buffers per connection
- **Management**: Connection lifecycle, error handling, cleanup

### Layer 4: Application Logic

#### Server Mode (`src/server.c`, `include/server.h`)
- **Client Sessions**: Management of authenticated client connections
- **Proxy Registry**: Mapping of client proxies to server ports
- **Authentication**: JWT-based client authentication flow
- **Capacity**: 1024 concurrent clients, 256 proxy mappings

#### Client Mode (`src/client.c` - stub)
- **Status**: Implementation stub (planned)
- **Purpose**: Connect to server and establish tunnels
- **Features**: Multiple proxy instances, tunnel management

### Layer 5: Data Forwarding (Planned)

#### TCP Proxy (`src/tcp_proxy.c` - stub)
- **Purpose**: TCP connection forwarding
- **Features**: Full-duplex data transfer
- **Encryption**: TLS and SSH support

#### UDP Proxy (`src/udp_proxy.c` - stub)  
- **Purpose**: UDP packet forwarding
- **Features**: Stateless packet relay
- **Encryption**: Custom byte mapping table

#### Encryption Modules (stubs)
- `src/tls.c` - TLS encryption for TCP
- `src/ssh.c` - SSH tunneling for TCP  
- `src/table_crypt.c` - Table encryption for UDP

## Memory Management

### Buffer Management
- **Connection Buffers**: 64KB receive + 64KB send per connection
- **Message Buffers**: Dynamic allocation for protocol messages
- **Cleanup**: Automatic cleanup on connection close

### Resource Limits
- **Max Connections**: 1024 (configurable via MAX_CONNECTIONS)
- **Max Users**: 100 (configurable via MAX_USERS)
- **Max Proxies**: 256 (configurable via MAX_PROXY_MAPPINGS)
- **Max Proxy Instances**: 100 per client (MAX_PROXY_INSTANCES)

### Memory Safety
- **Bounds Checking**: All buffer operations are bounds-checked
- **Safe Allocation**: SAFE_FREE macro for null-safe memory cleanup
- **No Memory Leaks**: Comprehensive cleanup on shutdown

## Threading Model

### Single-Threaded Event Loop
- **Main Thread**: All operations on single libuv event loop
- **No Locks**: No synchronization primitives needed
- **Callbacks**: All I/O operations use callback-based model
- **Scalability**: High concurrency through async I/O

## Error Handling

### Error Codes
```c
#define SEED_OK 0
#define SEED_ERROR -1
#define SEED_ERROR_INVALID_ARGS -2
#define SEED_ERROR_FILE_NOT_FOUND -3
#define SEED_ERROR_PERMISSION_DENIED -4
#define SEED_ERROR_OUT_OF_MEMORY -5
#define SEED_ERROR_NETWORK -6
#define SEED_ERROR_AUTH_FAILED -7
#define SEED_ERROR_CONFIG -8
#define SEED_ERROR_PROTOCOL -9
```

### Error Propagation
- **Return Codes**: Consistent error code returns
- **Logging**: Error conditions logged with context
- **Graceful Degradation**: Non-fatal errors don't crash system

## Configuration Architecture

### Server Configuration
```ini
[seed]
mode = server
log_level = info

[server]  
bind_addr = 0.0.0.0
bind_port = 7000
auth_file = seed.auth
```

### Client Configuration
```ini
[seed]
mode = client

[proxy-name]
type = tcp|udp
local_addr = 127.0.0.1
local_port = 8080
remote_port = 8080
encrypt = true|false
encrypt_impl = tls|ssh|table
```

## Build Architecture

### Cross-Platform Build
- **Windows**: Visual Studio 2022 solution (seed.sln/seed.vcxproj)
- **Linux**: GNU Make with GCC
- **Dependencies**: libuv, OpenSSL/MbedTLS, libssh

### Test Architecture
- **Unit Tests**: Individual module testing
- **Integration Tests**: Cross-module functionality
- **Test Framework**: Custom assertion framework
- **Coverage**: All implemented modules tested

## Performance Characteristics

### Throughput (Estimated)
- **Connections**: 1000+ concurrent connections
- **Bandwidth**: Limited by network and CPU, not architecture
- **Latency**: Single-digit millisecond overhead

### Memory Usage (Estimated)
- **Base**: ~1MB base memory usage
- **Per Connection**: ~128KB (buffers + structures)  
- **1000 Connections**: ~128MB total memory usage

## Security Architecture

### Authentication Flow
1. Client connects to server
2. Client sends HELLO message
3. Client sends AUTH_REQUEST with username/password
4. Server validates against JWT database
5. Server responds with AUTH_RESPONSE (success/failure)
6. Authenticated clients can create proxy mappings

### Encryption (Planned)
- **TCP**: TLS 1.3 or SSH tunneling
- **UDP**: Custom byte mapping table with key exchange
- **Authentication**: HMAC-SHA256 signatures for JWT tokens

## Current Implementation Status

### Completed (100%)
- ✅ Foundation infrastructure (logging, config, cmdline)
- ✅ Security infrastructure (JWT, authentication)
- ✅ Network protocol (binary protocol, message handling)  
- ✅ Network core (libuv integration, connection management)
- ✅ Server mode (client sessions, proxy registry)
- ✅ Testing framework (unit tests, integration tests)

### In Progress (0-50%)
- 🚧 Client mode implementation
- 🚧 TCP/UDP data forwarding
- 🚧 Encryption implementations

### Planned (0%)
- 📋 Performance optimization
- 📋 IPv6 support
- 📋 Advanced monitoring
- 📋 Web management interface

## Technical Decisions

### Why libuv?
- Cross-platform async I/O
- High performance event loop
- Excellent C API
- Used by Node.js (proven scalability)

### Why Custom Protocol?
- Optimized for reverse proxy use case
- Efficient binary format
- Built-in integrity checking
- Extensible message types

### Why JWT for Authentication?
- Stateless authentication
- Standard format
- Strong cryptographic signatures
- Easy to implement and verify

## Future Architecture Considerations

### Scalability Improvements
- Multi-threading for CPU-intensive operations
- Connection pooling optimizations
- Zero-copy networking where possible

### Feature Additions
- HTTP/2 and HTTP/3 support
- WebSocket tunneling
- Load balancing capabilities
- Health checking and failover

This architecture provides a solid foundation for a high-performance reverse proxy with room for future enhancements.