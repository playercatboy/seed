# Seed Reverse Proxy Encryption

This document describes the encryption features available in the Seed reverse proxy system.

## Overview

Seed supports multiple encryption methods to secure data transmission between clients, servers, and target services:

- **Table Encryption**: Fast, lightweight encryption for UDP traffic using byte substitution tables
- **TLS Encryption**: Industry-standard SSL/TLS encryption for TCP traffic (planned)  
- **SSH Tunneling**: Secure shell tunneling for TCP traffic (planned)

## Table Encryption (UDP)

Table encryption provides fast, O(1) per-byte encryption suitable for UDP packet forwarding where low latency is critical.

### How It Works

1. A 256-byte lookup table is generated from a password using SHA-256 seeding
2. Each byte in the UDP packet is replaced with the corresponding byte from the table
3. The inverse table is used for decryption
4. Encryption/decryption is performed in-place for maximum performance

### Configuration

```ini
[udp_proxy]
type = udp
local_addr = 127.0.0.1
local_port = 8080
remote_port = 8080
encrypt = true
encrypt_impl = table
encrypt_password = your_secure_password_here
```

### Security Considerations

- Use strong, unique passwords for each proxy instance
- Table encryption provides obfuscation rather than cryptographic security
- Suitable for gaming, streaming, and other UDP applications where speed > security
- Consider firewall rules and access controls as additional security layers

### Performance

- Overhead: ~1 CPU cycle per byte (O(1) complexity)
- Memory: 512 bytes per proxy instance (encrypt + decrypt tables)
- Latency impact: Minimal (<1ms for typical packet sizes)

## TLS Encryption (TCP) - Planned

TLS encryption will provide cryptographically secure communication for TCP proxy connections.

### Planned Features

- SSL/TLS 1.2 and 1.3 support via OpenSSL
- Client and server certificate authentication
- Perfect Forward Secrecy (PFS)
- Configurable cipher suites
- Certificate chain validation

### Planned Configuration

```ini
[tcp_proxy]
type = tcp
local_addr = 127.0.0.1
local_port = 443
remote_port = 443
encrypt = true
encrypt_impl = tls
tls_cert_file = /path/to/cert.pem
tls_key_file = /path/to/key.pem
tls_ca_file = /path/to/ca.pem
tls_verify_peer = true
```

## SSH Tunneling (TCP) - Planned

SSH tunneling will provide secure shell-based port forwarding for TCP connections.

### Planned Features

- SSH protocol version 2
- Key-based and password authentication
- Port forwarding (local and remote)
- Connection multiplexing
- Host key verification

### Planned Configuration

```ini
[tcp_proxy]
type = tcp
local_addr = 127.0.0.1
local_port = 5432
remote_port = 5432
encrypt = true
encrypt_impl = ssh
ssh_host = target.example.com
ssh_port = 22
ssh_username = proxyuser
ssh_private_key = /path/to/ssh_key
ssh_known_hosts = /path/to/known_hosts
```

## Implementation Status

### ✅ Completed
- Table encryption core implementation
- UDP proxy integration with table encryption
- Encryption context management
- Configuration parsing for encryption options
- Base64 table export/import
- Comprehensive unit tests

### 🚧 In Progress
- Configuration examples and documentation
- Integration with main application flow

### 📋 Planned
- TLS encryption implementation using OpenSSL
- SSH tunneling implementation using libssh
- Performance optimization for high-throughput scenarios
- Encryption key management and rotation
- Monitoring and logging for encrypted connections

## Usage Examples

### Basic UDP Encryption Setup

1. **Server Configuration** (server.conf):
```ini
[seed]
mode = server
log_level = info

[server]
bind_addr = 0.0.0.0
bind_port = 7000
auth_file = server.auth
```

2. **Client Configuration** (client.conf):
```ini
[seed]
mode = client
log_level = info
server_addr = your-server.com
server_port = 7000
username = client1
password = clientpassword

[game_proxy]
type = udp
local_addr = 127.0.0.1
local_port = 25565
remote_port = 25565
encrypt = true
encrypt_impl = table
encrypt_password = minecraft_encryption_123
```

3. **Start the server**:
```bash
./seed -f server.conf
```

4. **Start the client**:
```bash
./seed -f client.conf
```

5. **Connect your application**:
```bash
# Application connects to localhost:25565
# Traffic is encrypted between client and server
# Server forwards decrypted traffic to target:25565
```

## Security Best Practices

1. **Password Management**:
   - Use unique passwords for each proxy instance
   - Store passwords securely (consider environment variables)
   - Rotate passwords periodically
   - Use strong passwords (20+ characters, mixed case, numbers, symbols)

2. **Network Security**:
   - Use firewalls to restrict access to proxy ports
   - Consider VPN or private networks for additional security
   - Monitor connection logs for suspicious activity
   - Use authentication tokens (JWT) for client-server connections

3. **Deployment Security**:
   - Run with minimal privileges
   - Use secure file permissions for configuration files
   - Enable logging and monitoring
   - Keep the software updated

## Troubleshooting

### Common Issues

1. **"Failed to decrypt packet from client"**:
   - Check that both client and server use the same encryption password
   - Verify the proxy configuration matches on both sides
   - Ensure the client is connecting to the correct port

2. **Performance Issues with Encryption**:
   - Table encryption has minimal overhead; check network latency
   - Monitor CPU usage during high-traffic scenarios
   - Consider adjusting buffer sizes for large transfers

3. **Configuration Errors**:
   - Validate INI syntax with a parser
   - Check file paths and permissions
   - Review log messages for specific error details

### Debug Commands

```bash
# Enable debug logging
./seed -f config.conf --log-level debug

# Test table encryption independently  
./test_table_encrypt_simple

# Test UDP proxy with encryption
./test_udp_encryption_simple
```

## API Reference

For developers integrating encryption into custom applications, see:

- `include/table_encrypt.h` - Table encryption API
- `include/encrypt.h` - Main encryption manager API
- `src/table_encrypt.c` - Implementation reference
- `tests/test_*_simple.c` - Usage examples

## Performance Benchmarks

*Benchmarks will be added as development progresses*

| Encryption Type | Throughput | Latency Overhead | CPU Usage |
|------------------|------------|------------------|-----------|
| Table (UDP)      | TBD       | <1ms            | <1%       |
| TLS (TCP)        | TBD       | TBD             | TBD       |
| SSH (TCP)        | TBD       | TBD             | TBD       |

## Contributing

To contribute to the encryption features:

1. Review the existing code in `src/table_encrypt.c`
2. Follow the established patterns for new encryption methods
3. Add comprehensive tests for all new functionality
4. Update documentation and examples
5. Test performance impact on target use cases

## License

The encryption features are part of the Seed reverse proxy project and are subject to the same license terms as the main project.