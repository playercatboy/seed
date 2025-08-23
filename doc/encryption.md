# Seed Reverse Proxy Encryption

This document describes the encryption features available in the Seed reverse proxy system.

## Overview

Seed supports multiple encryption methods to secure data transmission and configuration storage:

- **Table Encryption**: Fast, lightweight encryption for UDP traffic using byte substitution tables
- **Encrypted Auth Files**: Secure storage for authentication databases using table encryption
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

## Encrypted Authentication Files

Seed can store authentication databases in encrypted form to protect user credentials and JWT tokens from unauthorized access.

### How It Works

1. Authentication database is encrypted using table encryption with password-based key derivation
2. A magic header "SEED_AUTH_ENC_V1\n" is added for password validation
3. Wrong passwords are detected immediately without exposing authentication data
4. The same table encryption used for UDP packets provides file encryption

### Configuration

```bash
# Use encrypted auth file with command-line options
seed -e -p your_auth_password -f seed.conf

# The encrypted file (seed.auth.enc) replaces seed.auth
# Original plaintext auth files remain supported
```

### Security Features

- **Password Validation**: Magic header detects wrong passwords instantly
- **Data Protection**: Authentication tokens encrypted at rest
- **Backward Compatibility**: Plaintext auth files still supported
- **Command Integration**: Seamless integration with existing CLI options

### Usage Examples

```bash
# Start server with encrypted auth file
./seed -e -p myauthpassword -f server.conf

# Generate tokens and use encrypted storage
./seed -s userpassword  # Generate JWT token
# Manually add to encrypted auth file or convert existing plaintext file
```

## TLS Encryption (TCP)

TLS encryption provides cryptographically secure communication for TCP proxy connections using OpenSSL.

### Features

- **SSL/TLS Support**: Full SSL/TLS 1.2 and 1.3 support via OpenSSL
- **Client/Server Modes**: Both TLS client and server implementations
- **Certificate Authentication**: Client and server certificate validation
- **Security Features**: High-grade cipher suites, configurable security levels
- **Non-blocking Operation**: Memory BIO-based implementation for async I/O
- **Certificate Chain Validation**: Full certificate chain verification

### Configuration

```ini
[secure_web]
type = tcp
local_addr = 127.0.0.1
local_port = 443
remote_port = 443
encrypt = true
encrypt_impl = tls
tls_cert_file = /path/to/client.crt
tls_key_file = /path/to/client.key
tls_ca_file = /path/to/ca.crt
tls_verify_peer = true
```

### Security Features

- **High Security**: Security level 2 enforced (112-bit security)
- **Cipher Suite Control**: Excludes weak algorithms (aNULL, kRSA, PSK, SRP, MD5, RC4)
- **Certificate Validation**: Optional peer certificate verification
- **Perfect Forward Secrecy**: Supported cipher suites provide PFS
- **Error Handling**: Comprehensive SSL error reporting and handling

### TLS Handshake Process

1. **Context Creation**: SSL context initialized with certificates and configuration
2. **Connection Setup**: SSL connection created with memory BIOs for non-blocking I/O
3. **Handshake Processing**: Incremental handshake with proper state management
4. **Data Transfer**: Encrypted data exchange once handshake completes
5. **Connection Teardown**: Proper SSL shutdown and resource cleanup

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
- TLS encryption implementation using OpenSSL
- TLS context management with client/server modes
- Certificate loading and validation
- Non-blocking TLS handshake processing
- Encrypted authentication file storage
- Magic header validation for password verification
- Command-line options for encrypted auth (-e, -p)
- Encryption context management
- Configuration parsing for encryption options
- Base64 table export/import
- Comprehensive unit tests for all encryption features

### 🚧 Recently Completed
- TLS encryption integration with TCP proxies
- Configuration examples and documentation
- Integration with main application flow

### 📋 Planned
- SSH tunneling implementation using libssh
- Performance optimization for high-throughput scenarios
- Encryption key management and rotation
- Certificate authority integration
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

3. **Start the server with encrypted auth**:
```bash
./seed -e -p server_auth_password -f server.conf
```

### TLS TCP Encryption Setup

1. **Generate TLS certificates** (for testing):
```bash
# Create CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 365 -key ca.key -out ca.crt

# Create server certificate
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -out server.crt

# Create client certificate
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr  
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -out client.crt
```

2. **Server Configuration** (server.conf):
```ini
[seed]
mode = server
log_level = info

[server]
bind_addr = 0.0.0.0
bind_port = 7000
auth_file = server.auth

[tls_proxy]
type = tcp
local_addr = 127.0.0.1
local_port = 443
remote_port = 8443
encrypt = true
encrypt_impl = tls
tls_cert_file = server.crt
tls_key_file = server.key
tls_ca_file = ca.crt
tls_verify_peer = true
```

3. **Client Configuration** (client.conf):
```ini
[seed]
mode = client
log_level = info
server_addr = your-server.com
server_port = 7000
username = client1
password = clientpassword

[web_proxy]
type = tcp
local_addr = 127.0.0.1
local_port = 8080
remote_port = 443
encrypt = true
encrypt_impl = tls
tls_cert_file = client.crt
tls_key_file = client.key
tls_ca_file = ca.crt
tls_verify_peer = true
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