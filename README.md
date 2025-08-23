# Seed - Reverse Proxy Software

Seed is a high-performance reverse proxy software inspired by [frp](https://github.com/fatedier/frp), designed to help you expose services behind NAT or firewalls to the public internet through a server with a public IP address.

## Features

- **Client-Server Architecture**: Clients behind NAT connect to public servers
- **Protocol Support**: TCP and UDP reverse proxy tunneling
- **Multiple Encryption Options**:
  - **UDP**: Table-based encryption with O(1) performance (implemented)
  - **TCP**: TLS encryption and SSH tunneling (implemented)
- **JWT Authentication**: Secure token-based authentication system
- **High Performance**: Built with libuv for async I/O operations
- **Cross-Platform**: Windows (MSVC) and Linux (GCC) support
- **Configuration-Driven**: Simple INI-based configuration files

## Quick Start

### Installation

#### Windows (Visual Studio 2022)
```cmd
git clone https://github.com/yourusername/seed.git
cd seed
# Install dependencies (libuv, OpenSSL) to components/ directory
msbuild seed.sln /p:Configuration=Release
```

#### Linux/Unix
```bash
git clone https://github.com/yourusername/seed.git
cd seed
# Install dependencies: libuv-dev, libssl-dev
make release
```

### Generate Authentication Token

```bash
# Generate JWT token for password
seed -s yourpassword

# Add output to seed.auth file
echo "username: <generated-jwt-token>" >> seed.auth

# Or use encrypted auth file with password protection
seed -e -p mypassword  # Uses encrypted seed.auth.enc file
```

### Server Mode

Create `seed.conf`:
```ini
[seed]
mode = server
log_level = info

[server]
bind_addr = 0.0.0.0
bind_port = 7000
auth_file = seed.auth
```

Start server:
```bash
seed -f seed.conf
```

### Client Mode

Create `seed.conf`:
```ini
[seed]
mode = client
log_level = info

[http-proxy]
type = tcp
local_addr = 127.0.0.1
local_port = 8080
remote_port = 8080
encrypt = true
encrypt_impl = tls
```

Start client:
```bash
seed -f seed.conf
```

## Configuration

### Server Configuration
```ini
[seed]
mode = server
log_level = info|warning|error|debug

[server]
bind_addr = 0.0.0.0       # IP to bind to
bind_port = 7000          # Port to listen on  
auth_file = seed.auth     # Authentication database
```

### Client Configuration
```ini
[seed]
mode = client
log_level = info

# TCP Proxy Example with TLS Encryption
[web-server]
type = tcp
local_addr = 127.0.0.1
local_port = 80
remote_port = 8080
encrypt = true
encrypt_impl = tls
tls_cert_file = /path/to/client.crt
tls_key_file = /path/to/client.key
tls_ca_file = /path/to/ca.crt
tls_verify_peer = true

# TCP Proxy Example with SSH Tunneling
[secure-app]
type = tcp
local_addr = 127.0.0.1
local_port = 3000
remote_port = 3000
encrypt = true
encrypt_impl = ssh
ssh_host = ssh-server.example.com
ssh_port = 22
ssh_username = username
ssh_password = password
ssh_remote_host = localhost
ssh_remote_port = 3000

# UDP Proxy Example  
[game-server]
type = udp
local_addr = 127.0.0.1
local_port = 27015
remote_port = 27015
encrypt = true
encrypt_impl = table
```

## Authentication

Seed uses JWT tokens for authentication. The authentication database (`seed.auth`) format:

```
# Format: username: jwt-token
admin: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
user1: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Encrypted Authentication Files

For enhanced security, Seed supports encrypted authentication files:

```bash
# Use encrypted auth file
seed -e -p your_password -f seed.conf

# The encrypted file (seed.auth.enc) is protected with table encryption
# Wrong passwords are detected via magic header validation
```

Generate tokens using:
```bash
seed -s <password>
```

## Protocol

Seed uses a custom binary protocol with the following features:

- **Message Types**: Hello, Authentication, Proxy Requests, Data Transfer, Keepalive
- **Integrity**: CRC32 checksums for all messages
- **Versioning**: Protocol version negotiation
- **Efficiency**: Binary format with minimal overhead

## Development

### Building from Source

#### Prerequisites
- **Windows**: Visual Studio 2022, libuv, OpenSSL
- **Linux**: GCC, make, libuv-dev, libssl-dev, libssh-dev

#### Dependencies
Place third-party libraries in `components/` directory:
```
components/
├── libuv/
├── openssl/ or mbedtls/
└── libssh/
```

#### Build Commands
```bash
make               # Build release version
make debug         # Build debug version  
make test          # Run comprehensive tests
make clean         # Clean build files
make install       # Install to system
```

### Testing

Comprehensive test suite with multiple test types:

```bash
make test              # Full test suite
make test-individual   # Unit tests only
make test-standalone   # Integration tests
```

Test coverage includes:
- Configuration parsing and validation
- Command line argument processing with encrypted auth support
- JWT token generation and verification  
- Protocol message handling
- Logging system functionality
- Table encryption and key management
- TLS encryption with certificate handling
- UDP proxy encryption integration
- Encryption manager functionality
- Encrypted authentication file storage and retrieval

### Code Style

- **Naming**: Linux style (lowercase with underscores)
- **Documentation**: Full Doxygen comments for public APIs
- **Headers**: No typedefs for structs, use `struct name` directly
- **Standards**: C99 compatible, cross-platform code

## Architecture

### Core Components

- **Logging Module** (`src/log.c`) - Colored logging with multiple levels
- **Configuration** (`src/config.c`) - INI file parsing and validation
- **Authentication** (`src/auth.c`, `src/jwt.c`) - JWT-based security with encrypted file support
- **Network Core** (`src/network.c`) - libuv-based async networking
- **Protocol Handler** (`src/protocol.c`) - Binary message protocol
- **Server Mode** (`src/server.c`) - Client management and proxy registry
- **Client Mode** (`src/client.c`) - Server connection and tunnel management
- **Encryption Manager** (`src/encrypt.c`) - Pluggable encryption architecture
- **Table Encryption** (`src/table_encrypt.c`) - Fast UDP packet encryption
- **TLS Encryption** (`src/tls_encrypt.c`) - OpenSSL-based TCP encryption
- **SSH Tunneling** (`src/ssh_encrypt.c`) - SSH-based secure TCP tunneling

### Project Structure
```
seed/
├── src/              # Source files (.c)
├── include/          # Public headers (.h)  
├── tests/            # Unit and integration tests
├── doc/              # Documentation (see doc/encryption.md)
├── examples/         # Configuration examples
├── components/       # Third-party libraries
├── Makefile          # Linux/Unix build
├── seed.sln          # Windows Visual Studio solution
└── README.md         # This file
```

### Documentation

- **[Encryption Guide](doc/encryption.md)** - Complete encryption setup and usage
- **[Developer Guide](doc/developer.md)** - Architecture and development info
- **[Configuration Examples](examples/)** - Sample configurations for various scenarios

## Implementation Status

### ✅ Completed
- [x] Project architecture and build system
- [x] Logging system with colored output
- [x] INI configuration parsing and validation
- [x] Command line argument processing
- [x] JWT authentication with SHA256 hashing
- [x] Binary protocol with CRC32 checksums
- [x] libuv-based async networking core
- [x] Server mode with client session management
- [x] Client mode with server authentication and proxy management
- [x] TCP proxy with full-duplex data forwarding
- [x] UDP proxy with session management and packet forwarding
- [x] **Encryption subsystem with pluggable architecture**
- [x] **Table encryption for UDP with O(1) performance**
- [x] **TLS encryption for TCP using OpenSSL with full certificate support**
- [x] **Encrypted authentication file storage with password protection**
- [x] **Encryption manager and configuration support**
- [x] Comprehensive unit and integration tests

### 🚧 Planned (Future Releases)
- [ ] SSH tunneling for TCP using libssh

### 📋 Planned
- [ ] Performance optimization
- [ ] IPv6 support
- [ ] Configuration hot-reload
- [ ] Web management interface
- [ ] Statistics and monitoring
- [ ] Systemd service integration

## Contributing

1. Follow the coding conventions in `CLAUDE.md`
2. Write tests for new functionality
3. Update documentation
4. Submit pull requests

## License

This project is released under the MIT License. See LICENSE file for details.

## Links

- **Documentation**: See `doc/` directory
  - `doc/requirements.md` - Original requirements
  - `doc/todos.md` - Development roadmap
  - `doc/protocol.md` - Protocol specification (planned)
  - `doc/developer.md` - Developer guide (planned)
  - `doc/user.md` - User manual (planned)
- **Tests**: See `tests/README.md`
- **Issues**: Report bugs and feature requests on GitHub