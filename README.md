# Seed - Reverse Proxy Software

Seed is a high-performance reverse proxy software inspired by [frp](https://github.com/fatedier/frp), designed to help you expose services behind NAT or firewalls to the public internet through a server with a public IP address.

## Features

- **Client-Server Architecture**: Clients behind NAT connect to public servers
- **Protocol Support**: TCP and UDP reverse proxy tunneling
- **Multiple Encryption Options**:
  - TCP: TLS and SSH port forwarding
  - UDP: Custom O(1) byte mapping table encryption
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

# TCP Proxy Example
[web-server]
type = tcp
local_addr = 127.0.0.1
local_port = 80
remote_port = 8080
encrypt = true
encrypt_impl = tls

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
- Command line argument processing
- JWT token generation and verification  
- Protocol message handling
- Logging system functionality

### Code Style

- **Naming**: Linux style (lowercase with underscores)
- **Documentation**: Full Doxygen comments for public APIs
- **Headers**: No typedefs for structs, use `struct name` directly
- **Standards**: C99 compatible, cross-platform code

## Architecture

### Core Components

- **Logging Module** (`src/log.c`) - Colored logging with multiple levels
- **Configuration** (`src/config.c`) - INI file parsing and validation
- **Authentication** (`src/auth.c`, `src/jwt.c`) - JWT-based security
- **Network Core** (`src/network.c`) - libuv-based async networking
- **Protocol Handler** (`src/protocol.c`) - Binary message protocol
- **Server Mode** (`src/server.c`) - Client management and proxy registry
- **Client Mode** (`src/client.c`) - Server connection and tunnel management

### Project Structure
```
seed/
├── src/              # Source files (.c)
├── include/          # Public headers (.h)  
├── tests/            # Unit and integration tests
├── doc/              # Documentation
├── components/       # Third-party libraries
├── Makefile          # Linux/Unix build
├── seed.sln          # Windows Visual Studio solution
└── README.md         # This file
```

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
- [x] Comprehensive unit and integration tests

### 🚧 In Progress
- [ ] UDP proxy data forwarding
- [ ] TLS encryption for TCP
- [ ] SSH tunneling for TCP
- [ ] Table encryption for UDP

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

This project is released under [LICENSE]. See LICENSE file for details.

## Links

- **Documentation**: See `doc/` directory
  - `doc/requirements.md` - Original requirements
  - `doc/todos.md` - Development roadmap
  - `doc/protocol.md` - Protocol specification (planned)
  - `doc/developer.md` - Developer guide (planned)
  - `doc/user.md` - User manual (planned)
- **Tests**: See `tests/README.md`
- **Issues**: Report bugs and feature requests on GitHub