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
- **TCP/UDP echo server integration tests with multi-threading**
- **Cross-platform networking and socket programming**
- **Payload verification using memcmp() for data integrity**
- **End-to-end proxy flow simulation and validation**

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

### ✅ Completed Features
- [x] **Core Infrastructure**
  - Project architecture and build system (GCC/MinGW + MSVC cross-platform)
  - Logging system with colored output and multiple levels
  - INI configuration parsing and validation with encrypted auth support
  - Command line argument processing with comprehensive options
  
- [x] **Authentication & Security**
  - JWT authentication with SHA256 hashing
  - Encrypted authentication file storage with password protection
  - Token generation and verification system
  
- [x] **Networking & Protocol**
  - Custom binary protocol with CRC32 checksums
  - libuv-based async networking core with cross-platform socket support
  - Protocol message handling (Hello, Auth, Proxy Request/Response, Data, Error)
  
- [x] **Proxy Services**
  - Server mode with client session management and proxy registry
  - Client mode with server authentication and proxy management
  - TCP proxy with full-duplex data forwarding and connection management
  - UDP proxy with session management and packet forwarding
  
- [x] **Encryption System**
  - **Table encryption for UDP** with O(1) byte-substitution performance
  - **TLS encryption for TCP** using OpenSSL with full certificate support
  - **SSH tunneling for TCP** using libssh with authentication methods
  - Pluggable encryption architecture with configuration support
  - Cross-platform compatibility macros for MSVC and GCC
  
- [x] **Testing & Quality**
  - Comprehensive unit and integration test suite
  - Multi-threaded TCP/UDP echo server integration testing
  - End-to-end proxy flow simulation with payload verification
  - Cross-platform build validation (Windows MSVC + Linux GCC)
  
### 🚧 Current Status
- ✅ **GCC/MinGW Build**: Fully functional executable with working encryption
- ✅ **MSVC Build**: Source code compiles successfully, requires library linking
- ✅ **All encryption modules**: Implemented and ready for use
- ✅ **Remote Testing**: Client-server communication verified with remote Debian server
- ✅ **Bug Fixes**: Critical protocol serialization and configuration parsing issues resolved

### 🔧 Recent Updates (August 2025)
- **Fixed client configuration bug**: Client now properly reads server address from config instead of hardcoded localhost
- **Fixed protocol serialization**: HELLO message serialization now works correctly with proper return value handling  
- **Added standalone echo servers**: Created dedicated TCP (port 33000) and UDP (port 34000) echo servers for testing
- **Verified remote connectivity**: Successfully established client connection to remote server at 74.82.196.126:7000

### 📋 Future Enhancements
- [ ] OpenSSL/libssh library integration for MSVC builds
- [ ] Performance optimization and benchmarking
- [ ] IPv6 support
- [ ] Configuration hot-reload
- [ ] Web management interface
- [ ] Statistics and monitoring dashboard
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