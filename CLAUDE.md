# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Seed is a reverse proxy software (inspired by frp) with client-server architecture that enables accessing services behind firewalls or NAT. The client connects to a public server and establishes reverse proxy tunnels for TCP/UDP traffic with optional encryption.

## Build Commands

**Windows (MSVC):**
```bash
# Build using MSBuild or Visual Studio solution file (to be created)
msbuild seed.sln /p:Configuration=Release
```

**Linux/Unix (GCC):**
```bash
# Build using Makefile (to be created)
make
make clean
make test
```

## Project Structure

```
seed/
├── src/              # Source files (.c)
├── include/          # Public headers (.h)
├── doc/              # Documentation
│   ├── requirements.md
│   ├── todos.md
│   ├── protocol.md
│   ├── developer.md
│   └── user.md
├── tests/            # Unit test files
├── components/       # Third-party libraries
│   ├── libuv/
│   ├── ini-parser/
│   ├── openssl or mbedtls/
│   └── libssh/
├── Makefile          # Linux/Unix build
├── seed.sln          # Windows MSVC solution
└── README.md         # Project overview with links
```

## Key Technical Requirements

- **Language**: C (cross-platform: Windows MSVC, Linux GCC)
- **Network**: IPv4 only, high-performance I/O using libuv
- **Protocols**: TCP and UDP reverse proxy support
- **Encryption**: 
  - TCP: SSH port forwarding or TLS (OpenSSL/MbedTLS)
  - UDP: Custom O(1) byte mapping table
- **Configuration**: INI format (seed.conf)
- **Authentication**: JWT tokens stored in seed.auth file

## Coding Conventions

1. **Naming**: Linux style - lowercase with underscores (e.g., `struct list_node`, `transfer_full_duplex()`)
2. **No typedefs for structs**: Use `struct xxx` directly
3. **Header guards**: `FILENAME_H` format (no underscores prefix/suffix)
4. **Documentation**: Full Doxygen comments for all public APIs
5. **File headers**: Include Doxygen file documentation

## Command Line Interface

```bash
seed [options]
  -h, --help          Print help and exit
  -v, --version       Print version and exit
  -f, --file <path>   Specify config file (default: ./seed.conf)
  -s, --hash <pass>   Hash password to JWT token
```

## Configuration File (seed.conf)

Server mode requires `[seed]` and `[server]` sections.
Client mode requires `[seed]` and proxy instance sections.

## Current Implementation Status

### ✅ Completed Components
- **Foundation**: Logging, configuration, command line parsing
- **Security**: JWT authentication with SHA256 hashing  
- **Network**: libuv-based async I/O with custom binary protocol
- **Server Mode**: Client session management and proxy registry
- **Client Mode**: Server authentication, proxy management, keepalive
- **TCP Proxy**: Full-duplex data forwarding with connection management
- **Testing**: Comprehensive unit tests and integration tests

### 🚧 In Progress
- UDP proxy data forwarding
- Encryption layers (TLS/SSH/Table)

### 📋 Next Steps
- Complete UDP proxy implementation
- Add encryption support for TCP (TLS/SSH) and UDP (Table)
- Performance optimization
- Advanced monitoring and statistics

## Development Workflow

1. Follow hierarchical TODO list in doc/todos.md
2. Implement components incrementally with unit tests
3. Test functionality with standalone tests  
4. Run full test suite: `make test`
5. Commit with descriptive messages following conventional commits

## Testing

```bash
make test              # Run comprehensive test suite
make test-individual   # Run unit tests separately  
make test-standalone   # Run integration tests
```

All core components have been tested and verified working.