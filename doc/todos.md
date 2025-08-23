# Seed Implementation TODO List

## Top-Down Design Overview

### Layer 1: Main Application
- Entry point and initialization
- Command line argument parsing
- Configuration loading
- Mode selection (server/client)

### Layer 2: Core Components
- Logging system
- Configuration management
- Authentication/JWT handling
- Network event loop (libuv)

### Layer 3: Protocol Layer
- Protocol message definitions
- Message serialization/deserialization
- Control channel management
- Data channel management

### Layer 4: Proxy Implementation
- TCP proxy handler
- UDP proxy handler
- Encryption layer
  - TLS/SSH for TCP
  - Byte mapping table for UDP

### Layer 5: Mode-Specific Logic
- Server mode
  - Bind and listen
  - Client authentication
  - Port mapping management
- Client mode
  - Connect to server
  - Local service forwarding
  - Tunnel establishment

## Hierarchical TODO List

### 1. Project Setup
- [x] Create directory structure
- [ ] Set up Visual Studio 2022 solution
- [ ] Create Makefile for Linux
- [ ] Add .gitignore

### 2. Core Infrastructure
#### 2.1 Logging Module (src/log.c, include/log.h)
- [ ] Implement log levels (ERROR, WARNING, INFO, DEBUG)
- [ ] Add timestamp formatting
- [ ] Add color output support
- [ ] Thread-safe logging

#### 2.2 Configuration Module (src/config.c, include/config.h)
- [ ] INI parser integration
- [ ] Configuration structure definitions
- [ ] Configuration validation
- [ ] Default values handling

#### 2.3 Command Line Module (src/cmdline.c, include/cmdline.h)
- [ ] Argument parsing (-h, -v, -f, -s)
- [ ] Help text generation
- [ ] Version information

### 3. Security Components
#### 3.1 JWT Module (src/jwt.c, include/jwt.h)
- [ ] Password to JWT token hashing
- [ ] Token validation
- [ ] Integration with crypto library

#### 3.2 Authentication Module (src/auth.c, include/auth.h)
- [ ] Auth file parsing (seed.auth)
- [ ] User credential management
- [ ] Authentication verification

### 4. Network Foundation
#### 4.1 Network Core (src/network.c, include/network.h)
- [ ] libuv integration
- [ ] Event loop management
- [ ] Connection handling abstractions
- [ ] Buffer management

#### 4.2 Protocol Module (src/protocol.c, include/protocol.h)
- [ ] Message type definitions
- [ ] Protocol state machine
- [ ] Message encoding/decoding
- [ ] Control messages
  - [ ] AUTH request/response
  - [ ] PROXY_REQUEST/PROXY_RESPONSE
  - [ ] KEEPALIVE
  - [ ] ERROR

### 5. Proxy Implementation
#### 5.1 TCP Proxy (src/tcp_proxy.c, include/tcp_proxy.h)
- [ ] TCP connection establishment
- [ ] Data forwarding
- [ ] Connection pooling
- [ ] Error handling

#### 5.2 UDP Proxy (src/udp_proxy.c, include/udp_proxy.h)
- [ ] UDP socket handling
- [ ] Packet forwarding
- [ ] Session management

### 6. Encryption Layer
#### 6.1 TLS Module (src/tls.c, include/tls.h)
- [ ] OpenSSL/MbedTLS integration
- [ ] Certificate handling
- [ ] TLS handshake

#### 6.2 SSH Module (src/ssh.c, include/ssh.h)
- [ ] libssh integration
- [ ] SSH tunnel establishment

#### 6.3 Table Encryption (src/table_crypt.c, include/table_crypt.h)
- [ ] Byte mapping table generation
- [ ] Table exchange protocol
- [ ] Fast O(1) encryption/decryption

### 7. Mode Implementation
#### 7.1 Server Mode (src/server.c, include/server.h)
- [ ] Server initialization
- [ ] Client connection acceptance
- [ ] Authentication handling
- [ ] Port mapping registry
- [ ] Proxy request handling

#### 7.2 Client Mode (src/client.c, include/client.h)
- [ ] Server connection
- [ ] Authentication
- [ ] Proxy instance management
- [ ] Local service forwarding

### 8. Main Application (src/main.c)
- [ ] Application entry point
- [ ] Component initialization
- [ ] Mode selection and execution
- [ ] Graceful shutdown

### 9. Build System
#### 9.1 Windows Build
- [ ] Visual Studio 2022 solution file
- [ ] Project configurations (Debug/Release)
- [ ] Third-party library integration

#### 9.2 Linux Build
- [ ] Makefile creation
- [ ] Dependency management
- [ ] Installation targets

### 10. Testing
#### 10.1 Unit Tests
- [ ] Log module tests
- [ ] Config module tests
- [ ] Protocol module tests
- [ ] JWT module tests
- [ ] Encryption module tests

#### 10.2 Integration Tests
- [ ] Server-client communication
- [ ] TCP proxy functionality
- [ ] UDP proxy functionality
- [ ] Encryption verification

### 11. Documentation
- [ ] README.md with project overview
- [ ] doc/protocol.md - Protocol specification
- [ ] doc/developer.md - Build instructions
- [ ] doc/user.md - User guide
- [ ] Code documentation (Doxygen)

## Implementation Order

1. **Phase 1: Foundation**
   - Project structure
   - Build system
   - Logging module
   - Configuration module
   - Command line parsing

2. **Phase 2: Core Components**
   - JWT/Authentication
   - Network core with libuv
   - Basic protocol implementation

3. **Phase 3: Proxy Features**
   - TCP proxy
   - UDP proxy
   - Basic server/client modes

4. **Phase 4: Security**
   - TLS encryption
   - SSH tunneling
   - Table encryption for UDP

5. **Phase 5: Polish**
   - Testing
   - Documentation
   - Performance optimization