# Third-Party Components

This directory contains third-party libraries required by Seed. These libraries are not included in the repository and must be installed separately.

## Required Dependencies

### libuv
**Version**: 1.44.0 or later  
**Purpose**: High-performance, cross-platform async I/O library  
**License**: MIT License  
**Website**: https://libuv.org/

#### Installation
- **Windows**: Download precompiled binaries or build from source
- **Linux**: `sudo apt-get install libuv1-dev` (Ubuntu/Debian) or `sudo yum install libuv-devel` (CentOS/RHEL)

#### Directory Structure
```
components/libuv/
├── include/
│   └── uv.h
├── lib/
│   ├── libuv.a (static)
│   └── libuv.so (shared) 
└── README.md
```

### OpenSSL or MbedTLS
**Version**: OpenSSL 1.1.1+ or MbedTLS 3.0+  
**Purpose**: Cryptographic functions for TLS encryption and JWT tokens  
**License**: Apache License 2.0 (OpenSSL) / Apache License 2.0 (MbedTLS)

#### OpenSSL (Recommended)
- **Website**: https://www.openssl.org/
- **Windows**: Download from https://slproweb.com/products/Win32OpenSSL.html
- **Linux**: `sudo apt-get install libssl-dev`

#### Directory Structure (OpenSSL)
```
components/openssl/
├── include/
│   └── openssl/
├── lib/
│   ├── libssl.a
│   └── libcrypto.a
└── README.md
```

#### MbedTLS (Alternative)
- **Website**: https://www.trustedfirmware.org/projects/mbed-tls/
- **Usage**: Can be used instead of OpenSSL for smaller footprint

### libssh (Optional)
**Version**: 0.9.0 or later  
**Purpose**: SSH tunneling support for TCP encryption  
**License**: LGPL  
**Website**: https://www.libssh.org/

#### Installation
- **Windows**: Build from source or use vcpkg
- **Linux**: `sudo apt-get install libssh-dev`

#### Directory Structure
```
components/libssh/
├── include/
│   └── libssh/
├── lib/
│   └── libssh.a
└── README.md
```

## Installation Instructions

### Windows (Visual Studio)

1. **Create components directory structure**:
   ```cmd
   mkdir components\libuv components\openssl components\libssh
   ```

2. **Download and extract libraries**:
   - Extract libuv to `components/libuv/`
   - Extract OpenSSL to `components/openssl/`
   - Extract libssh to `components/libssh/` (optional)

3. **Verify paths in seed.vcxproj** match your library locations

### Linux (Make)

1. **Install system packages**:
   ```bash
   # Ubuntu/Debian
   sudo apt-get update
   sudo apt-get install libuv1-dev libssl-dev libssh-dev
   
   # CentOS/RHEL
   sudo yum install libuv-devel openssl-devel libssh-devel
   ```

2. **For custom builds, create symlinks**:
   ```bash
   mkdir -p components/libuv components/openssl components/libssh
   ln -s /usr/include components/libuv/include
   ln -s /usr/lib/x86_64-linux-gnu components/libuv/lib
   # Similar for other libraries
   ```

## Build Integration

### Visual Studio Project
The `seed.vcxproj` file includes these paths:
- Include directories: `$(ProjectDir)components\libuv\include;$(ProjectDir)components\openssl\include`  
- Library directories: `$(ProjectDir)components\libuv\lib;$(ProjectDir)components\openssl\lib`
- Additional dependencies: `libuv.lib;libssl.lib;libcrypto.lib`

### Makefile
The Makefile includes these settings:
- `CFLAGS`: `-I./components/libuv/include -I./components/openssl/include`
- `LDFLAGS`: `-L./components/libuv/lib -L./components/openssl/lib`  
- `LIBS`: `-luv -lssl -lcrypto`

## Version Compatibility

| Component | Minimum Version | Tested Version | Notes |
|-----------|----------------|----------------|-------|
| libuv | 1.44.0 | 1.48.0 | Core networking |
| OpenSSL | 1.1.1 | 3.0.0 | Cryptography |
| MbedTLS | 3.0.0 | 3.5.0 | OpenSSL alternative |
| libssh | 0.9.0 | 0.10.0 | SSH tunneling (optional) |

## Troubleshooting

### Common Issues

#### Windows
- **Missing DLLs**: Ensure OpenSSL DLLs are in PATH or copied to output directory
- **Architecture mismatch**: Use x64 libraries for x64 builds
- **Visual Studio version**: Ensure libraries are compatible with VS2022

#### Linux  
- **Package not found**: Update package manager cache
- **Wrong architecture**: Install appropriate dev packages (lib*-dev)
- **Permission errors**: Use sudo for system package installation

### Verification
Build and run the test suite to verify dependencies:
```bash
make test-standalone
```

If tests pass, all dependencies are correctly installed.

## License Information

This project uses the following third-party libraries:

- **libuv**: MIT License - https://github.com/libuv/libuv/blob/v1.x/LICENSE
- **OpenSSL**: Apache License 2.0 - https://www.openssl.org/source/license.html  
- **MbedTLS**: Apache License 2.0 - https://github.com/Mbed-TLS/mbedtls/blob/development/LICENSE
- **libssh**: LGPL 2.1 - https://www.libssh.org/license/

Please review each license for compliance requirements in your use case.