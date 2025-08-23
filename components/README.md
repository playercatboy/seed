# Third-Party Components

This directory contains third-party libraries required by Seed. The source code for these libraries has been downloaded into this directory but is excluded from the repository via .gitignore.

## Required Dependencies

### libuv
**Version**: 1.51.0+ (currently v1.51.0-51-g3b1ac021)  
**Purpose**: High-performance, cross-platform async I/O library  
**License**: MIT License  
**Website**: https://libuv.org/  
**Git Repository**: https://github.com/libuv/libuv.git  
**Current Commit SHA**: `3b1ac021e323b3e2c460941dec6242176df6ef16`

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
**Version**: OpenSSL 3.4.0+ or MbedTLS 3.0+  
**Purpose**: Cryptographic functions for JWT tokens and future TLS encryption  
**License**: Apache License 2.0 (OpenSSL) / Apache License 2.0 (MbedTLS)
**Note**: Table encryption for UDP uses built-in algorithms and doesn't require OpenSSL

#### OpenSSL (Recommended)
- **Website**: https://www.openssl.org/
- **Git Repository**: https://github.com/openssl/openssl.git
- **Current Version**: 3.4.0-alpha1+ (openssl-3.4.0-alpha1-2156-g53eb2363a1)
- **Current Commit SHA**: `53eb2363a1e6336a40a64b3f7b9f09eca95fabef`
- **Windows**: Download from https://slproweb.com/products/Win32OpenSSL.html or build from source
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
**Version**: 0.11.0+ (currently libssh-0.11.0-289-g118a747a)  
**Purpose**: SSH tunneling support for TCP encryption  
**License**: LGPL 2.1  
**Website**: https://www.libssh.org/  
**Git Repository**: https://git.libssh.org/projects/libssh.git  
**Current Commit SHA**: `118a747acd1151e45dcf3eb154d48814209a2214`

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

### inih (INI Parser)
**Version**: r61 (release 61)  
**Purpose**: Simple INI file parser for configuration management  
**License**: BSD 3-Clause  
**Website**: https://github.com/benhoyt/inih  
**Git Repository**: https://github.com/benhoyt/inih.git  
**Current Commit SHA**: `3eda303b34610adc0554bdea08d02a25668c774c`

#### Directory Structure
```
components/inih/
├── ini.c
├── ini.h
├── examples/
├── tests/
└── README.md
```

## Installation Instructions

### Windows (Visual Studio)

1. **Download library source code**:
   ```cmd
   cd components
   git clone https://github.com/libuv/libuv.git
   git clone https://github.com/openssl/openssl.git
   git clone https://git.libssh.org/projects/libssh.git
   git clone https://github.com/benhoyt/inih.git
   ```

2. **Build libraries** (follow each library's build instructions):
   - libuv: Use CMake or Visual Studio project files
   - OpenSSL: Use Configure and nmake
   - libssh: Use CMake (optional)
   - inih: Copy ini.c/ini.h to project or build as static library

3. **Verify paths in seed.vcxproj** match your library locations

### Linux (Make)

**Option 1: Use system packages**:
   ```bash
   # Ubuntu/Debian
   sudo apt-get update
   sudo apt-get install libuv1-dev libssl-dev libssh-dev
   
   # CentOS/RHEL
   sudo yum install libuv-devel openssl-devel libssh-devel
   ```

**Option 2: Build from source**:
   ```bash
   cd components
   git clone https://github.com/libuv/libuv.git
   git clone https://github.com/openssl/openssl.git
   git clone https://git.libssh.org/projects/libssh.git
   git clone https://github.com/benhoyt/inih.git
   
   # Build each library according to their documentation
   # libuv: mkdir build && cd build && cmake .. && make
   # OpenSSL: ./Configure && make
   # libssh: mkdir build && cd build && cmake .. && make
   # inih: Copy ini.c/ini.h files to src/ directory
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

| Component | Minimum Version | Current Downloaded Version | Git Commit SHA | Notes |
|-----------|----------------|---------------------------|----------------|-------|
| libuv | 1.44.0 | v1.51.0-51-g3b1ac021 | `3b1ac021...` | Core networking |
| OpenSSL | 1.1.1 | 3.4.0-alpha1-2156-g53eb2363a1 | `53eb2363...` | Cryptography |
| MbedTLS | 3.0.0 | N/A (not downloaded) | N/A | OpenSSL alternative |
| libssh | 0.9.0 | libssh-0.11.0-289-g118a747a | `118a747a...` | SSH tunneling (optional) |
| inih | Any | r61 | `3eda303b...` | INI file parser |

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

### Source Code Management
The source code for all dependencies has been downloaded to the components directory:
- Libraries are excluded from the main repository via .gitignore
- To update a library: `cd components/<library> && git pull`
- To checkout a specific version: `cd components/<library> && git checkout <tag-or-commit>`
- Current versions are locked to the commit SHAs listed above for reproducible builds

## License Information

This project uses the following third-party libraries:

- **libuv**: MIT License - https://github.com/libuv/libuv/blob/v1.x/LICENSE
- **OpenSSL**: Apache License 2.0 - https://www.openssl.org/source/license.html  
- **MbedTLS**: Apache License 2.0 - https://github.com/Mbed-TLS/mbedtls/blob/development/LICENSE
- **libssh**: LGPL 2.1 - https://www.libssh.org/license/
- **inih**: BSD 3-Clause - https://github.com/benhoyt/inih/blob/master/LICENSE.txt

Please review each license for compliance requirements in your use case.