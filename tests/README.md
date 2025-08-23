# Seed Test Suite

This directory contains the comprehensive test suite for the Seed reverse proxy project.

## Test Organization

### Unit Tests
- `test_framework.c/.h` - Custom test framework with assertion macros
- `test_config.c` - Configuration module unit tests
- `test_cmdline.c` - Command line parsing unit tests  
- `test_jwt.c` - JWT token generation/verification unit tests
- `test_protocol.c` - Protocol message handling unit tests

### Integration Tests
- `test_integration_simple.c` - Basic integration test combining multiple modules
- `test_jwt_standalone.c` - Standalone JWT functionality test
- `test_cmdline_standalone.c` - Standalone command line test with JWT integration
- `test_full_integration.c` - Comprehensive TCP/UDP proxy integration test
- `test_seed_integration.c` - Practical integration test with echo servers
- `test_echo_simple.c` - Multi-threaded TCP/UDP echo server test
- `test_proxy_concept.c` - Conceptual proxy flow demonstration

### Test Runner
- `run_tests.c` - Comprehensive test runner that executes all unit tests

## Running Tests

### Prerequisites
- GCC compiler (Windows: MinGW-W64, Linux: build-essential)
- Make (for automated building)

### Test Commands

#### Comprehensive Test Suite
```bash
make test
```
Runs all unit tests through the test runner framework.

#### Individual Unit Tests  
```bash
make test-individual
```
Builds and runs each unit test separately.

#### Standalone Integration Tests
```bash
make test-standalone
```
Builds and runs integration tests that verify module interactions.

#### Manual Test Building
```bash
# Build specific test
gcc -Wall -Wextra -I../include -o test_jwt_standalone test_jwt_standalone.c ../src/log.c ../src/jwt.c

# Run test
./test_jwt_standalone
```

## Test Coverage

### ✅ Implemented Tests
- **Configuration Loading** - INI parsing, validation, server/client configs
- **Command Line Parsing** - All options (-h, -v, -f, -s), error handling
- **JWT Authentication** - Token generation, verification, password hashing
- **Protocol Messages** - Serialization, deserialization, validation, CRC32
- **Logging System** - Log levels, formatting, color output
- **Client Mode Logic** - Proxy management, state handling, parameter validation
- **TCP Proxy Logic** - Connection management, lifecycle, statistics tracking
- **TCP/UDP Echo Servers** - Multi-threaded echo server implementation
- **Cross-Platform Networking** - Windows and Linux socket programming
- **Data Integrity Verification** - memcmp() payload validation
- **Thread Management** - Platform-specific threading (POSIX/Windows)
- **End-to-End Proxy Flow** - Complete proxy simulation testing

### 📋 Future Tests
- Network layer integration tests (requires libuv runtime)
- Server mode integration tests with live connections
- UDP proxy tests (when implemented)
- Encryption module tests (when implemented)

## Test Framework Features

- **Simple Assertions** - ASSERT_TRUE, ASSERT_FALSE, ASSERT_EQUAL, ASSERT_STR_EQUAL
- **Test Organization** - TEST_SUITE and TEST_CASE macros
- **Statistics** - Pass/fail counts and summary reports
- **Cross-Platform** - Works on Windows and Linux

## Example Test Output

### JWT Test
```
=== JWT Standalone Test ===
✓ JWT generation successful
Token length: 226
Token preview: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
✓ JWT verification successful  
✓ JWT correctly rejected wrong password
=== JWT Test Complete ===
```

### Integration Test
```
Seed Integration Test - Echo Server Verification
================================================
Test payload: 'Hello, Seed Proxy Test!' (size: 24 bytes)

=== Starting Echo Servers ===
TCP Echo: Server listening on port 33000
UDP Echo: Server listening on port 34000

=== Testing TCP Echo ===
✓ TCP Client connected to server
✓ TCP Client sent 24 bytes: Hello, Seed Proxy Test!
✓ TCP Client received 24 bytes: Hello, Seed Proxy Test!
✅ TCP memcmp() verification PASSED!

=== Testing UDP Echo ===
✓ UDP Client sent 24 bytes: Hello, Seed Proxy Test!
✓ UDP Client received 24 bytes: Hello, Seed Proxy Test!
✅ UDP memcmp() verification PASSED!

=== TEST SUMMARY ===
TCP Echo Test: ✅ PASSED
UDP Echo Test: ✅ PASSED
memcmp() Verification: ✅ PASSED

✅ ALL TESTS PASSED!
```

## Adding New Tests

1. Create test file in tests/ directory
2. Include test_framework.h for unit tests
3. Use assertion macros to verify functionality
4. Add to Makefile TEST_SRCS or STANDALONE_TESTS as appropriate
5. Document in this README

## Build System Integration

Tests are integrated into the main Makefile with these targets:
- `make clean` - Removes all test executables and build files
- `make help` - Shows all available test targets
- Tests can be built with debug symbols using `make debug`