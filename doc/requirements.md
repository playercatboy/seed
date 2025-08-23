# Seed
Seed is a reverse proxy software. inspired by frp (https://github.com/fatedier/frp).

This program is a client-server architecture. Typically, the client is behind the firewall or NAT (like home environment), the server is on a VPS which has public IP address.

The server listens on a port, the client connects to the server, then talks to it with proxy requests and configurations. If the server accepts the proxy request, it talks to the client success. Then the client requested protocol-port combo is mapped to the server side to achieve reverse proxy.

Once port mapped to the public server. Any other user can access the seed server's protocol-port combo, it just like accessing the services behind the firewall or NAT.

Seed supports optional encrypted communication. The client can choose to use it or not. As for TCP, the encryption can be implemented by SSH port forwarding, or by TLS. As for UDP, consider its use cases, the encryption can be implemented by simply O(1) table, which just maps the order of UINT8s to another UINT8s. the map table should be exchanged with both client and server side during encryption handshake.

## 1. Platforms and implementation requirements
1. Use C to implement Seed.
2. Seed should be able to compile both under Windows via MSVC or under UNIX (currently Linux) via GCC.
3. Implementation should be high performance.
4. 3rd-party libraries allowed: 
    * Any INI file reader library.
    * libuv for high-performance I/O.
    * libssh for SSH port forward encryption implementation.
    * OpenSSL or MbedTLS for TLS encryption implementation.
    * Any string to JWT token generator, prioritize to implementated by crtypto libraries.
5. Tidy code hierarchy:
    * Sources should be placed under `src/`
    * Public headers should be placed under `include/`
    * Documentation should be placed under `doc/`
    * Test cases should be placed under `tests/`
    * All 3rd-party libraries should be placed under `components/`
    * Makefile / MSBuild / Visual Studio solution file should be placed under project root dir.
6. Implement IPv4 only.

## 2. Command line arguments requirements
Seed is designed to have this command line interface:
```bash
$ seed [options]

options:
    -h, --help              Print help information and exit.
    -v, --version           Print Seed version and exit.
    -f, --file              Specify Seed configuration file. defaults to $PWD/seed.conf.
    -s, --hash password     Hash a password to JWT token.
```

## 3. Configuration file requirements
Seed uses traditional INI format as configuration file. the configuration file name defaults to `seed.conf`.

```ini
; global seed configuration section
;
;   @applies-to:   server, client
;   @required:     true
[seed]
; seed working mode
;
;   @applies-to:      server, client
;   @required:        true
;   @values-allowed:  'server' or 'client'
mode        = server
; seed log level
;
;   @applies-to:      server, client
;   @required:        optinal, defaults to 'error'
;   @values-allowed:  'error', 'warning', 'info', 'debug'
log_level   = error


; server configuration section
;
;   @applies-to:   server
;   @required:     true, only if server mode
[server]
; server bind address
;   @required:        true
;   @values-allowed:  valid ipv4 address
bind_addr = 0.0.0.0
; server bind port
;   @required:        true
;   @values-allowed:  valid port number
bind_port = 7000
; authencitaion database file location
;   @required:        true
;   @values-allowed:  string. can be absolute path or path relative to current working directory
auth_file = seed.auth


; down below are all client configurations.
; the server only checks for 'seed' and 'server' section
; the client only checks for 'seed' and non 'server' section


; proxy instance name (in this instace, 'proxy-instance-name-1')
;
;   @required:      true
;   @value-allowed: string
[proxy-instance-name-1]
; proxy type
;   @required:        true
;   @values-allowed:  'tcp' or 'udp'
type            = tcp
; local address which the proxy will forward to
;   @required:        true
;   @values-allowed:  valid ipv4 address
local_addr      = 127.0.0.1
; local port which the proxy will forward to
;   @required:        true
;   @values-allowed:  valid port number
local_port      = 8080
; remote port which will mapped to the seed server
;   @required:        true
;   @values-allowed:  valid port number
remote_port     = 8080
; use encryption
;   @required:        optinal, defaults to 'true'
;   @values-allowed:  'true' or 'false'
encrypt         = true
; use encryption
;   @required:        true, if 'encrypt' is 'true'
;   @values-allowed:  if 'type' is 'tcp', 'ssh' or 'tls'
;                     if 'type' is 'udp', 'table'
encrypt_impl    = tls


; another proxy instance
[proxy-instance-name-2]
type            = udp
local_addr      = 127.0.0.1
local_port      = 9999
remote_port     = 9999
encrypt         = true
encrypt_impl    = table
```

## 4. Authencitaion database file requirements
It's a simple text file, each line maps a user with jwt token, which looks like this:

```
user-one: jwt-token-of-user-two
user-two: jwt-token-of-user-two
```

Since the client may send the password as clear text, then server hash it to JWT tokens and compare it, you should find a way to safely exchange the user password.

## 5. Encryption requirements
As for TCP, the encryption can be implemented by SSH port forwarding, or by TLS.

As for UDP, consider its use cases, the encryption can be implemented by simply O(1) table, which just maps the order of UINT8s to another UINT8s. The map table should be exchanged with both client and server side during encryption handshake, find a way to safely exchange the map table.

## 6. Logging requirements
Should NOT use 3rd-party logging libraried. Just implement a `printf()` (or similar function) wrapper, which prints like this:

```
[2025-08-23 12:30:00](E) Error log entry.
[2025-08-23 12:30:00](W) Warning log entry.
[2025-08-23 12:30:00](I) Information log entry.
[2025-08-23 12:30:00](D) Debug log entry.
```

The log should be colored as:
* Error: red
* Warning: yellow
* Information: default style
* Debug: blue

## 7. Coding conventions
Seed should follow these coding conventions:

### 7.1. Use Linux style.
Only use lower case letters and underscores. Unless macro constants, upper case is not allowed. Structures should not be type defined, just use `struct xxx`.

### 7.2. Add full doxygen comment to global variables, macro definitions, functions, structs and struct members. mind the alignments:

```c
/** Global variables */
int value = 42;

/** Macro definitions */
#define PATH_MAX    256

/** Structures */
struct list_node {
    struct list_node *prev; /** Previous member */
    struct list_node *next; /** Next member */
};

/**
 * @brief       Full duplex transfer.
 *
 * @param[in]       fd          File descriptor.
 * @param[in,out]   data        Data to transfer and receive.
 * @param[in]       length      Length of the data.
 *
 * @return          Negative errno
 *     @retval      0           No error
 *     @retval      -EINVAL     Invalid argument
 *     @retval      -ENOMEM     Low memory
 */
int transfer_full_duplex(int fd, void *data, size_t length)
{
    /* Implementation */
}
```

### 7.3. Add doxygen file header.

### 7.4. The inclusion protect macro should be the file name with an 'h', all upper case, no underscore prefix and suffix. add comments to endifs:

```c
// if file name is protocol_control_block.h, then it is:
#ifndef PROTOCOL_CONTROL_BLOCK_H
#define PROTOCOL_CONTROL_BLOCK_H
#endif /* PROTOCOL_CONTROL_BLOCK_H */
```

## 8. Documentation requirements
1. All documentations should be placed inside `doc/` dir.
2. This file is `requirements.md` which talks about requirements.
3. Seed protocol should be documented as `doc/protocol.md`.
4. Developers' manual which talks about compiling Seed should be documented as `doc/developer.md`.
5. Users' manual which talks about configuring Seed (especially installing, seed config file and systemd service configuration) should be documented as `doc/user.md`.
6. Seed brief should be places under project root dir, named as `README.md` and contain links to other documentations.

## 9. Claude requirements
Analyse the requirements and do a top-down design first, then summarise a hierarchycal TODO list, also from top to down. Save the TODO list to file `doc/todos.md`.

Implement components one by one. On each component finished, write test cases (unit test) to test it, then test it, fix it, finally git commit.
