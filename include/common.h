/**
 * @file common.h
 * @brief Common definitions and includes for Seed reverse proxy
 * @author Seed Development Team
 * @date 2025
 */

#ifndef COMMON_H
#define COMMON_H

/* Standard includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>

/* Platform-specific includes */
#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
#endif

/* Version information */
#define SEED_VERSION_MAJOR 1
#define SEED_VERSION_MINOR 0
#define SEED_VERSION_PATCH 0
#define SEED_VERSION_STRING "1.0.0"

/* Default values */
#define DEFAULT_SERVER_PORT 7000
#define DEFAULT_CONFIG_FILE "seed.conf"
#define DEFAULT_AUTH_FILE "seed.auth"
#define DEFAULT_LOG_LEVEL LOG_ERROR

/* Buffer sizes */
#define MAX_PATH_LENGTH 256
#define MAX_LINE_LENGTH 1024
#define MAX_TOKEN_LENGTH 512
#define BUFFER_SIZE 65536

/* Network constants */
#define MAX_CONNECTIONS 1024
#define KEEPALIVE_INTERVAL 30
#define CONNECTION_TIMEOUT 60

/* Error codes */
#define SEED_OK 0
#define SEED_ERROR -1
#define SEED_ERROR_INVALID_ARGS -2
#define SEED_ERROR_FILE_NOT_FOUND -3
#define SEED_ERROR_PERMISSION_DENIED -4
#define SEED_ERROR_OUT_OF_MEMORY -5
#define SEED_ERROR_NETWORK -6
#define SEED_ERROR_AUTH_FAILED -7
#define SEED_ERROR_CONFIG -8
#define SEED_ERROR_PROTOCOL -9
#define SEED_ERROR_NOT_IMPLEMENTED -10
#define SEED_ERROR_CONNECTION_CLOSED -11

/* Utility macros */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

/* Memory allocation macros */
#define SAFE_FREE(ptr) do { if (ptr) { free(ptr); ptr = NULL; } } while(0)
#define SAFE_CLOSE(fd) do { if (fd >= 0) { close(fd); fd = -1; } } while(0)

#endif /* COMMON_H */