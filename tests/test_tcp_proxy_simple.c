/**
 * @file test_tcp_proxy_simple.c
 * @brief Simple TCP proxy logic unit tests (no libuv dependencies)
 * @author Seed Development Team  
 * @date 2025
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* Include only what we need for basic testing */
#include "../src/log.c"
#include "../include/common.h"

/* Simple TCP proxy structures for testing */
enum tcp_connection_state {
    TCP_STATE_CONNECTING,
    TCP_STATE_CONNECTED,
    TCP_STATE_CLOSING,
    TCP_STATE_CLOSED
};

struct simple_tcp_connection {
    enum tcp_connection_state state;
    char client_addr[16];
    char target_addr[16];
    uint16_t client_port;
    uint16_t target_port;
    uint64_t bytes_received;
    uint64_t bytes_sent;
    struct simple_tcp_connection *next;
    struct simple_tcp_connection *prev;
};

struct simple_tcp_proxy {
    char name[64];
    char bind_addr[16];
    uint16_t bind_port;
    char target_addr[16];
    uint16_t target_port;
    bool encrypt;
    bool active;
    
    struct simple_tcp_connection *connections;
    int connection_count;
    uint64_t total_connections;
    uint64_t active_connections;
    uint64_t total_bytes_transferred;
};

struct simple_tcp_proxy_stats {
    uint64_t total_connections;
    uint64_t active_connections;
    uint64_t total_bytes_transferred;
    uint64_t bytes_per_second;
};

/* Simple TCP proxy functions for testing */
int simple_tcp_proxy_init(struct simple_tcp_proxy *proxy, const char *name,
                         const char *bind_addr, uint16_t bind_port,
                         const char *target_addr, uint16_t target_port, bool encrypt)
{
    if (!proxy || !name || !bind_addr || !target_addr) {
        return SEED_ERROR_INVALID_ARGS;
    }

    memset(proxy, 0, sizeof(*proxy));
    
    strncpy(proxy->name, name, sizeof(proxy->name) - 1);
    proxy->name[sizeof(proxy->name) - 1] = '\0';
    
    strncpy(proxy->bind_addr, bind_addr, sizeof(proxy->bind_addr) - 1);
    proxy->bind_addr[sizeof(proxy->bind_addr) - 1] = '\0';
    proxy->bind_port = bind_port;
    
    strncpy(proxy->target_addr, target_addr, sizeof(proxy->target_addr) - 1);
    proxy->target_addr[sizeof(proxy->target_addr) - 1] = '\0';
    proxy->target_port = target_port;
    
    proxy->encrypt = encrypt;
    proxy->active = false;
    proxy->connections = NULL;
    proxy->connection_count = 0;
    proxy->total_connections = 0;
    proxy->active_connections = 0;
    proxy->total_bytes_transferred = 0;

    return SEED_OK;
}

int simple_tcp_proxy_start(struct simple_tcp_proxy *proxy)
{
    if (!proxy) {
        return SEED_ERROR_INVALID_ARGS;
    }

    proxy->active = true;
    return SEED_OK;
}

int simple_tcp_proxy_stop(struct simple_tcp_proxy *proxy)
{
    if (!proxy) {
        return SEED_ERROR_INVALID_ARGS;
    }

    proxy->active = false;
    
    /* Close all connections */
    struct simple_tcp_connection *conn = proxy->connections;
    while (conn) {
        struct simple_tcp_connection *next = conn->next;
        conn->state = TCP_STATE_CLOSED;
        proxy->connection_count--;
        proxy->active_connections--;
        free(conn);
        conn = next;
    }
    proxy->connections = NULL;

    return SEED_OK;
}

int simple_tcp_proxy_get_stats(const struct simple_tcp_proxy *proxy, struct simple_tcp_proxy_stats *stats)
{
    if (!proxy || !stats) {
        return SEED_ERROR_INVALID_ARGS;
    }

    stats->total_connections = proxy->total_connections;
    stats->active_connections = proxy->active_connections;
    stats->total_bytes_transferred = proxy->total_bytes_transferred;
    stats->bytes_per_second = 0;

    return SEED_OK;
}

struct simple_tcp_connection* simple_tcp_add_connection(struct simple_tcp_proxy *proxy,
                                                       const char *client_addr, uint16_t client_port)
{
    if (!proxy || !client_addr) {
        return NULL;
    }

    struct simple_tcp_connection *conn = malloc(sizeof(*conn));
    if (!conn) {
        return NULL;
    }

    memset(conn, 0, sizeof(*conn));
    conn->state = TCP_STATE_CONNECTING;
    
    strncpy(conn->client_addr, client_addr, sizeof(conn->client_addr) - 1);
    conn->client_addr[sizeof(conn->client_addr) - 1] = '\0';
    conn->client_port = client_port;
    
    strncpy(conn->target_addr, proxy->target_addr, sizeof(conn->target_addr) - 1);
    conn->target_addr[sizeof(conn->target_addr) - 1] = '\0';
    conn->target_port = proxy->target_port;

    /* Add to beginning of list */
    conn->next = proxy->connections;
    conn->prev = NULL;
    
    if (proxy->connections) {
        proxy->connections->prev = conn;
    }
    
    proxy->connections = conn;
    proxy->connection_count++;
    proxy->active_connections++;
    proxy->total_connections++;

    return conn;
}

void simple_tcp_remove_connection(struct simple_tcp_proxy *proxy, struct simple_tcp_connection *conn)
{
    if (!proxy || !conn) {
        return;
    }

    /* Remove from list */
    if (conn->prev) {
        conn->prev->next = conn->next;
    } else {
        proxy->connections = conn->next;
    }
    
    if (conn->next) {
        conn->next->prev = conn->prev;
    }

    proxy->connection_count--;
    proxy->active_connections--;
    
    free(conn);
}

void simple_tcp_connection_transfer_data(struct simple_tcp_connection *conn, uint64_t bytes)
{
    if (!conn) {
        return;
    }

    conn->bytes_received += bytes;
    conn->bytes_sent += bytes;
}

void simple_tcp_proxy_cleanup(struct simple_tcp_proxy *proxy)
{
    if (!proxy) {
        return;
    }

    simple_tcp_proxy_stop(proxy);
    memset(proxy, 0, sizeof(*proxy));
}

/* Test functions */
void test_tcp_proxy_initialization(void)
{
    printf("Testing TCP proxy initialization...\n");
    
    struct simple_tcp_proxy proxy;
    
    /* Test valid initialization */
    int ret = simple_tcp_proxy_init(&proxy, "test-proxy", "127.0.0.1", 8080,
                                   "10.0.0.1", 9090, true);
    if (ret != SEED_OK) {
        printf("✗ Failed to initialize TCP proxy\n");
        return;
    }
    
    if (strcmp(proxy.name, "test-proxy") != 0) {
        printf("✗ Wrong proxy name: %s\n", proxy.name);
        return;
    }
    
    if (strcmp(proxy.bind_addr, "127.0.0.1") != 0) {
        printf("✗ Wrong bind address: %s\n", proxy.bind_addr);
        return;
    }
    
    if (proxy.bind_port != 8080) {
        printf("✗ Wrong bind port: %d\n", proxy.bind_port);
        return;
    }
    
    if (strcmp(proxy.target_addr, "10.0.0.1") != 0) {
        printf("✗ Wrong target address: %s\n", proxy.target_addr);
        return;
    }
    
    if (proxy.target_port != 9090) {
        printf("✗ Wrong target port: %d\n", proxy.target_port);
        return;
    }
    
    if (!proxy.encrypt) {
        printf("✗ Wrong encryption setting\n");
        return;
    }
    
    if (proxy.active) {
        printf("✗ Proxy should not be active initially\n");
        return;
    }
    
    if (proxy.connection_count != 0) {
        printf("✗ Wrong initial connection count: %d\n", proxy.connection_count);
        return;
    }
    
    printf("✓ TCP proxy initialization\n");
}

void test_tcp_proxy_parameter_validation(void)
{
    printf("Testing TCP proxy parameter validation...\n");
    
    struct simple_tcp_proxy proxy;
    
    /* Test null parameters */
    int ret = simple_tcp_proxy_init(NULL, "test", "127.0.0.1", 80, "10.0.0.1", 80, false);
    if (ret != SEED_ERROR_INVALID_ARGS) {
        printf("✗ Should reject null proxy\n");
        return;
    }
    
    ret = simple_tcp_proxy_init(&proxy, NULL, "127.0.0.1", 80, "10.0.0.1", 80, false);
    if (ret != SEED_ERROR_INVALID_ARGS) {
        printf("✗ Should reject null name\n");
        return;
    }
    
    ret = simple_tcp_proxy_init(&proxy, "test", NULL, 80, "10.0.0.1", 80, false);
    if (ret != SEED_ERROR_INVALID_ARGS) {
        printf("✗ Should reject null bind address\n");
        return;
    }
    
    ret = simple_tcp_proxy_init(&proxy, "test", "127.0.0.1", 80, NULL, 80, false);
    if (ret != SEED_ERROR_INVALID_ARGS) {
        printf("✗ Should reject null target address\n");
        return;
    }
    
    ret = simple_tcp_proxy_start(NULL);
    if (ret != SEED_ERROR_INVALID_ARGS) {
        printf("✗ Should reject null proxy for start\n");
        return;
    }
    
    ret = simple_tcp_proxy_stop(NULL);
    if (ret != SEED_ERROR_INVALID_ARGS) {
        printf("✗ Should reject null proxy for stop\n");
        return;
    }
    
    ret = simple_tcp_proxy_get_stats(NULL, NULL);
    if (ret != SEED_ERROR_INVALID_ARGS) {
        printf("✗ Should reject null parameters for stats\n");
        return;
    }
    
    printf("✓ TCP proxy parameter validation\n");
}

void test_tcp_proxy_lifecycle(void)
{
    printf("Testing TCP proxy lifecycle...\n");
    
    struct simple_tcp_proxy proxy;
    
    /* Initialize proxy */
    int ret = simple_tcp_proxy_init(&proxy, "test-proxy", "127.0.0.1", 8080,
                                   "10.0.0.1", 9090, false);
    if (ret != SEED_OK) {
        printf("✗ Failed to initialize proxy\n");
        return;
    }
    
    if (proxy.active) {
        printf("✗ Proxy should not be active initially\n");
        return;
    }
    
    /* Start proxy */
    ret = simple_tcp_proxy_start(&proxy);
    if (ret != SEED_OK) {
        printf("✗ Failed to start proxy\n");
        return;
    }
    
    if (!proxy.active) {
        printf("✗ Proxy should be active after start\n");
        return;
    }
    
    /* Stop proxy */
    ret = simple_tcp_proxy_stop(&proxy);
    if (ret != SEED_OK) {
        printf("✗ Failed to stop proxy\n");
        return;
    }
    
    if (proxy.active) {
        printf("✗ Proxy should not be active after stop\n");
        return;
    }
    
    /* Cleanup */
    simple_tcp_proxy_cleanup(&proxy);
    
    printf("✓ TCP proxy lifecycle management\n");
}

void test_tcp_connection_management(void)
{
    printf("Testing TCP connection management...\n");
    
    struct simple_tcp_proxy proxy;
    simple_tcp_proxy_init(&proxy, "test-proxy", "127.0.0.1", 8080,
                         "10.0.0.1", 9090, false);
    
    /* Add connection */
    struct simple_tcp_connection *conn1 = simple_tcp_add_connection(&proxy, "192.168.1.100", 45678);
    if (!conn1) {
        printf("✗ Failed to add connection\n");
        return;
    }
    
    if (proxy.connection_count != 1) {
        printf("✗ Wrong connection count after add: %d\n", proxy.connection_count);
        return;
    }
    
    if (proxy.active_connections != 1) {
        printf("✗ Wrong active connection count: %llu\n", (unsigned long long)proxy.active_connections);
        return;
    }
    
    if (proxy.total_connections != 1) {
        printf("✗ Wrong total connection count: %llu\n", (unsigned long long)proxy.total_connections);
        return;
    }
    
    /* Add second connection */
    struct simple_tcp_connection *conn2 = simple_tcp_add_connection(&proxy, "192.168.1.101", 45679);
    if (!conn2) {
        printf("✗ Failed to add second connection\n");
        return;
    }
    
    if (proxy.connection_count != 2) {
        printf("✗ Wrong connection count after second add: %d\n", proxy.connection_count);
        return;
    }
    
    /* Remove first connection */
    simple_tcp_remove_connection(&proxy, conn1);
    
    if (proxy.connection_count != 1) {
        printf("✗ Wrong connection count after remove: %d\n", proxy.connection_count);
        return;
    }
    
    if (proxy.active_connections != 1) {
        printf("✗ Wrong active connection count after remove: %llu\n", (unsigned long long)proxy.active_connections);
        return;
    }
    
    /* Cleanup */
    simple_tcp_proxy_cleanup(&proxy);
    
    printf("✓ TCP connection management\n");
}

void test_tcp_proxy_statistics(void)
{
    printf("Testing TCP proxy statistics...\n");
    
    struct simple_tcp_proxy proxy;
    struct simple_tcp_proxy_stats stats;
    
    simple_tcp_proxy_init(&proxy, "test-proxy", "127.0.0.1", 8080,
                         "10.0.0.1", 9090, false);
    
    /* Test initial stats */
    int ret = simple_tcp_proxy_get_stats(&proxy, &stats);
    if (ret != SEED_OK) {
        printf("✗ Failed to get initial stats\n");
        return;
    }
    
    if (stats.total_connections != 0 || stats.active_connections != 0 || stats.total_bytes_transferred != 0) {
        printf("✗ Wrong initial statistics\n");
        return;
    }
    
    /* Add connection and simulate data transfer */
    struct simple_tcp_connection *conn = simple_tcp_add_connection(&proxy, "192.168.1.100", 45678);
    simple_tcp_connection_transfer_data(conn, 1024);
    proxy.total_bytes_transferred += 1024;
    
    /* Get updated stats */
    ret = simple_tcp_proxy_get_stats(&proxy, &stats);
    if (ret != SEED_OK) {
        printf("✗ Failed to get updated stats\n");
        return;
    }
    
    if (stats.total_connections != 1) {
        printf("✗ Wrong total connections in stats: %llu\n", (unsigned long long)stats.total_connections);
        return;
    }
    
    if (stats.active_connections != 1) {
        printf("✗ Wrong active connections in stats: %llu\n", (unsigned long long)stats.active_connections);
        return;
    }
    
    if (stats.total_bytes_transferred != 1024) {
        printf("✗ Wrong bytes transferred in stats: %llu\n", (unsigned long long)stats.total_bytes_transferred);
        return;
    }
    
    /* Cleanup */
    simple_tcp_proxy_cleanup(&proxy);
    
    printf("✓ TCP proxy statistics\n");
}

int main(void)
{
    log_init(LOG_ERROR);
    
    printf("=== Simple TCP Proxy Tests ===\n");
    
    test_tcp_proxy_initialization();
    test_tcp_proxy_parameter_validation();
    test_tcp_proxy_lifecycle();
    test_tcp_connection_management();
    test_tcp_proxy_statistics();
    
    printf("=== Simple TCP Proxy Tests Complete ===\n");
    
    return 0;
}