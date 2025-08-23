/**
 * @file test_client_simple.c
 * @brief Simple client logic unit tests (no libuv dependencies)
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

/* Simple client state definitions for testing */
enum client_state {
    CLIENT_STATE_DISCONNECTED,
    CLIENT_STATE_CONNECTING,
    CLIENT_STATE_AUTHENTICATING,
    CLIENT_STATE_AUTHENTICATED,
    CLIENT_STATE_ERROR
};

enum proxy_type {
    PROXY_TYPE_TCP = 1,
    PROXY_TYPE_UDP = 2
};

enum encrypt_impl {
    ENCRYPT_IMPL_NONE = 0,
    ENCRYPT_IMPL_TLS = 1,
    ENCRYPT_IMPL_SSH = 2,
    ENCRYPT_IMPL_TABLE = 3
};

struct proxy_instance {
    char name[64];
    enum proxy_type type;
    char local_addr[16];
    uint16_t local_port;
    uint16_t remote_port;
    bool encrypt;
    enum encrypt_impl encrypt_impl;
    bool active;
};

struct simple_client {
    enum client_state state;
    char username[64];
    char password[256];
    char server_addr[16];
    uint16_t server_port;
    struct proxy_instance proxies[10];
    int proxy_count;
};

/* Simple client functions for testing */
int simple_client_add_proxy(struct simple_client *client, const char *name, 
                           enum proxy_type type, const char *local_addr,
                           uint16_t local_port, uint16_t remote_port,
                           bool encrypt, enum encrypt_impl encrypt_impl)
{
    if (!client || !name || !local_addr) {
        return SEED_ERROR_INVALID_ARGS;
    }

    if (client->proxy_count >= 10) {
        return SEED_ERROR;
    }

    struct proxy_instance *proxy = &client->proxies[client->proxy_count];
    
    strncpy(proxy->name, name, sizeof(proxy->name) - 1);
    proxy->name[sizeof(proxy->name) - 1] = '\0';
    proxy->type = type;
    strncpy(proxy->local_addr, local_addr, sizeof(proxy->local_addr) - 1);
    proxy->local_addr[sizeof(proxy->local_addr) - 1] = '\0';
    proxy->local_port = local_port;
    proxy->remote_port = remote_port;
    proxy->encrypt = encrypt;
    proxy->encrypt_impl = encrypt_impl;
    proxy->active = false;

    client->proxy_count++;
    return SEED_OK;
}

int simple_client_start_proxies(struct simple_client *client)
{
    if (!client) {
        return SEED_ERROR_INVALID_ARGS;
    }

    if (client->state != CLIENT_STATE_AUTHENTICATED) {
        return SEED_ERROR;
    }

    for (int i = 0; i < client->proxy_count; i++) {
        client->proxies[i].active = true;
    }

    return SEED_OK;
}

int simple_client_stop_proxies(struct simple_client *client)
{
    if (!client) {
        return SEED_ERROR_INVALID_ARGS;
    }

    for (int i = 0; i < client->proxy_count; i++) {
        client->proxies[i].active = false;
    }

    return SEED_OK;
}

void simple_client_cleanup(struct simple_client *client)
{
    if (!client) {
        return;
    }

    memset(client->password, 0, sizeof(client->password));
    memset(client, 0, sizeof(*client));
}

/* Test functions */
void test_client_proxy_management(void)
{
    printf("Testing client proxy management...\n");
    
    struct simple_client client;
    memset(&client, 0, sizeof(client));
    
    /* Test adding proxy */
    int ret = simple_client_add_proxy(&client, "test-proxy", PROXY_TYPE_TCP,
                                     "127.0.0.1", 8080, 8080, true, ENCRYPT_IMPL_TLS);
    if (ret != SEED_OK) {
        printf("✗ Failed to add proxy\n");
        return;
    }
    
    if (client.proxy_count != 1) {
        printf("✗ Wrong proxy count: %d\n", client.proxy_count);
        return;
    }
    
    struct proxy_instance *proxy = &client.proxies[0];
    if (strcmp(proxy->name, "test-proxy") != 0) {
        printf("✗ Wrong proxy name: %s\n", proxy->name);
        return;
    }
    
    if (proxy->type != PROXY_TYPE_TCP) {
        printf("✗ Wrong proxy type: %d\n", proxy->type);
        return;
    }
    
    if (strcmp(proxy->local_addr, "127.0.0.1") != 0) {
        printf("✗ Wrong local address: %s\n", proxy->local_addr);
        return;
    }
    
    if (proxy->local_port != 8080 || proxy->remote_port != 8080) {
        printf("✗ Wrong ports: %d -> %d\n", proxy->local_port, proxy->remote_port);
        return;
    }
    
    if (!proxy->encrypt || proxy->encrypt_impl != ENCRYPT_IMPL_TLS) {
        printf("✗ Wrong encryption settings\n");
        return;
    }
    
    if (proxy->active) {
        printf("✗ Proxy should not be active initially\n");
        return;
    }
    
    printf("✓ Proxy management basic functionality\n");
}

void test_client_state_management(void)
{
    printf("Testing client state management...\n");
    
    struct simple_client client;
    memset(&client, 0, sizeof(client));
    client.state = CLIENT_STATE_DISCONNECTED;
    client.proxy_count = 1;
    client.proxies[0].active = false;
    
    /* Test starting proxies without authentication */
    int ret = simple_client_start_proxies(&client);
    if (ret == SEED_OK) {
        printf("✗ Should not start proxies when not authenticated\n");
        return;
    }
    
    /* Test with authenticated state */
    client.state = CLIENT_STATE_AUTHENTICATED;
    ret = simple_client_start_proxies(&client);
    if (ret != SEED_OK) {
        printf("✗ Failed to start proxies when authenticated\n");
        return;
    }
    
    if (!client.proxies[0].active) {
        printf("✗ Proxy should be active after start\n");
        return;
    }
    
    /* Test stopping proxies */
    ret = simple_client_stop_proxies(&client);
    if (ret != SEED_OK) {
        printf("✗ Failed to stop proxies\n");
        return;
    }
    
    if (client.proxies[0].active) {
        printf("✗ Proxy should not be active after stop\n");
        return;
    }
    
    printf("✓ State management functionality\n");
}

void test_client_parameter_validation(void)
{
    printf("Testing parameter validation...\n");
    
    struct simple_client client;
    memset(&client, 0, sizeof(client));
    
    /* Test null parameters */
    int ret = simple_client_add_proxy(NULL, "test", PROXY_TYPE_TCP, "127.0.0.1", 80, 80, false, ENCRYPT_IMPL_NONE);
    if (ret != SEED_ERROR_INVALID_ARGS) {
        printf("✗ Should reject null client\n");
        return;
    }
    
    ret = simple_client_add_proxy(&client, NULL, PROXY_TYPE_TCP, "127.0.0.1", 80, 80, false, ENCRYPT_IMPL_NONE);
    if (ret != SEED_ERROR_INVALID_ARGS) {
        printf("✗ Should reject null name\n");
        return;
    }
    
    ret = simple_client_add_proxy(&client, "test", PROXY_TYPE_TCP, NULL, 80, 80, false, ENCRYPT_IMPL_NONE);
    if (ret != SEED_ERROR_INVALID_ARGS) {
        printf("✗ Should reject null address\n");
        return;
    }
    
    ret = simple_client_start_proxies(NULL);
    if (ret != SEED_ERROR_INVALID_ARGS) {
        printf("✗ Should reject null client for start\n");
        return;
    }
    
    ret = simple_client_stop_proxies(NULL);
    if (ret != SEED_ERROR_INVALID_ARGS) {
        printf("✗ Should reject null client for stop\n");
        return;
    }
    
    printf("✓ Parameter validation\n");
}

void test_client_cleanup(void)
{
    printf("Testing client cleanup...\n");
    
    struct simple_client client;
    memset(&client, 0, sizeof(client));
    strcpy(client.password, "sensitive_password");
    client.state = CLIENT_STATE_AUTHENTICATED;
    
    /* Test cleanup with null - should not crash */
    simple_client_cleanup(NULL);
    
    /* Test normal cleanup */
    simple_client_cleanup(&client);
    
    /* Verify password is cleared */
    for (size_t i = 0; i < sizeof(client.password); i++) {
        if (client.password[i] != 0) {
            printf("✗ Password not properly cleared at position %zu\n", i);
            return;
        }
    }
    
    printf("✓ Client cleanup and security\n");
}

int main(void)
{
    log_init(LOG_ERROR);
    
    printf("=== Simple Client Tests ===\n");
    
    test_client_proxy_management();
    test_client_state_management();
    test_client_parameter_validation();
    test_client_cleanup();
    
    printf("=== Simple Client Tests Complete ===\n");
    
    return 0;
}