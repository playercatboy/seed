/**
 * @file test_udp_proxy_simple.c
 * @brief Simple UDP proxy logic unit tests (no libuv dependencies)
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

/* Simple UDP proxy structures for testing */
enum udp_session_state {
    UDP_SESSION_ACTIVE,
    UDP_SESSION_TIMEOUT,
    UDP_SESSION_CLOSED
};

struct simple_udp_session {
    enum udp_session_state state;
    char client_addr[16];
    char target_addr[16];
    uint16_t client_port;
    uint16_t target_port;
    uint64_t last_activity;
    uint64_t packets_received;
    uint64_t packets_sent;
    uint64_t bytes_received;
    uint64_t bytes_sent;
    struct simple_udp_session *next;
    struct simple_udp_session *prev;
};

struct simple_udp_proxy {
    char name[64];
    char bind_addr[16];
    uint16_t bind_port;
    char target_addr[16];
    uint16_t target_port;
    bool encrypt;
    bool active;
    
    struct simple_udp_session *sessions;
    int session_count;
    uint64_t total_sessions;
    uint64_t active_sessions;
    uint64_t total_packets_forwarded;
    uint64_t total_bytes_forwarded;
};

struct simple_udp_proxy_stats {
    uint64_t total_sessions;
    uint64_t active_sessions;
    uint64_t total_packets_forwarded;
    uint64_t total_bytes_forwarded;
    uint64_t packets_per_second;
};

/* Simple UDP proxy functions for testing */
int simple_udp_proxy_init(struct simple_udp_proxy *proxy, const char *name,
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
    proxy->sessions = NULL;
    proxy->session_count = 0;
    proxy->total_sessions = 0;
    proxy->active_sessions = 0;
    proxy->total_packets_forwarded = 0;
    proxy->total_bytes_forwarded = 0;

    return SEED_OK;
}

int simple_udp_proxy_start(struct simple_udp_proxy *proxy)
{
    if (!proxy) {
        return SEED_ERROR_INVALID_ARGS;
    }

    proxy->active = true;
    return SEED_OK;
}

int simple_udp_proxy_stop(struct simple_udp_proxy *proxy)
{
    if (!proxy) {
        return SEED_ERROR_INVALID_ARGS;
    }

    proxy->active = false;
    
    /* Close all sessions */
    struct simple_udp_session *session = proxy->sessions;
    while (session) {
        struct simple_udp_session *next = session->next;
        session->state = UDP_SESSION_CLOSED;
        proxy->session_count--;
        proxy->active_sessions--;
        free(session);
        session = next;
    }
    proxy->sessions = NULL;

    return SEED_OK;
}

int simple_udp_proxy_get_stats(const struct simple_udp_proxy *proxy, struct simple_udp_proxy_stats *stats)
{
    if (!proxy || !stats) {
        return SEED_ERROR_INVALID_ARGS;
    }

    stats->total_sessions = proxy->total_sessions;
    stats->active_sessions = proxy->active_sessions;
    stats->total_packets_forwarded = proxy->total_packets_forwarded;
    stats->total_bytes_forwarded = proxy->total_bytes_forwarded;
    stats->packets_per_second = 0;

    return SEED_OK;
}

struct simple_udp_session* simple_udp_add_session(struct simple_udp_proxy *proxy,
                                                 const char *client_addr, uint16_t client_port)
{
    if (!proxy || !client_addr) {
        return NULL;
    }

    struct simple_udp_session *session = malloc(sizeof(*session));
    if (!session) {
        return NULL;
    }

    memset(session, 0, sizeof(*session));
    session->state = UDP_SESSION_ACTIVE;
    
    strncpy(session->client_addr, client_addr, sizeof(session->client_addr) - 1);
    session->client_addr[sizeof(session->client_addr) - 1] = '\0';
    session->client_port = client_port;
    
    strncpy(session->target_addr, proxy->target_addr, sizeof(session->target_addr) - 1);
    session->target_addr[sizeof(session->target_addr) - 1] = '\0';
    session->target_port = proxy->target_port;

    session->last_activity = 12345; /* Mock timestamp */

    /* Add to beginning of list */
    session->next = proxy->sessions;
    session->prev = NULL;
    
    if (proxy->sessions) {
        proxy->sessions->prev = session;
    }
    
    proxy->sessions = session;
    proxy->session_count++;
    proxy->active_sessions++;
    proxy->total_sessions++;

    return session;
}

void simple_udp_remove_session(struct simple_udp_proxy *proxy, struct simple_udp_session *session)
{
    if (!proxy || !session) {
        return;
    }

    /* Remove from list */
    if (session->prev) {
        session->prev->next = session->next;
    } else {
        proxy->sessions = session->next;
    }
    
    if (session->next) {
        session->next->prev = session->prev;
    }

    proxy->session_count--;
    proxy->active_sessions--;
    
    free(session);
}

void simple_udp_session_forward_packet(struct simple_udp_session *session, uint64_t bytes)
{
    if (!session) {
        return;
    }

    session->packets_received++;
    session->packets_sent++;
    session->bytes_received += bytes;
    session->bytes_sent += bytes;
}

void simple_udp_proxy_cleanup(struct simple_udp_proxy *proxy)
{
    if (!proxy) {
        return;
    }

    simple_udp_proxy_stop(proxy);
    memset(proxy, 0, sizeof(*proxy));
}

/* Test functions */
void test_udp_proxy_initialization(void)
{
    printf("Testing UDP proxy initialization...\n");
    
    struct simple_udp_proxy proxy;
    
    /* Test valid initialization */
    int ret = simple_udp_proxy_init(&proxy, "test-udp-proxy", "127.0.0.1", 5353,
                                   "8.8.8.8", 53, false);
    if (ret != SEED_OK) {
        printf("✗ Failed to initialize UDP proxy\n");
        return;
    }
    
    if (strcmp(proxy.name, "test-udp-proxy") != 0) {
        printf("✗ Wrong proxy name: %s\n", proxy.name);
        return;
    }
    
    if (strcmp(proxy.bind_addr, "127.0.0.1") != 0) {
        printf("✗ Wrong bind address: %s\n", proxy.bind_addr);
        return;
    }
    
    if (proxy.bind_port != 5353) {
        printf("✗ Wrong bind port: %d\n", proxy.bind_port);
        return;
    }
    
    if (strcmp(proxy.target_addr, "8.8.8.8") != 0) {
        printf("✗ Wrong target address: %s\n", proxy.target_addr);
        return;
    }
    
    if (proxy.target_port != 53) {
        printf("✗ Wrong target port: %d\n", proxy.target_port);
        return;
    }
    
    if (proxy.encrypt) {
        printf("✗ Wrong encryption setting\n");
        return;
    }
    
    if (proxy.active) {
        printf("✗ Proxy should not be active initially\n");
        return;
    }
    
    if (proxy.session_count != 0) {
        printf("✗ Wrong initial session count: %d\n", proxy.session_count);
        return;
    }
    
    printf("✓ UDP proxy initialization\n");
}

void test_udp_proxy_parameter_validation(void)
{
    printf("Testing UDP proxy parameter validation...\n");
    
    struct simple_udp_proxy proxy;
    
    /* Test null parameters */
    int ret = simple_udp_proxy_init(NULL, "test", "127.0.0.1", 80, "10.0.0.1", 80, false);
    if (ret != SEED_ERROR_INVALID_ARGS) {
        printf("✗ Should reject null proxy\n");
        return;
    }
    
    ret = simple_udp_proxy_init(&proxy, NULL, "127.0.0.1", 80, "10.0.0.1", 80, false);
    if (ret != SEED_ERROR_INVALID_ARGS) {
        printf("✗ Should reject null name\n");
        return;
    }
    
    ret = simple_udp_proxy_init(&proxy, "test", NULL, 80, "10.0.0.1", 80, false);
    if (ret != SEED_ERROR_INVALID_ARGS) {
        printf("✗ Should reject null bind address\n");
        return;
    }
    
    ret = simple_udp_proxy_init(&proxy, "test", "127.0.0.1", 80, NULL, 80, false);
    if (ret != SEED_ERROR_INVALID_ARGS) {
        printf("✗ Should reject null target address\n");
        return;
    }
    
    ret = simple_udp_proxy_start(NULL);
    if (ret != SEED_ERROR_INVALID_ARGS) {
        printf("✗ Should reject null proxy for start\n");
        return;
    }
    
    ret = simple_udp_proxy_stop(NULL);
    if (ret != SEED_ERROR_INVALID_ARGS) {
        printf("✗ Should reject null proxy for stop\n");
        return;
    }
    
    ret = simple_udp_proxy_get_stats(NULL, NULL);
    if (ret != SEED_ERROR_INVALID_ARGS) {
        printf("✗ Should reject null parameters for stats\n");
        return;
    }
    
    printf("✓ UDP proxy parameter validation\n");
}

void test_udp_proxy_lifecycle(void)
{
    printf("Testing UDP proxy lifecycle...\n");
    
    struct simple_udp_proxy proxy;
    
    /* Initialize proxy */
    int ret = simple_udp_proxy_init(&proxy, "test-proxy", "127.0.0.1", 5353,
                                   "8.8.8.8", 53, false);
    if (ret != SEED_OK) {
        printf("✗ Failed to initialize proxy\n");
        return;
    }
    
    if (proxy.active) {
        printf("✗ Proxy should not be active initially\n");
        return;
    }
    
    /* Start proxy */
    ret = simple_udp_proxy_start(&proxy);
    if (ret != SEED_OK) {
        printf("✗ Failed to start proxy\n");
        return;
    }
    
    if (!proxy.active) {
        printf("✗ Proxy should be active after start\n");
        return;
    }
    
    /* Stop proxy */
    ret = simple_udp_proxy_stop(&proxy);
    if (ret != SEED_OK) {
        printf("✗ Failed to stop proxy\n");
        return;
    }
    
    if (proxy.active) {
        printf("✗ Proxy should not be active after stop\n");
        return;
    }
    
    /* Cleanup */
    simple_udp_proxy_cleanup(&proxy);
    
    printf("✓ UDP proxy lifecycle management\n");
}

void test_udp_session_management(void)
{
    printf("Testing UDP session management...\n");
    
    struct simple_udp_proxy proxy;
    simple_udp_proxy_init(&proxy, "test-proxy", "127.0.0.1", 5353,
                         "8.8.8.8", 53, false);
    
    /* Add session */
    struct simple_udp_session *session1 = simple_udp_add_session(&proxy, "192.168.1.100", 34567);
    if (!session1) {
        printf("✗ Failed to add session\n");
        return;
    }
    
    if (proxy.session_count != 1) {
        printf("✗ Wrong session count after add: %d\n", proxy.session_count);
        return;
    }
    
    if (proxy.active_sessions != 1) {
        printf("✗ Wrong active session count: %llu\n", (unsigned long long)proxy.active_sessions);
        return;
    }
    
    if (proxy.total_sessions != 1) {
        printf("✗ Wrong total session count: %llu\n", (unsigned long long)proxy.total_sessions);
        return;
    }
    
    /* Test session properties */
    if (strcmp(session1->client_addr, "192.168.1.100") != 0) {
        printf("✗ Wrong client address: %s\n", session1->client_addr);
        return;
    }
    
    if (session1->client_port != 34567) {
        printf("✗ Wrong client port: %d\n", session1->client_port);
        return;
    }
    
    if (strcmp(session1->target_addr, "8.8.8.8") != 0) {
        printf("✗ Wrong target address: %s\n", session1->target_addr);
        return;
    }
    
    if (session1->target_port != 53) {
        printf("✗ Wrong target port: %d\n", session1->target_port);
        return;
    }
    
    /* Add second session */
    struct simple_udp_session *session2 = simple_udp_add_session(&proxy, "192.168.1.101", 34568);
    if (!session2) {
        printf("✗ Failed to add second session\n");
        return;
    }
    
    if (proxy.session_count != 2) {
        printf("✗ Wrong session count after second add: %d\n", proxy.session_count);
        return;
    }
    
    /* Remove first session */
    simple_udp_remove_session(&proxy, session1);
    
    if (proxy.session_count != 1) {
        printf("✗ Wrong session count after remove: %d\n", proxy.session_count);
        return;
    }
    
    if (proxy.active_sessions != 1) {
        printf("✗ Wrong active session count after remove: %llu\n", (unsigned long long)proxy.active_sessions);
        return;
    }
    
    /* Cleanup */
    simple_udp_proxy_cleanup(&proxy);
    
    printf("✓ UDP session management\n");
}

void test_udp_proxy_statistics(void)
{
    printf("Testing UDP proxy statistics...\n");
    
    struct simple_udp_proxy proxy;
    struct simple_udp_proxy_stats stats;
    
    simple_udp_proxy_init(&proxy, "test-proxy", "127.0.0.1", 5353,
                         "8.8.8.8", 53, false);
    
    /* Test initial stats */
    int ret = simple_udp_proxy_get_stats(&proxy, &stats);
    if (ret != SEED_OK) {
        printf("✗ Failed to get initial stats\n");
        return;
    }
    
    if (stats.total_sessions != 0 || stats.active_sessions != 0 || 
        stats.total_packets_forwarded != 0 || stats.total_bytes_forwarded != 0) {
        printf("✗ Wrong initial statistics\n");
        return;
    }
    
    /* Add session and simulate packet forwarding */
    struct simple_udp_session *session = simple_udp_add_session(&proxy, "192.168.1.100", 34567);
    simple_udp_session_forward_packet(session, 512);
    proxy.total_packets_forwarded += 2; /* Forward + return */
    proxy.total_bytes_forwarded += 1024; /* 512 * 2 */
    
    /* Get updated stats */
    ret = simple_udp_proxy_get_stats(&proxy, &stats);
    if (ret != SEED_OK) {
        printf("✗ Failed to get updated stats\n");
        return;
    }
    
    if (stats.total_sessions != 1) {
        printf("✗ Wrong total sessions in stats: %llu\n", (unsigned long long)stats.total_sessions);
        return;
    }
    
    if (stats.active_sessions != 1) {
        printf("✗ Wrong active sessions in stats: %llu\n", (unsigned long long)stats.active_sessions);
        return;
    }
    
    if (stats.total_packets_forwarded != 2) {
        printf("✗ Wrong packets forwarded in stats: %llu\n", (unsigned long long)stats.total_packets_forwarded);
        return;
    }
    
    if (stats.total_bytes_forwarded != 1024) {
        printf("✗ Wrong bytes forwarded in stats: %llu\n", (unsigned long long)stats.total_bytes_forwarded);
        return;
    }
    
    /* Cleanup */
    simple_udp_proxy_cleanup(&proxy);
    
    printf("✓ UDP proxy statistics\n");
}

void test_udp_session_packet_forwarding(void)
{
    printf("Testing UDP session packet forwarding...\n");
    
    struct simple_udp_proxy proxy;
    simple_udp_proxy_init(&proxy, "dns-proxy", "127.0.0.1", 5353,
                         "8.8.8.8", 53, false);
    
    /* Add session */
    struct simple_udp_session *session = simple_udp_add_session(&proxy, "192.168.1.100", 34567);
    
    /* Test initial packet counts */
    if (session->packets_received != 0 || session->packets_sent != 0) {
        printf("✗ Initial packet counts should be zero\n");
        return;
    }
    
    if (session->bytes_received != 0 || session->bytes_sent != 0) {
        printf("✗ Initial byte counts should be zero\n");
        return;
    }
    
    /* Simulate packet forwarding */
    simple_udp_session_forward_packet(session, 64);  /* DNS query */
    
    if (session->packets_received != 1 || session->packets_sent != 1) {
        printf("✗ Wrong packet counts after forwarding\n");
        return;
    }
    
    if (session->bytes_received != 64 || session->bytes_sent != 64) {
        printf("✗ Wrong byte counts after forwarding\n");
        return;
    }
    
    /* Simulate response packet */
    simple_udp_session_forward_packet(session, 128);  /* DNS response */
    
    if (session->packets_received != 2 || session->packets_sent != 2) {
        printf("✗ Wrong packet counts after response\n");
        return;
    }
    
    if (session->bytes_received != 192 || session->bytes_sent != 192) {
        printf("✗ Wrong byte counts after response\n");
        return;
    }
    
    /* Cleanup */
    simple_udp_proxy_cleanup(&proxy);
    
    printf("✓ UDP session packet forwarding\n");
}

int main(void)
{
    log_init(LOG_ERROR);
    
    printf("=== Simple UDP Proxy Tests ===\n");
    
    test_udp_proxy_initialization();
    test_udp_proxy_parameter_validation();
    test_udp_proxy_lifecycle();
    test_udp_session_management();
    test_udp_proxy_statistics();
    test_udp_session_packet_forwarding();
    
    printf("=== Simple UDP Proxy Tests Complete ===\n");
    
    return 0;
}