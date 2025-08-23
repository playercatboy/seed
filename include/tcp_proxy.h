/**
 * @file tcp_proxy.h
 * @brief TCP proxy functionality for Seed reverse proxy
 * @author Seed Development Team
 * @date 2025
 */

#ifndef TCP_PROXY_H
#define TCP_PROXY_H

#include "common.h"
#include "network.h"
#include <uv.h>

/** Maximum number of TCP connections per proxy instance */
#define MAX_TCP_CONNECTIONS 256

/** TCP connection buffer size */
#define TCP_BUFFER_SIZE 65536

/**
 * @brief TCP connection state
 */
enum tcp_connection_state {
    TCP_STATE_CONNECTING,      /**< Establishing connection */
    TCP_STATE_CONNECTED,       /**< Connection established */
    TCP_STATE_CLOSING,         /**< Connection being closed */
    TCP_STATE_CLOSED          /**< Connection closed */
};

/**
 * @brief TCP connection pair (client-target connection)
 */
struct tcp_connection {
    /** Connection state */
    enum tcp_connection_state state;
    
    /** Client side (incoming connection) */
    uv_tcp_t client_handle;
    struct sockaddr_in client_addr;
    
    /** Target side (outgoing connection) */
    uv_tcp_t target_handle;
    uv_connect_t connect_req;
    struct sockaddr_in target_addr;
    
    /** Data buffers */
    uint8_t client_buffer[TCP_BUFFER_SIZE];
    uint8_t target_buffer[TCP_BUFFER_SIZE];
    
    /** Connection statistics */
    uint64_t bytes_received;
    uint64_t bytes_sent;
    
    /** Reference to proxy instance */
    struct tcp_proxy *proxy;
    
    /** List linkage */
    struct tcp_connection *next;
    struct tcp_connection *prev;
};

/**
 * @brief TCP proxy instance
 */
struct tcp_proxy {
    /** Proxy configuration */
    char name[64];              /**< Proxy instance name */
    struct sockaddr_in bind_addr;    /**< Address to bind to */
    struct sockaddr_in target_addr;  /**< Target address to forward to */
    bool encrypt;               /**< Use encryption */
    
    /** Network context */
    struct network_context *network;
    
    /** Listening server */
    uv_tcp_t server_handle;
    
    /** Active connections */
    struct tcp_connection *connections;
    int connection_count;
    
    /** Proxy statistics */
    uint64_t total_connections;
    uint64_t active_connections;
    uint64_t total_bytes_transferred;
    
    /** Callbacks */
    void (*on_connection_established)(struct tcp_proxy *proxy, struct tcp_connection *conn);
    void (*on_connection_closed)(struct tcp_proxy *proxy, struct tcp_connection *conn);
    void (*on_data_transferred)(struct tcp_proxy *proxy, size_t bytes);
    void (*on_error)(struct tcp_proxy *proxy, int error);
};

/**
 * @brief Initialize TCP proxy instance
 * 
 * @param[out] proxy        TCP proxy instance to initialize
 * @param[in]  network      Network context
 * @param[in]  name         Proxy instance name
 * @param[in]  bind_addr    Local address to bind to
 * @param[in]  bind_port    Local port to bind to
 * @param[in]  target_addr  Target address to forward to
 * @param[in]  target_port  Target port to forward to
 * @param[in]  encrypt      Enable encryption
 * 
 * @return SEED_OK on success, negative error code on failure
 */
int tcp_proxy_init(struct tcp_proxy *proxy, struct network_context *network,
                  const char *name, const char *bind_addr, uint16_t bind_port,
                  const char *target_addr, uint16_t target_port, bool encrypt);

/**
 * @brief Start TCP proxy listening
 * 
 * @param[in] proxy         TCP proxy instance
 * 
 * @return SEED_OK on success, negative error code on failure
 */
int tcp_proxy_start(struct tcp_proxy *proxy);

/**
 * @brief Stop TCP proxy
 * 
 * @param[in] proxy         TCP proxy instance
 * 
 * @return SEED_OK on success, negative error code on failure
 */
int tcp_proxy_stop(struct tcp_proxy *proxy);

/**
 * @brief TCP proxy statistics structure
 */
struct tcp_proxy_stats {
    uint64_t total_connections;      /**< Total connections handled */
    uint64_t active_connections;     /**< Currently active connections */
    uint64_t total_bytes_transferred; /**< Total bytes transferred */
    uint64_t bytes_per_second;       /**< Current transfer rate */
};

/**
 * @brief Get proxy statistics
 * 
 * @param[in]  proxy        TCP proxy instance
 * @param[out] stats        Statistics structure to fill
 * 
 * @return SEED_OK on success, negative error code on failure
 */
int tcp_proxy_get_stats(const struct tcp_proxy *proxy, struct tcp_proxy_stats *stats);

/**
 * @brief Close specific TCP connection
 * 
 * @param[in] conn          TCP connection to close
 */
void tcp_connection_close(struct tcp_connection *conn);

/**
 * @brief Cleanup TCP proxy instance
 * 
 * @param[in] proxy         TCP proxy instance to cleanup
 */
void tcp_proxy_cleanup(struct tcp_proxy *proxy);

#endif /* TCP_PROXY_H */