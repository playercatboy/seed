/**
 * @file udp_proxy.h
 * @brief UDP proxy functionality for Seed reverse proxy
 * @author Seed Development Team
 * @date 2025
 */

#ifndef UDP_PROXY_H
#define UDP_PROXY_H

#include "common.h"
#include "network.h"
#include <uv.h>

/** Maximum number of UDP sessions per proxy instance */
#define MAX_UDP_SESSIONS 512

/** UDP packet buffer size */
#define UDP_BUFFER_SIZE 65536

/** UDP session timeout in seconds */
#define UDP_SESSION_TIMEOUT_SECS 300

/**
 * @brief UDP session state
 */
enum udp_session_state {
    UDP_SESSION_ACTIVE,        /**< Session is active */
    UDP_SESSION_TIMEOUT,       /**< Session has timed out */
    UDP_SESSION_CLOSED         /**< Session is closed */
};

/**
 * @brief UDP session (client-target mapping)
 */
struct udp_session {
    /** Session identification */
    struct sockaddr_in client_addr;    /**< Client source address */
    struct sockaddr_in target_addr;    /**< Target destination address */
    
    /** Session state */
    enum udp_session_state state;
    
    /** Target socket */
    uv_udp_t target_socket;
    
    /** Session timing */
    uv_timer_t timeout_timer;
    uint64_t last_activity;
    
    /** Session statistics */
    uint64_t packets_received;
    uint64_t packets_sent;
    uint64_t bytes_received;
    uint64_t bytes_sent;
    
    /** Reference to proxy instance */
    struct udp_proxy *proxy;
    
    /** List linkage */
    struct udp_session *next;
    struct udp_session *prev;
};

/**
 * @brief UDP proxy statistics structure
 */
struct udp_proxy_stats {
    uint64_t total_sessions;         /**< Total sessions created */
    uint64_t active_sessions;        /**< Currently active sessions */
    uint64_t total_packets_forwarded; /**< Total packets forwarded */
    uint64_t total_bytes_forwarded;  /**< Total bytes forwarded */
    uint64_t packets_per_second;     /**< Current packet rate */
};

/**
 * @brief UDP proxy instance
 */
struct udp_proxy {
    /** Proxy configuration */
    char name[64];                     /**< Proxy instance name */
    struct sockaddr_in bind_addr;      /**< Address to bind to */
    struct sockaddr_in target_addr;    /**< Target address to forward to */
    bool encrypt;                      /**< Use encryption */
    
    /** Network context */
    struct network_context *network;
    
    /** Listening socket */
    uv_udp_t server_socket;
    
    /** Active sessions */
    struct udp_session *sessions;
    int session_count;
    
    /** Session cleanup timer */
    uv_timer_t cleanup_timer;
    
    /** Proxy statistics */
    uint64_t total_sessions;
    uint64_t active_sessions;
    uint64_t total_packets_forwarded;
    uint64_t total_bytes_forwarded;
    
    /** Callbacks */
    void (*on_session_created)(struct udp_proxy *proxy, struct udp_session *session);
    void (*on_session_closed)(struct udp_proxy *proxy, struct udp_session *session);
    void (*on_packet_forwarded)(struct udp_proxy *proxy, size_t bytes);
    void (*on_error)(struct udp_proxy *proxy, int error);
};

/**
 * @brief Initialize UDP proxy instance
 * 
 * @param[out] proxy        UDP proxy instance to initialize
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
int udp_proxy_init(struct udp_proxy *proxy, struct network_context *network,
                  const char *name, const char *bind_addr, uint16_t bind_port,
                  const char *target_addr, uint16_t target_port, bool encrypt);

/**
 * @brief Start UDP proxy listening
 * 
 * @param[in] proxy         UDP proxy instance
 * 
 * @return SEED_OK on success, negative error code on failure
 */
int udp_proxy_start(struct udp_proxy *proxy);

/**
 * @brief Stop UDP proxy
 * 
 * @param[in] proxy         UDP proxy instance
 * 
 * @return SEED_OK on success, negative error code on failure
 */
int udp_proxy_stop(struct udp_proxy *proxy);

/**
 * @brief Get proxy statistics
 * 
 * @param[in]  proxy        UDP proxy instance
 * @param[out] stats        Statistics structure to fill
 * 
 * @return SEED_OK on success, negative error code on failure
 */
int udp_proxy_get_stats(const struct udp_proxy *proxy, struct udp_proxy_stats *stats);

/**
 * @brief Find or create UDP session for client
 * 
 * @param[in] proxy         UDP proxy instance
 * @param[in] client_addr   Client address
 * 
 * @return UDP session pointer or NULL on error
 */
struct udp_session* udp_proxy_find_or_create_session(struct udp_proxy *proxy, 
                                                    const struct sockaddr_in *client_addr);

/**
 * @brief Close specific UDP session
 * 
 * @param[in] session       UDP session to close
 */
void udp_session_close(struct udp_session *session);

/**
 * @brief Cleanup UDP proxy instance
 * 
 * @param[in] proxy         UDP proxy instance to cleanup
 */
void udp_proxy_cleanup(struct udp_proxy *proxy);

#endif /* UDP_PROXY_H */