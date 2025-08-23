/**
 * @file client.h
 * @brief Client mode functionality for Seed reverse proxy
 * @author Seed Development Team
 * @date 2025
 */

#ifndef CLIENT_H
#define CLIENT_H

#include "common.h"
#include "config.h"
#include "network.h"
#include "protocol.h"
#include <uv.h>

/** Maximum number of proxy instances per client */
#define MAX_PROXY_INSTANCES 100

/**
 * @brief Proxy instance configuration
 */
struct proxy_instance {
    char name[64];              /**< Proxy instance name */
    enum proxy_type type;       /**< TCP or UDP */
    char local_addr[16];        /**< Local address to forward to */
    uint16_t local_port;        /**< Local port to forward to */
    uint16_t remote_port;       /**< Remote port on server */
    bool encrypt;               /**< Use encryption */
    enum encrypt_impl encrypt_impl; /**< Encryption implementation */
    bool active;                /**< Is this instance active */
};

/**
 * @brief Client session structure
 */
struct client_session {
    struct network_context *network;    /**< Network context */
    uv_tcp_t server_connection;         /**< Connection to server */
    enum client_state state;            /**< Current client state */
    char username[64];                  /**< Username for authentication */
    char password[256];                 /**< Password for authentication */
    char server_addr[16];               /**< Server address */
    uint16_t server_port;               /**< Server port */
    
    /** Proxy instances */
    struct proxy_instance proxies[MAX_PROXY_INSTANCES];
    int proxy_count;                    /**< Number of configured proxies */
    
    /** Keepalive timer */
    uv_timer_t keepalive_timer;
    
    /** Callbacks */
    void (*on_connected)(struct client_session *session);
    void (*on_authenticated)(struct client_session *session);
    void (*on_disconnected)(struct client_session *session);
    void (*on_error)(struct client_session *session, int error);
};

/**
 * @brief Initialize client session
 * 
 * @param[out] session      Client session to initialize
 * @param[in]  network      Network context
 * @param[in]  config       Configuration
 * 
 * @return SEED_OK on success, negative error code on failure
 */
int client_init(struct client_session *session, struct network_context *network, const struct seed_config *config);

/**
 * @brief Connect to server
 * 
 * @param[in] session       Client session
 * @param[in] server_addr   Server address
 * @param[in] server_port   Server port
 * 
 * @return SEED_OK on success, negative error code on failure
 */
int client_connect(struct client_session *session, const char *server_addr, uint16_t server_port);

/**
 * @brief Authenticate with server
 * 
 * @param[in] session       Client session
 * @param[in] username      Username
 * @param[in] password      Password
 * 
 * @return SEED_OK on success, negative error code on failure
 */
int client_authenticate(struct client_session *session, const char *username, const char *password);

/**
 * @brief Add proxy instance to client
 * 
 * @param[in] session       Client session
 * @param[in] name          Proxy instance name
 * @param[in] type          Proxy type (TCP/UDP)
 * @param[in] local_addr    Local address
 * @param[in] local_port    Local port
 * @param[in] remote_port   Remote port
 * @param[in] encrypt       Enable encryption
 * @param[in] encrypt_impl  Encryption implementation
 * 
 * @return SEED_OK on success, negative error code on failure
 */
int client_add_proxy(struct client_session *session, const char *name, 
                    enum proxy_type type, const char *local_addr,
                    uint16_t local_port, uint16_t remote_port,
                    bool encrypt, enum encrypt_impl encrypt_impl);

/**
 * @brief Start all configured proxy instances
 * 
 * @param[in] session       Client session
 * 
 * @return SEED_OK on success, negative error code on failure
 */
int client_start_proxies(struct client_session *session);

/**
 * @brief Stop all proxy instances
 * 
 * @param[in] session       Client session
 * 
 * @return SEED_OK on success, negative error code on failure
 */
int client_stop_proxies(struct client_session *session);

/**
 * @brief Disconnect from server
 * 
 * @param[in] session       Client session
 */
void client_disconnect(struct client_session *session);

/**
 * @brief Cleanup client session
 * 
 * @param[in] session       Client session to cleanup
 */
void client_cleanup(struct client_session *session);

/**
 * @brief Handle received message from server
 * 
 * @param[in] session       Client session
 * @param[in] msg           Received message
 * 
 * @return SEED_OK on success, negative error code on failure
 */
int client_handle_message(struct client_session *session, const struct protocol_message *msg);

/**
 * @brief Send keepalive message to server
 * 
 * @param[in] session       Client session
 * 
 * @return SEED_OK on success, negative error code on failure
 */
int client_send_keepalive(struct client_session *session);

#endif /* CLIENT_H */