/**
 * @file server.h
 * @brief Server mode implementation for Seed reverse proxy
 * @author Seed Development Team
 * @date 2025
 */

#ifndef SERVER_H
#define SERVER_H

#include "common.h"
#include "config.h"
#include "auth.h"
#include "network.h"
#include "protocol.h"

/** Maximum number of proxy mappings */
#define MAX_PROXY_MAPPINGS 256

/** Client connection states */
enum client_state {
    CLIENT_STATE_DISCONNECTED = 0,
    CLIENT_STATE_CONNECTED,
    CLIENT_STATE_AUTHENTICATING,
    CLIENT_STATE_AUTHENTICATED,
    CLIENT_STATE_ERROR
};

/** Proxy mapping structure */
struct proxy_mapping {
    char proxy_id[64];                  /** Unique proxy ID */
    char client_id[64];                 /** Client ID that owns this mapping */
    struct connection *client_conn;     /** Client connection */
    
    /* Proxy configuration */
    enum proxy_type type;               /** TCP or UDP */
    int remote_port;                    /** Port bound on server */
    char local_addr[16];                /** Client's local address */
    int local_port;                     /** Client's local port */
    enum encrypt_impl encryption;       /** Encryption type */
    
    /* Server-side listening */
    uv_tcp_t tcp_server;                /** TCP server handle */
    uv_udp_t udp_server;                /** UDP server handle */
    bool active;                        /** Is mapping active */
    
    /* Statistics */
    uint64_t bytes_sent;                /** Bytes sent to client */
    uint64_t bytes_received;            /** Bytes received from client */
    uint32_t connections_count;         /** Active connections */
    time_t created_time;                /** Creation time */
};

/** Client session structure */
struct client_session {
    struct connection *conn;            /** Network connection */
    enum client_state state;            /** Client state */
    char username[64];                  /** Authenticated username */
    char client_id[64];                 /** Client identifier */
    
    /* Proxy mappings owned by this client */
    struct proxy_mapping *mappings[MAX_PROXY_INSTANCES];
    int mapping_count;                  /** Number of active mappings */
    
    /* Session info */
    time_t connect_time;                /** Connection time */
    time_t auth_time;                   /** Authentication time */
    uint64_t bytes_sent;                /** Total bytes sent */
    uint64_t bytes_received;            /** Total bytes received */
};

/** Server context structure */
struct server_context {
    struct network_context network;     /** Network context */
    struct auth_db auth;                /** Authentication database */
    struct seed_config *config;         /** Configuration */
    
    /* Client management */
    struct client_session clients[MAX_CONNECTIONS];
    int active_clients;                 /** Number of active clients */
    
    /* Proxy mappings */
    struct proxy_mapping mappings[MAX_PROXY_MAPPINGS];
    int active_mappings;                /** Number of active mappings */
    
    /* Server state */
    bool running;                       /** Is server running */
    time_t start_time;                  /** Server start time */
};

/**
 * @brief Initialize server context
 *
 * @param[out] ctx     Server context to initialize
 * @param[in]  config  Configuration
 *
 * @return 0 on success, negative error code on failure
 */
int server_init(struct server_context *ctx, struct seed_config *config);

/**
 * @brief Start server
 *
 * @param[in,out] ctx  Server context
 *
 * @return 0 on success, negative error code on failure
 */
int server_start(struct server_context *ctx);

/**
 * @brief Stop server
 *
 * @param[in,out] ctx  Server context
 */
void server_stop(struct server_context *ctx);

/**
 * @brief Run server main loop
 *
 * @param[in,out] ctx  Server context
 *
 * @return Exit code
 */
int server_run(struct server_context *ctx);

/**
 * @brief Cleanup server context
 *
 * @param[in,out] ctx  Server context to cleanup
 */
void server_cleanup(struct server_context *ctx);

/**
 * @brief Handle new client connection
 *
 * @param[in,out] ctx   Server context
 * @param[in]     conn  New connection
 */
void server_handle_new_connection(struct server_context *ctx, struct connection *conn);

/**
 * @brief Handle client message
 *
 * @param[in,out] ctx   Server context
 * @param[in]     conn  Client connection
 * @param[in]     msg   Received message
 */
void server_handle_message(struct server_context *ctx, struct connection *conn, 
                          const struct protocol_message *msg);

/**
 * @brief Handle client disconnection
 *
 * @param[in,out] ctx   Server context
 * @param[in]     conn  Disconnected connection
 */
void server_handle_disconnection(struct server_context *ctx, struct connection *conn);

/**
 * @brief Find client session by connection
 *
 * @param[in] ctx   Server context
 * @param[in] conn  Connection to find
 *
 * @return Client session pointer, or NULL if not found
 */
struct client_session *server_find_client(struct server_context *ctx, struct connection *conn);

/**
 * @brief Create proxy mapping
 *
 * @param[in,out] ctx      Server context
 * @param[in]     client   Client session
 * @param[in]     request  Proxy request
 *
 * @return 0 on success, negative error code on failure
 */
int server_create_proxy_mapping(struct server_context *ctx, struct client_session *client,
                               const struct msg_proxy_request *request);

/**
 * @brief Destroy proxy mapping
 *
 * @param[in,out] ctx       Server context
 * @param[in]     proxy_id  Proxy ID to destroy
 *
 * @return 0 on success, negative error code on failure
 */
int server_destroy_proxy_mapping(struct server_context *ctx, const char *proxy_id);

/**
 * @brief Print server statistics
 *
 * @param[in] ctx  Server context
 */
void server_print_statistics(const struct server_context *ctx);

#endif /* SERVER_H */