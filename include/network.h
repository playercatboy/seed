/**
 * @file network.h
 * @brief Network core using libuv for Seed reverse proxy
 * @author Seed Development Team
 * @date 2025
 */

#ifndef NETWORK_H
#define NETWORK_H

#include "common.h"
#include "protocol.h"
#include <uv.h>

/** Forward declarations */
struct network_context;
struct connection;

/** Connection states */
enum connection_state {
    CONN_STATE_DISCONNECTED = 0,
    CONN_STATE_CONNECTING,
    CONN_STATE_CONNECTED,
    CONN_STATE_AUTHENTICATED,
    CONN_STATE_ERROR,
    CONN_STATE_CLOSED
};

/** Connection type */
enum connection_type {
    CONN_TYPE_UNKNOWN = 0,
    CONN_TYPE_CLIENT,    /** Client connection to server */
    CONN_TYPE_SERVER,    /** Server accepting client connections */
    CONN_TYPE_PROXY_TCP, /** TCP proxy connection */
    CONN_TYPE_PROXY_UDP  /** UDP proxy connection */
};

/** Network callback function types */
typedef void (*connection_callback_t)(struct connection *conn, int status);
typedef void (*message_callback_t)(struct connection *conn, const struct protocol_message *msg);
typedef void (*data_callback_t)(struct connection *conn, const uint8_t *data, size_t len);
typedef void (*close_callback_t)(struct connection *conn);

/** Connection structure */
struct connection {
    uv_tcp_t tcp_handle;                /** TCP handle */
    uv_udp_t udp_handle;                /** UDP handle */
    enum connection_type type;          /** Connection type */
    enum connection_state state;        /** Connection state */
    struct sockaddr_in addr;            /** Address */
    
    /* Callbacks */
    connection_callback_t on_connect;   /** Connection callback */
    message_callback_t on_message;      /** Message received callback */
    data_callback_t on_data;            /** Raw data callback */
    close_callback_t on_close;          /** Connection closed callback */
    
    /* Buffers */
    uint8_t *recv_buffer;               /** Receive buffer */
    size_t recv_buffer_size;            /** Receive buffer size */
    size_t recv_buffer_pos;             /** Current position in buffer */
    
    uint8_t *send_buffer;               /** Send buffer */
    size_t send_buffer_size;            /** Send buffer size */
    
    /* Connection info */
    char remote_ip[16];                 /** Remote IP address */
    int remote_port;                    /** Remote port */
    char local_ip[16];                  /** Local IP address */
    int local_port;                     /** Local port */
    
    /* User data */
    void *user_data;                    /** User data pointer */
    struct network_context *ctx;       /** Parent network context */
};

/** Network context structure */
struct network_context {
    uv_loop_t *loop;                    /** Event loop */
    uv_tcp_t server_handle;             /** Server handle */
    bool running;                       /** Is network running */
    
    /* Connection management */
    struct connection *connections;      /** Connection array */
    int max_connections;                /** Maximum connections */
    int active_connections;             /** Active connection count */
    
    /* Callbacks */
    connection_callback_t on_new_connection; /** New connection callback */
    message_callback_t on_message;      /** Global message callback */
    close_callback_t on_connection_closed;   /** Connection closed callback */
    
    /* Server info */
    char bind_addr[16];                 /** Bind address */
    int bind_port;                      /** Bind port */
    
    /* User data */
    void *user_data;                    /** User data pointer */
};

/**
 * @brief Initialize network context
 *
 * @param[out] ctx   Network context to initialize
 * @param[in]  loop  Event loop (NULL to create new one)
 *
 * @return 0 on success, negative error code on failure
 */
int network_init(struct network_context *ctx, uv_loop_t *loop);

/**
 * @brief Cleanup network context
 *
 * @param[in,out] ctx  Network context to cleanup
 */
void network_cleanup(struct network_context *ctx);

/**
 * @brief Start network server
 *
 * @param[in,out] ctx       Network context
 * @param[in]     bind_addr Bind address
 * @param[in]     bind_port Bind port
 *
 * @return 0 on success, negative error code on failure
 */
int network_start_server(struct network_context *ctx, const char *bind_addr, int bind_port);

/**
 * @brief Stop network server
 *
 * @param[in,out] ctx  Network context
 */
void network_stop_server(struct network_context *ctx);

/**
 * @brief Connect to remote server
 *
 * @param[in,out] ctx         Network context
 * @param[in]     remote_addr Remote address
 * @param[in]     remote_port Remote port
 * @param[out]    conn        Connection structure to fill
 *
 * @return 0 on success, negative error code on failure
 */
int network_connect(struct network_context *ctx, const char *remote_addr, int remote_port, 
                   struct connection *conn);

/**
 * @brief Send protocol message
 *
 * @param[in] conn  Connection
 * @param[in] msg   Message to send
 *
 * @return 0 on success, negative error code on failure
 */
int network_send_message(struct connection *conn, const struct protocol_message *msg);

/**
 * @brief Send raw data
 *
 * @param[in] conn  Connection
 * @param[in] data  Data to send
 * @param[in] len   Data length
 *
 * @return 0 on success, negative error code on failure
 */
int network_send_data(struct connection *conn, const uint8_t *data, size_t len);

/**
 * @brief Close connection
 *
 * @param[in,out] conn  Connection to close
 */
void network_close_connection(struct connection *conn);

/**
 * @brief Run network event loop
 *
 * @param[in,out] ctx  Network context
 *
 * @return 0 on success, negative error code on failure
 */
int network_run(struct network_context *ctx);

/**
 * @brief Stop network event loop
 *
 * @param[in,out] ctx  Network context
 */
void network_stop(struct network_context *ctx);

/**
 * @brief Get connection info string
 *
 * @param[in]  conn     Connection
 * @param[out] buffer   Buffer to fill
 * @param[in]  buflen   Buffer length
 *
 * @return Buffer pointer
 */
const char *network_connection_info(const struct connection *conn, char *buffer, size_t buflen);

#endif /* NETWORK_H */