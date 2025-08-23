/**
 * @file network.c
 * @brief Network core implementation using libuv
 * @author Seed Development Team
 * @date 2025
 */

#include "network.h"
#include "log.h"

/** Default buffer sizes */
#define DEFAULT_RECV_BUFFER_SIZE (64 * 1024)
#define DEFAULT_SEND_BUFFER_SIZE (64 * 1024)

/** Write request structure */
struct write_request {
    uv_write_t req;
    uv_buf_t buf;
    struct connection *conn;
};

/** Connect request structure */
struct connect_request {
    uv_connect_t req;
    struct connection *conn;
};

/**
 * @brief Allocate buffer callback
 *
 * @param[in]  handle      Handle
 * @param[in]  suggested_size Suggested size
 * @param[out] buf         Buffer to allocate
 */
static void alloc_buffer_callback(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    struct connection *conn = (struct connection *)handle->data;
    
    (void)suggested_size; /* Unused */
    
    if (!conn || !conn->recv_buffer) {
        buf->base = NULL;
        buf->len = 0;
        return;
    }
    
    buf->base = (char *)conn->recv_buffer + conn->recv_buffer_pos;
    buf->len = conn->recv_buffer_size - conn->recv_buffer_pos;
}

/**
 * @brief Process received protocol messages
 *
 * @param[in,out] conn  Connection
 */
static void process_messages(struct connection *conn)
{
    uint8_t *buffer = conn->recv_buffer;
    size_t buffer_len = conn->recv_buffer_pos;
    size_t offset = 0;
    
    while (offset < buffer_len) {
        struct protocol_message msg;
        int consumed;
        
        /* Try to deserialize message */
        consumed = protocol_deserialize(&msg, buffer + offset, buffer_len - offset);
        if (consumed < 0) {
            /* Not enough data or invalid message */
            break;
        }
        
        /* Call message callback */
        if (conn->on_message) {
            conn->on_message(conn, &msg);
        }
        
        offset += consumed;
    }
    
    /* Move remaining data to beginning of buffer */
    if (offset > 0) {
        if (offset < buffer_len) {
            memmove(buffer, buffer + offset, buffer_len - offset);
            conn->recv_buffer_pos = buffer_len - offset;
        } else {
            conn->recv_buffer_pos = 0;
        }
    }
}

/**
 * @brief Read callback
 *
 * @param[in] stream  Stream handle
 * @param[in] nread   Number of bytes read
 * @param[in] buf     Buffer
 */
static void read_callback(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    struct connection *conn = (struct connection *)stream->data;
    
    (void)buf; /* Unused */
    
    if (!conn) {
        log_error("Read callback: no connection data");
        return;
    }
    
    if (nread < 0) {
        if (nread != UV_EOF) {
            log_error("Read error: %s", uv_strerror((int)nread));
        }
        
        conn->state = CONN_STATE_ERROR;
        network_close_connection(conn);
        return;
    }
    
    if (nread == 0) {
        /* No data read, continue */
        return;
    }
    
    /* Update buffer position */
    conn->recv_buffer_pos += nread;
    
    log_debug("Received %zd bytes from %s", nread, 
              network_connection_info(conn, NULL, 0));
    
    /* Process any complete messages */
    if (conn->on_message) {
        process_messages(conn);
    } else if (conn->on_data) {
        /* Raw data callback */
        conn->on_data(conn, conn->recv_buffer, conn->recv_buffer_pos);
        conn->recv_buffer_pos = 0; /* Reset buffer */
    }
}

/**
 * @brief Write callback
 *
 * @param[in] req     Write request
 * @param[in] status  Write status
 */
static void write_callback(uv_write_t *req, int status)
{
    struct write_request *write_req = (struct write_request *)req;
    
    if (status < 0) {
        log_error("Write error: %s", uv_strerror(status));
        if (write_req->conn) {
            write_req->conn->state = CONN_STATE_ERROR;
            network_close_connection(write_req->conn);
        }
    }
    
    /* Free write request and buffer */
    if (write_req->buf.base) {
        free(write_req->buf.base);
    }
    free(write_req);
}

/**
 * @brief Connection callback
 *
 * @param[in] req     Connect request
 * @param[in] status  Connection status
 */
static void connect_callback(uv_connect_t *req, int status)
{
    struct connect_request *connect_req = (struct connect_request *)req;
    struct connection *conn = connect_req->conn;
    
    if (status < 0) {
        log_error("Connection failed: %s", uv_strerror(status));
        conn->state = CONN_STATE_ERROR;
    } else {
        log_info("Connected to %s", network_connection_info(conn, NULL, 0));
        conn->state = CONN_STATE_CONNECTED;
        
        /* Start reading */
        int result = uv_read_start((uv_stream_t *)&conn->tcp_handle, 
                                  alloc_buffer_callback, read_callback);
        if (result < 0) {
            log_error("Failed to start reading: %s", uv_strerror(result));
            conn->state = CONN_STATE_ERROR;
        }
    }
    
    /* Call connection callback */
    if (conn->on_connect) {
        conn->on_connect(conn, status);
    }
    
    free(connect_req);
}

/**
 * @brief New connection callback (server)
 *
 * @param[in] server  Server handle
 * @param[in] status  Status
 */
static void new_connection_callback(uv_stream_t *server, int status)
{
    struct network_context *ctx = (struct network_context *)server->data;
    struct connection *conn;
    int result;
    
    if (status < 0) {
        log_error("New connection error: %s", uv_strerror(status));
        return;
    }
    
    if (!ctx) {
        log_error("No network context in server handle");
        return;
    }
    
    /* Find available connection slot */
    conn = NULL;
    for (int i = 0; i < ctx->max_connections; i++) {
        if (ctx->connections[i].state == CONN_STATE_DISCONNECTED) {
            conn = &ctx->connections[i];
            break;
        }
    }
    
    if (!conn) {
        log_warning("No available connection slots");
        return;
    }
    
    /* Initialize connection */
    memset(conn, 0, sizeof(struct connection));
    conn->type = CONN_TYPE_SERVER;
    conn->state = CONN_STATE_CONNECTING;
    conn->ctx = ctx;
    
    /* Allocate buffers */
    conn->recv_buffer = malloc(DEFAULT_RECV_BUFFER_SIZE);
    conn->send_buffer = malloc(DEFAULT_SEND_BUFFER_SIZE);
    if (!conn->recv_buffer || !conn->send_buffer) {
        log_error("Failed to allocate connection buffers");
        SAFE_FREE(conn->recv_buffer);
        SAFE_FREE(conn->send_buffer);
        return;
    }
    
    conn->recv_buffer_size = DEFAULT_RECV_BUFFER_SIZE;
    conn->send_buffer_size = DEFAULT_SEND_BUFFER_SIZE;
    conn->recv_buffer_pos = 0;
    
    /* Initialize TCP handle */
    result = uv_tcp_init(ctx->loop, &conn->tcp_handle);
    if (result < 0) {
        log_error("Failed to initialize TCP handle: %s", uv_strerror(result));
        SAFE_FREE(conn->recv_buffer);
        SAFE_FREE(conn->send_buffer);
        return;
    }
    
    conn->tcp_handle.data = conn;
    
    /* Accept connection */
    result = uv_accept(server, (uv_stream_t *)&conn->tcp_handle);
    if (result < 0) {
        log_error("Failed to accept connection: %s", uv_strerror(result));
        uv_close((uv_handle_t *)&conn->tcp_handle, NULL);
        SAFE_FREE(conn->recv_buffer);
        SAFE_FREE(conn->send_buffer);
        return;
    }
    
    /* Get peer information */
    struct sockaddr_storage addr;
    int addr_len = sizeof(addr);
    result = uv_tcp_getpeername(&conn->tcp_handle, (struct sockaddr *)&addr, &addr_len);
    if (result == 0) {
        if (addr.ss_family == AF_INET) {
            struct sockaddr_in *addr_in = (struct sockaddr_in *)&addr;
            uv_ip4_name(addr_in, conn->remote_ip, sizeof(conn->remote_ip));
            conn->remote_port = ntohs(addr_in->sin_port);
        }
    }
    
    conn->state = CONN_STATE_CONNECTED;
    ctx->active_connections++;
    
    log_info("New client connected: %s", network_connection_info(conn, NULL, 0));
    
    /* Start reading */
    result = uv_read_start((uv_stream_t *)&conn->tcp_handle, 
                          alloc_buffer_callback, read_callback);
    if (result < 0) {
        log_error("Failed to start reading: %s", uv_strerror(result));
        network_close_connection(conn);
        return;
    }
    
    /* Call new connection callback */
    if (ctx->on_new_connection) {
        ctx->on_new_connection(conn, 0);
    }
}

/**
 * @brief Close callback
 *
 * @param[in] handle  Handle being closed
 */
static void close_callback(uv_handle_t *handle)
{
    struct connection *conn = (struct connection *)handle->data;
    
    if (conn) {
        log_debug("Connection closed: %s", network_connection_info(conn, NULL, 0));
        
        /* Free buffers */
        SAFE_FREE(conn->recv_buffer);
        SAFE_FREE(conn->send_buffer);
        
        /* Update state */
        conn->state = CONN_STATE_CLOSED;
        
        /* Update connection count */
        if (conn->ctx) {
            conn->ctx->active_connections--;
        }
        
        /* Call close callback */
        if (conn->on_close) {
            conn->on_close(conn);
        }
        
        /* Reset connection */
        memset(conn, 0, sizeof(struct connection));
    }
}

/**
 * @brief Initialize network context
 *
 * @param[out] ctx   Network context to initialize
 * @param[in]  loop  Event loop (NULL to create new one)
 *
 * @return 0 on success, negative error code on failure
 */
int network_init(struct network_context *ctx, uv_loop_t *loop)
{
    if (!ctx) {
        return SEED_ERROR_INVALID_ARGS;
    }
    
    memset(ctx, 0, sizeof(struct network_context));
    
    /* Initialize event loop */
    if (loop) {
        ctx->loop = loop;
    } else {
        ctx->loop = malloc(sizeof(uv_loop_t));
        if (!ctx->loop) {
            return SEED_ERROR_OUT_OF_MEMORY;
        }
        
        int result = uv_loop_init(ctx->loop);
        if (result < 0) {
            log_error("Failed to initialize event loop: %s", uv_strerror(result));
            free(ctx->loop);
            return SEED_ERROR_NETWORK;
        }
    }
    
    /* Allocate connection array */
    ctx->max_connections = MAX_CONNECTIONS;
    ctx->connections = calloc(ctx->max_connections, sizeof(struct connection));
    if (!ctx->connections) {
        if (loop == NULL) {
            uv_loop_close(ctx->loop);
            free(ctx->loop);
        }
        return SEED_ERROR_OUT_OF_MEMORY;
    }
    
    ctx->running = false;
    ctx->active_connections = 0;
    
    log_debug("Network context initialized");
    
    return SEED_OK;
}

/**
 * @brief Cleanup network context
 *
 * @param[in,out] ctx  Network context to cleanup
 */
void network_cleanup(struct network_context *ctx)
{
    if (!ctx) return;
    
    /* Stop server if running */
    network_stop_server(ctx);
    
    /* Close all connections */
    if (ctx->connections) {
        for (int i = 0; i < ctx->max_connections; i++) {
            if (ctx->connections[i].state != CONN_STATE_DISCONNECTED) {
                network_close_connection(&ctx->connections[i]);
            }
        }
        free(ctx->connections);
    }
    
    /* Cleanup event loop */
    if (ctx->loop) {
        uv_loop_close(ctx->loop);
        free(ctx->loop);
    }
    
    log_debug("Network context cleaned up");
    
    memset(ctx, 0, sizeof(struct network_context));
}

/**
 * @brief Start network server
 *
 * @param[in,out] ctx       Network context
 * @param[in]     bind_addr Bind address
 * @param[in]     bind_port Bind port
 *
 * @return 0 on success, negative error code on failure
 */
int network_start_server(struct network_context *ctx, const char *bind_addr, int bind_port)
{
    struct sockaddr_in addr;
    int result;
    
    if (!ctx || !bind_addr || bind_port <= 0) {
        return SEED_ERROR_INVALID_ARGS;
    }
    
    /* Parse bind address */
    result = uv_ip4_addr(bind_addr, bind_port, &addr);
    if (result < 0) {
        log_error("Invalid bind address %s:%d: %s", bind_addr, bind_port, uv_strerror(result));
        return SEED_ERROR_INVALID_ARGS;
    }
    
    /* Initialize server handle */
    result = uv_tcp_init(ctx->loop, &ctx->server_handle);
    if (result < 0) {
        log_error("Failed to initialize server handle: %s", uv_strerror(result));
        return SEED_ERROR_NETWORK;
    }
    
    ctx->server_handle.data = ctx;
    
    /* Bind server */
    result = uv_tcp_bind(&ctx->server_handle, (const struct sockaddr *)&addr, 0);
    if (result < 0) {
        log_error("Failed to bind to %s:%d: %s", bind_addr, bind_port, uv_strerror(result));
        return SEED_ERROR_NETWORK;
    }
    
    /* Start listening */
    result = uv_listen((uv_stream_t *)&ctx->server_handle, 128, new_connection_callback);
    if (result < 0) {
        log_error("Failed to listen: %s", uv_strerror(result));
        return SEED_ERROR_NETWORK;
    }
    
    strncpy(ctx->bind_addr, bind_addr, sizeof(ctx->bind_addr) - 1);
    ctx->bind_port = bind_port;
    
    log_info("Server listening on %s:%d", bind_addr, bind_port);
    
    return SEED_OK;
}

/**
 * @brief Stop network server
 *
 * @param[in,out] ctx  Network context
 */
void network_stop_server(struct network_context *ctx)
{
    if (!ctx) return;
    
    if (ctx->server_handle.data) {
        uv_close((uv_handle_t *)&ctx->server_handle, NULL);
        ctx->server_handle.data = NULL;
    }
    
    log_info("Server stopped");
}

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
                   struct connection *conn)
{
    struct sockaddr_in addr;
    struct connect_request *connect_req;
    int result;
    
    if (!ctx || !remote_addr || remote_port <= 0 || !conn) {
        return SEED_ERROR_INVALID_ARGS;
    }
    
    /* Parse remote address */
    result = uv_ip4_addr(remote_addr, remote_port, &addr);
    if (result < 0) {
        log_error("Invalid remote address %s:%d: %s", remote_addr, remote_port, uv_strerror(result));
        return SEED_ERROR_INVALID_ARGS;
    }
    
    /* Initialize connection */
    memset(conn, 0, sizeof(struct connection));
    conn->type = CONN_TYPE_CLIENT;
    conn->state = CONN_STATE_CONNECTING;
    conn->ctx = ctx;
    conn->addr = addr;
    strncpy(conn->remote_ip, remote_addr, sizeof(conn->remote_ip) - 1);
    conn->remote_port = remote_port;
    
    /* Allocate buffers */
    conn->recv_buffer = malloc(DEFAULT_RECV_BUFFER_SIZE);
    conn->send_buffer = malloc(DEFAULT_SEND_BUFFER_SIZE);
    if (!conn->recv_buffer || !conn->send_buffer) {
        log_error("Failed to allocate connection buffers");
        SAFE_FREE(conn->recv_buffer);
        SAFE_FREE(conn->send_buffer);
        return SEED_ERROR_OUT_OF_MEMORY;
    }
    
    conn->recv_buffer_size = DEFAULT_RECV_BUFFER_SIZE;
    conn->send_buffer_size = DEFAULT_SEND_BUFFER_SIZE;
    conn->recv_buffer_pos = 0;
    
    /* Initialize TCP handle */
    result = uv_tcp_init(ctx->loop, &conn->tcp_handle);
    if (result < 0) {
        log_error("Failed to initialize TCP handle: %s", uv_strerror(result));
        SAFE_FREE(conn->recv_buffer);
        SAFE_FREE(conn->send_buffer);
        return SEED_ERROR_NETWORK;
    }
    
    conn->tcp_handle.data = conn;
    
    /* Create connect request */
    connect_req = malloc(sizeof(struct connect_request));
    if (!connect_req) {
        uv_close((uv_handle_t *)&conn->tcp_handle, NULL);
        SAFE_FREE(conn->recv_buffer);
        SAFE_FREE(conn->send_buffer);
        return SEED_ERROR_OUT_OF_MEMORY;
    }
    
    connect_req->conn = conn;
    
    /* Start connection */
    result = uv_tcp_connect(&connect_req->req, &conn->tcp_handle, 
                           (const struct sockaddr *)&addr, connect_callback);
    if (result < 0) {
        log_error("Failed to connect: %s", uv_strerror(result));
        free(connect_req);
        uv_close((uv_handle_t *)&conn->tcp_handle, NULL);
        SAFE_FREE(conn->recv_buffer);
        SAFE_FREE(conn->send_buffer);
        return SEED_ERROR_NETWORK;
    }
    
    log_info("Connecting to %s:%d...", remote_addr, remote_port);
    
    return SEED_OK;
}

/**
 * @brief Send protocol message
 *
 * @param[in] conn  Connection
 * @param[in] msg   Message to send
 *
 * @return 0 on success, negative error code on failure
 */
int network_send_message(struct connection *conn, const struct protocol_message *msg)
{
    struct write_request *write_req;
    uint8_t *buffer;
    int serialized_len;
    
    if (!conn || !msg) {
        return SEED_ERROR_INVALID_ARGS;
    }
    
    if (conn->state != CONN_STATE_CONNECTED && conn->state != CONN_STATE_AUTHENTICATED) {
        log_error("Cannot send message: connection not ready");
        return SEED_ERROR_NETWORK;
    }
    
    /* Allocate buffer for serialization */
    buffer = malloc(MAX_MESSAGE_SIZE);
    if (!buffer) {
        return SEED_ERROR_OUT_OF_MEMORY;
    }
    
    /* Serialize message */
    serialized_len = protocol_serialize(msg, buffer, MAX_MESSAGE_SIZE);
    if (serialized_len < 0) {
        free(buffer);
        return serialized_len;
    }
    
    /* Create write request */
    write_req = malloc(sizeof(struct write_request));
    if (!write_req) {
        free(buffer);
        return SEED_ERROR_OUT_OF_MEMORY;
    }
    
    write_req->conn = conn;
    write_req->buf.base = (char *)buffer;
    write_req->buf.len = serialized_len;
    
    /* Send data */
    int result = uv_write(&write_req->req, (uv_stream_t *)&conn->tcp_handle, 
                         &write_req->buf, 1, write_callback);
    if (result < 0) {
        log_error("Failed to write data: %s", uv_strerror(result));
        free(buffer);
        free(write_req);
        return SEED_ERROR_NETWORK;
    }
    
    log_debug("Sent %s message (%d bytes) to %s", 
              protocol_type_name((enum message_type)msg->header.type),
              serialized_len,
              network_connection_info(conn, NULL, 0));
    
    return SEED_OK;
}

/**
 * @brief Send raw data
 *
 * @param[in] conn  Connection
 * @param[in] data  Data to send
 * @param[in] len   Data length
 *
 * @return 0 on success, negative error code on failure
 */
int network_send_data(struct connection *conn, const uint8_t *data, size_t len)
{
    struct write_request *write_req;
    uint8_t *buffer;
    
    if (!conn || !data || len == 0) {
        return SEED_ERROR_INVALID_ARGS;
    }
    
    if (conn->state != CONN_STATE_CONNECTED && conn->state != CONN_STATE_AUTHENTICATED) {
        log_error("Cannot send data: connection not ready");
        return SEED_ERROR_NETWORK;
    }
    
    /* Allocate buffer copy */
    buffer = malloc(len);
    if (!buffer) {
        return SEED_ERROR_OUT_OF_MEMORY;
    }
    
    memcpy(buffer, data, len);
    
    /* Create write request */
    write_req = malloc(sizeof(struct write_request));
    if (!write_req) {
        free(buffer);
        return SEED_ERROR_OUT_OF_MEMORY;
    }
    
    write_req->conn = conn;
    write_req->buf.base = (char *)buffer;
    write_req->buf.len = len;
    
    /* Send data */
    int result = uv_write(&write_req->req, (uv_stream_t *)&conn->tcp_handle, 
                         &write_req->buf, 1, write_callback);
    if (result < 0) {
        log_error("Failed to write raw data: %s", uv_strerror(result));
        free(buffer);
        free(write_req);
        return SEED_ERROR_NETWORK;
    }
    
    log_debug("Sent %zu bytes to %s", len, network_connection_info(conn, NULL, 0));
    
    return SEED_OK;
}

/**
 * @brief Close connection
 *
 * @param[in,out] conn  Connection to close
 */
void network_close_connection(struct connection *conn)
{
    if (!conn || conn->state == CONN_STATE_CLOSED) {
        return;
    }
    
    log_debug("Closing connection: %s", network_connection_info(conn, NULL, 0));
    
    conn->state = CONN_STATE_CLOSED;
    
    if (conn->tcp_handle.data) {
        uv_close((uv_handle_t *)&conn->tcp_handle, close_callback);
    }
}

/**
 * @brief Run network event loop
 *
 * @param[in,out] ctx  Network context
 *
 * @return 0 on success, negative error code on failure
 */
int network_run(struct network_context *ctx)
{
    if (!ctx) {
        return SEED_ERROR_INVALID_ARGS;
    }
    
    ctx->running = true;
    
    log_info("Starting network event loop");
    
    int result = uv_run(ctx->loop, UV_RUN_DEFAULT);
    
    ctx->running = false;
    
    log_info("Network event loop stopped");
    
    return result;
}

/**
 * @brief Stop network event loop
 *
 * @param[in,out] ctx  Network context
 */
void network_stop(struct network_context *ctx)
{
    if (!ctx) return;
    
    ctx->running = false;
    uv_stop(ctx->loop);
    
    log_info("Network stop requested");
}

/**
 * @brief Get connection info string
 *
 * @param[in]  conn     Connection
 * @param[out] buffer   Buffer to fill
 * @param[in]  buflen   Buffer length
 *
 * @return Buffer pointer
 */
const char *network_connection_info(const struct connection *conn, char *buffer, size_t buflen)
{
    static char static_buffer[128];
    char *buf = buffer ? buffer : static_buffer;
    size_t len = buffer ? buflen : sizeof(static_buffer);
    
    if (!conn) {
        snprintf(buf, len, "null");
        return buf;
    }
    
    snprintf(buf, len, "%s:%d", conn->remote_ip, conn->remote_port);
    
    return buf;
}