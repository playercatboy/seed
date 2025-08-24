/**
 * @file tcp_proxy.c
 * @brief TCP proxy implementation for Seed reverse proxy
 * @author Seed Development Team
 * @date 2025
 */

#include "tcp_proxy.h"
#include "log.h"
#include "encrypt.h"
#include <uv.h>

/**
 * @brief Connection callback for incoming client connections
 */
static void on_client_connection(uv_stream_t *server, int status);

/**
 * @brief Connection callback for outgoing target connections
 */
static void on_target_connect(uv_connect_t *req, int status);

/**
 * @brief Read callback for client data
 */
static void on_client_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);

/**
 * @brief Read callback for target data
 */
static void on_target_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);

/**
 * @brief Allocate callback for read operations
 */
static void on_tcp_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);

/**
 * @brief Write callback for data forwarding
 */
static void on_tcp_write(uv_write_t *req, int status);

/**
 * @brief Close callback for TCP handles
 */
static void on_tcp_close(uv_handle_t *handle);

/**
 * @brief Add connection to proxy's connection list
 */
static void add_connection(struct tcp_proxy *proxy, struct tcp_connection *conn);

/**
 * @brief Remove connection from proxy's connection list
 */
static void remove_connection(struct tcp_proxy *proxy, struct tcp_connection *conn);

/**
 * @brief Forward data from source to destination
 */
static int forward_data(uv_stream_t *dest, const uint8_t *data, size_t size);

/**
 * @brief Forward data with encryption support
 */
static int forward_data_with_encryption(struct tcp_proxy *proxy, uv_stream_t *dest, 
                                       const uint8_t *data, size_t size, bool encrypt_direction);

int tcp_proxy_init(struct tcp_proxy *proxy, struct network_context *network,
                  const char *name, const char *bind_addr, uint16_t bind_port,
                  const char *target_addr, uint16_t target_port, bool encrypt,
                  enum encrypt_impl encrypt_impl)
{
    if (!proxy || !network || !name || !bind_addr || !target_addr) {
        log_error("Invalid arguments to tcp_proxy_init");
        return SEED_ERROR_INVALID_ARGS;
    }

    /* Initialize proxy structure */
    memset(proxy, 0, sizeof(*proxy));
    proxy->network = network;
    proxy->encrypt = encrypt;
    proxy->encrypt_impl = encrypt_impl;
    proxy->encrypt_ctx = NULL;
    proxy->connections = NULL;
    proxy->connection_count = 0;
    proxy->total_connections = 0;
    proxy->active_connections = 0;
    proxy->total_bytes_transferred = 0;

    /* Store proxy name */
    strncpy(proxy->name, name, sizeof(proxy->name) - 1);
    proxy->name[sizeof(proxy->name) - 1] = '\0';

    /* Parse bind address */
    int ret = uv_ip4_addr(bind_addr, bind_port, &proxy->bind_addr);
    if (ret != 0) {
        log_error("Invalid bind address: %s:%d", bind_addr, bind_port);
        return SEED_ERROR_INVALID_ARGS;
    }

    /* Parse target address */
    ret = uv_ip4_addr(target_addr, target_port, &proxy->target_addr);
    if (ret != 0) {
        log_error("Invalid target address: %s:%d", target_addr, target_port);
        return SEED_ERROR_INVALID_ARGS;
    }

    /* Initialize server handle */
    ret = uv_tcp_init(network->loop, &proxy->server_handle);
    if (ret != 0) {
        log_error("Failed to initialize TCP server: %s", uv_strerror(ret));
        return SEED_ERROR_NETWORK;
    }

    proxy->server_handle.data = proxy;

    /* Initialize encryption if enabled */
    if (encrypt && encrypt_impl != ENCRYPT_NONE) {
        proxy->encrypt_ctx = encrypt_instance_create(encrypt_impl, NULL);
        if (!proxy->encrypt_ctx) {
            log_error("Failed to create encryption context for %s", encrypt_type_string(encrypt_impl));
            return SEED_ERROR_ENCRYPTION;
        }
        log_info("TCP proxy '%s' encryption enabled: %s", name, encrypt_type_string(encrypt_impl));
    }

    log_info("TCP proxy '%s' initialized: %s:%d -> %s:%d (encrypt=%s)",
             name, bind_addr, bind_port, target_addr, target_port,
             encrypt ? encrypt_type_string(encrypt_impl) : "no");

    return SEED_OK;
}

int tcp_proxy_start(struct tcp_proxy *proxy)
{
    if (!proxy) {
        log_error("Invalid arguments to tcp_proxy_start");
        return SEED_ERROR_INVALID_ARGS;
    }

    /* Bind to address */
    int ret = uv_tcp_bind(&proxy->server_handle, 
                         (const struct sockaddr*)&proxy->bind_addr, 0);
    if (ret != 0) {
        log_error("Failed to bind TCP proxy '%s': %s", proxy->name, uv_strerror(ret));
        return SEED_ERROR_NETWORK;
    }

    /* Start listening for connections */
    ret = uv_listen((uv_stream_t*)&proxy->server_handle, 128, on_client_connection);
    if (ret != 0) {
        log_error("Failed to listen on TCP proxy '%s': %s", proxy->name, uv_strerror(ret));
        return SEED_ERROR_NETWORK;
    }

    log_info("TCP proxy '%s' started and listening", proxy->name);
    return SEED_OK;
}

int tcp_proxy_stop(struct tcp_proxy *proxy)
{
    if (!proxy) {
        log_error("Invalid arguments to tcp_proxy_stop");
        return SEED_ERROR_INVALID_ARGS;
    }

    log_info("Stopping TCP proxy '%s'", proxy->name);

    /* Close server handle */
    if (!uv_is_closing((uv_handle_t*)&proxy->server_handle)) {
        uv_close((uv_handle_t*)&proxy->server_handle, NULL);
    }

    /* Close all active connections */
    struct tcp_connection *conn = proxy->connections;
    while (conn) {
        struct tcp_connection *next = conn->next;
        tcp_connection_close(conn);
        conn = next;
    }

    return SEED_OK;
}

int tcp_proxy_get_stats(const struct tcp_proxy *proxy, struct tcp_proxy_stats *stats)
{
    if (!proxy || !stats) {
        log_error("Invalid arguments to tcp_proxy_get_stats");
        return SEED_ERROR_INVALID_ARGS;
    }

    stats->total_connections = proxy->total_connections;
    stats->active_connections = proxy->active_connections;
    stats->total_bytes_transferred = proxy->total_bytes_transferred;
    stats->bytes_per_second = 0; /* TODO: Calculate transfer rate */

    return SEED_OK;
}

void tcp_connection_close(struct tcp_connection *conn)
{
    if (!conn) {
        return;
    }

    if (conn->state == TCP_STATE_CLOSED) {
        return;
    }

    log_debug("Closing TCP connection");

    conn->state = TCP_STATE_CLOSING;

    /* Close client handle */
    if (!uv_is_closing((uv_handle_t*)&conn->client_handle)) {
        uv_close((uv_handle_t*)&conn->client_handle, on_tcp_close);
    }

    /* Close target handle */
    if (!uv_is_closing((uv_handle_t*)&conn->target_handle)) {
        uv_close((uv_handle_t*)&conn->target_handle, on_tcp_close);
    }
}

void tcp_proxy_cleanup(struct tcp_proxy *proxy)
{
    if (!proxy) {
        return;
    }

    log_info("Cleaning up TCP proxy '%s'", proxy->name);

    /* Stop proxy first */
    tcp_proxy_stop(proxy);

    /* Cleanup encryption context */
    if (proxy->encrypt_ctx) {
        encrypt_instance_destroy(proxy->encrypt_ctx);
        proxy->encrypt_ctx = NULL;
    }

    /* Clear proxy structure */
    memset(proxy, 0, sizeof(*proxy));
}

/* Static helper functions */

static void add_connection(struct tcp_proxy *proxy, struct tcp_connection *conn)
{
    if (!proxy || !conn) {
        return;
    }

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

    log_debug("Added connection to proxy '%s' (count: %d)", proxy->name, proxy->connection_count);
}

static void remove_connection(struct tcp_proxy *proxy, struct tcp_connection *conn)
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

    log_debug("Removed connection from proxy '%s' (count: %d)", proxy->name, proxy->connection_count);

    /* Notify callback */
    if (proxy->on_connection_closed) {
        proxy->on_connection_closed(proxy, conn);
    }

    /* Free connection structure */
    free(conn);
}

static int forward_data(uv_stream_t *dest, const uint8_t *data, size_t size)
{
    if (!dest || !data || size == 0) {
        return SEED_ERROR_INVALID_ARGS;
    }

    /* Allocate write request and buffer */
    uv_write_t *write_req = malloc(sizeof(*write_req));
    if (!write_req) {
        log_error("Failed to allocate write request");
        return SEED_ERROR_OUT_OF_MEMORY;
    }

    uv_buf_t *write_buf = malloc(sizeof(*write_buf));
    if (!write_buf) {
        free(write_req);
        return SEED_ERROR_OUT_OF_MEMORY;
    }

    uint8_t *buffer_data = malloc(size);
    if (!buffer_data) {
        free(write_req);
        free(write_buf);
        return SEED_ERROR_OUT_OF_MEMORY;
    }

    /* Copy data */
    memcpy(buffer_data, data, size);
    
    write_buf->base = (char*)buffer_data;
    write_buf->len = size;
    write_req->data = write_buf;

    /* Send data */
    int ret = uv_write(write_req, dest, write_buf, 1, on_tcp_write);
    if (ret != 0) {
        log_error("Failed to write data: %s", uv_strerror(ret));
        free(write_req);
        free(write_buf);
        free(buffer_data);
        return SEED_ERROR_NETWORK;
    }

    return SEED_OK;
}

/**
 * @brief Forward data with encryption support
 */
static int forward_data_with_encryption(struct tcp_proxy *proxy, uv_stream_t *dest, 
                                       const uint8_t *data, size_t size, bool encrypt_direction)
{
    if (!proxy || !dest || !data || size == 0) {
        return SEED_ERROR_INVALID_ARGS;
    }

    const uint8_t *forward_data = data;
    size_t forward_size = size;
    uint8_t *encrypted_data = NULL;
    
    /* Apply encryption/decryption if enabled */
    if (proxy->encrypt && proxy->encrypt_ctx) {
        if (encrypt_direction) {
            /* Encrypt data going to target */
            char *cipher_text = NULL;
            size_t cipher_len = 0;
            
            int ret = encrypt_instance_encrypt(proxy->encrypt_ctx, 
                                             (const char*)data, size,
                                             &cipher_text, &cipher_len);
            if (ret != SEED_OK || !cipher_text) {
                log_error("Failed to encrypt data for forwarding");
                return ret;
            }
            
            encrypted_data = (uint8_t*)cipher_text;
            forward_data = encrypted_data;
            forward_size = cipher_len;
            
            log_debug("Encrypted %zu bytes to %zu bytes", size, cipher_len);
        } else {
            /* Decrypt data coming from target */
            char *plain_text = NULL;
            size_t plain_len = 0;
            
            int ret = encrypt_instance_decrypt(proxy->encrypt_ctx,
                                             (const char*)data, size,
                                             &plain_text, &plain_len);
            if (ret != SEED_OK || !plain_text) {
                log_error("Failed to decrypt data for forwarding");
                return ret;
            }
            
            encrypted_data = (uint8_t*)plain_text;
            forward_data = encrypted_data;
            forward_size = plain_len;
            
            log_debug("Decrypted %zu bytes to %zu bytes", size, plain_len);
        }
    }
    
    /* Forward the data (encrypted or plain) */
    int ret = forward_data(dest, forward_data, forward_size);
    
    /* Free encrypted/decrypted data if allocated */
    if (encrypted_data) {
        free(encrypted_data);
    }
    
    return ret;
}

/* libuv callback functions */

static void on_client_connection(uv_stream_t *server, int status)
{
    struct tcp_proxy *proxy = (struct tcp_proxy*)server->data;
    
    if (status != 0) {
        log_error("Client connection error: %s", uv_strerror(status));
        return;
    }

    log_debug("New client connection on proxy '%s'", proxy->name);

    /* Allocate connection structure */
    struct tcp_connection *conn = malloc(sizeof(*conn));
    if (!conn) {
        log_error("Failed to allocate connection structure");
        return;
    }

    memset(conn, 0, sizeof(*conn));
    conn->proxy = proxy;
    conn->state = TCP_STATE_CONNECTING;

    /* Initialize client handle */
    int ret = uv_tcp_init(proxy->network->loop, &conn->client_handle);
    if (ret != 0) {
        log_error("Failed to initialize client handle: %s", uv_strerror(ret));
        free(conn);
        return;
    }

    conn->client_handle.data = conn;

    /* Accept client connection */
    ret = uv_accept(server, (uv_stream_t*)&conn->client_handle);
    if (ret != 0) {
        log_error("Failed to accept client connection: %s", uv_strerror(ret));
        uv_close((uv_handle_t*)&conn->client_handle, NULL);
        free(conn);
        return;
    }

    /* Get client address */
    int addr_len = sizeof(conn->client_addr);
    uv_tcp_getpeername(&conn->client_handle, 
                      (struct sockaddr*)&conn->client_addr, &addr_len);

    /* Initialize target handle */
    ret = uv_tcp_init(proxy->network->loop, &conn->target_handle);
    if (ret != 0) {
        log_error("Failed to initialize target handle: %s", uv_strerror(ret));
        uv_close((uv_handle_t*)&conn->client_handle, NULL);
        free(conn);
        return;
    }

    conn->target_handle.data = conn;
    conn->connect_req.data = conn;

    /* Connect to target */
    ret = uv_tcp_connect(&conn->connect_req, &conn->target_handle,
                        (const struct sockaddr*)&proxy->target_addr,
                        on_target_connect);
    if (ret != 0) {
        log_error("Failed to connect to target: %s", uv_strerror(ret));
        uv_close((uv_handle_t*)&conn->client_handle, NULL);
        uv_close((uv_handle_t*)&conn->target_handle, NULL);
        free(conn);
        return;
    }

    /* Add connection to proxy */
    add_connection(proxy, conn);
}

static void on_target_connect(uv_connect_t *req, int status)
{
    struct tcp_connection *conn = (struct tcp_connection*)req->data;
    struct tcp_proxy *proxy = conn->proxy;

    if (status != 0) {
        log_error("Failed to connect to target: %s", uv_strerror(status));
        tcp_connection_close(conn);
        return;
    }

    log_debug("Connected to target for proxy '%s'", proxy->name);

    conn->state = TCP_STATE_CONNECTED;

    /* Start reading from both client and target */
    int ret = uv_read_start((uv_stream_t*)&conn->client_handle, 
                           on_tcp_alloc, on_client_read);
    if (ret != 0) {
        log_error("Failed to start reading from client: %s", uv_strerror(ret));
        tcp_connection_close(conn);
        return;
    }

    ret = uv_read_start((uv_stream_t*)&conn->target_handle,
                       on_tcp_alloc, on_target_read);
    if (ret != 0) {
        log_error("Failed to start reading from target: %s", uv_strerror(ret));
        tcp_connection_close(conn);
        return;
    }

    /* Notify callback */
    if (proxy->on_connection_established) {
        proxy->on_connection_established(proxy, conn);
    }
}

static void on_client_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    struct tcp_connection *conn = (struct tcp_connection*)stream->data;
    struct tcp_proxy *proxy = conn->proxy;

    if (nread < 0) {
        if (nread != UV_EOF) {
            log_debug("Client read error: %s", uv_strerror(nread));
        }
        tcp_connection_close(conn);
        if (buf->base) {
            free(buf->base);
        }
        return;
    }

    if (nread == 0) {
        if (buf->base) {
            free(buf->base);
        }
        return;
    }

    /* Forward data to target (encrypt if needed) */
    int ret = forward_data_with_encryption(proxy, (uv_stream_t*)&conn->target_handle, 
                                          (const uint8_t*)buf->base, nread, true);
    if (ret != SEED_OK) {
        log_error("Failed to forward data to target");
        tcp_connection_close(conn);
    } else {
        conn->bytes_received += nread;
        proxy->total_bytes_transferred += nread;
        
        if (proxy->on_data_transferred) {
            proxy->on_data_transferred(proxy, nread);
        }
    }

    if (buf->base) {
        free(buf->base);
    }
}

static void on_target_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    struct tcp_connection *conn = (struct tcp_connection*)stream->data;
    struct tcp_proxy *proxy = conn->proxy;

    if (nread < 0) {
        if (nread != UV_EOF) {
            log_debug("Target read error: %s", uv_strerror(nread));
        }
        tcp_connection_close(conn);
        if (buf->base) {
            free(buf->base);
        }
        return;
    }

    if (nread == 0) {
        if (buf->base) {
            free(buf->base);
        }
        return;
    }

    /* Forward data to client (decrypt if needed) */
    int ret = forward_data_with_encryption(proxy, (uv_stream_t*)&conn->client_handle, 
                                          (const uint8_t*)buf->base, nread, false);
    if (ret != SEED_OK) {
        log_error("Failed to forward data to client");
        tcp_connection_close(conn);
    } else {
        conn->bytes_sent += nread;
        proxy->total_bytes_transferred += nread;
        
        if (proxy->on_data_transferred) {
            proxy->on_data_transferred(proxy, nread);
        }
    }

    if (buf->base) {
        free(buf->base);
    }
}

static void on_tcp_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    /* Allocate buffer for reading */
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
}

static void on_tcp_write(uv_write_t *req, int status)
{
    uv_buf_t *write_buf = (uv_buf_t*)req->data;
    
    if (status != 0) {
        log_debug("TCP write error: %s", uv_strerror(status));
    }

    if (write_buf) {
        if (write_buf->base) {
            free(write_buf->base);
        }
        free(write_buf);
    }
    free(req);
}

static void on_tcp_close(uv_handle_t *handle)
{
    struct tcp_connection *conn = (struct tcp_connection*)handle->data;
    
    if (!conn) {
        return;
    }

    /* Check if both handles are closed */
    if (uv_is_closing((uv_handle_t*)&conn->client_handle) && 
        uv_is_closing((uv_handle_t*)&conn->target_handle)) {
        
        conn->state = TCP_STATE_CLOSED;
        
        log_debug("TCP connection closed (received: %llu bytes, sent: %llu bytes)",
                 (unsigned long long)conn->bytes_received,
                 (unsigned long long)conn->bytes_sent);
        
        /* Remove from proxy's connection list */
        remove_connection(conn->proxy, conn);
    }
}