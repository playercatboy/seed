/**
 * @file client.c
 * @brief Client mode implementation for Seed reverse proxy
 * @author Seed Development Team
 * @date 2025
 */

#include "client.h"
#include "log.h"
#include "auth.h"
#include "jwt.h"
#include <uv.h>

/**
 * @brief Connection callback for server connection
 */
static void on_server_connect(uv_connect_t *req, int status);

/**
 * @brief Read callback for server connection
 */
static void on_server_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);

/**
 * @brief Allocate callback for server connection
 */
static void on_server_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);

/**
 * @brief Write callback for server connection
 */
static void on_server_write(uv_write_t *req, int status);

/**
 * @brief Keepalive timer callback
 */
static void on_keepalive_timer(uv_timer_t *timer);

/**
 * @brief Close callback for server connection
 */
static void on_server_close(uv_handle_t *handle);

int client_init(struct client_session *session, struct network_context *network, const struct seed_config *config)
{
    if (!session || !network || !config) {
        log_error("Invalid arguments to client_init");
        return SEED_ERROR_INVALID_ARGS;
    }

    /* Initialize session structure */
    memset(session, 0, sizeof(*session));
    session->network = network;
    session->state = CLIENT_STATE_DISCONNECTED;
    session->proxy_count = 0;

    /* Initialize server connection handle */
    int ret = uv_tcp_init(network->loop, &session->server_connection);
    if (ret != 0) {
        log_error("Failed to initialize server connection: %s", uv_strerror(ret));
        return SEED_ERROR_NETWORK;
    }

    /* Set session as handle data */
    session->server_connection.data = session;

    /* Initialize keepalive timer */
    ret = uv_timer_init(network->loop, &session->keepalive_timer);
    if (ret != 0) {
        log_error("Failed to initialize keepalive timer: %s", uv_strerror(ret));
        uv_close((uv_handle_t*)&session->server_connection, NULL);
        return SEED_ERROR_NETWORK;
    }

    session->keepalive_timer.data = session;

    log_info("Client session initialized");
    return SEED_OK;
}

int client_connect(struct client_session *session, const char *server_addr, uint16_t server_port)
{
    if (!session || !server_addr) {
        log_error("Invalid arguments to client_connect");
        return SEED_ERROR_INVALID_ARGS;
    }

    if (session->state != CLIENT_STATE_DISCONNECTED) {
        log_error("Client is not in disconnected state");
        return SEED_ERROR;
    }

    /* Store server details */
    strncpy(session->server_addr, server_addr, sizeof(session->server_addr) - 1);
    session->server_addr[sizeof(session->server_addr) - 1] = '\0';
    session->server_port = server_port;

    /* Parse server address */
    struct sockaddr_in dest;
    int ret = uv_ip4_addr(server_addr, server_port, &dest);
    if (ret != 0) {
        log_error("Invalid server address: %s:%d", server_addr, server_port);
        return SEED_ERROR_INVALID_ARGS;
    }

    /* Create connection request */
    uv_connect_t *connect_req = malloc(sizeof(*connect_req));
    if (!connect_req) {
        log_error("Failed to allocate connect request");
        return SEED_ERROR_OUT_OF_MEMORY;
    }

    connect_req->data = session;
    session->state = CLIENT_STATE_CONNECTING;

    /* Connect to server */
    ret = uv_tcp_connect(connect_req, &session->server_connection,
                        (const struct sockaddr*)&dest, on_server_connect);
    if (ret != 0) {
        log_error("Failed to connect to server: %s", uv_strerror(ret));
        free(connect_req);
        session->state = CLIENT_STATE_ERROR;
        return SEED_ERROR_NETWORK;
    }

    log_info("Connecting to server %s:%d", server_addr, server_port);
    return SEED_OK;
}

int client_authenticate(struct client_session *session, const char *username, const char *password)
{
    if (!session || !username || !password) {
        log_error("Invalid arguments to client_authenticate");
        return SEED_ERROR_INVALID_ARGS;
    }

    if (session->state != CLIENT_STATE_AUTHENTICATED) {
        log_error("Client is not connected to server");
        return SEED_ERROR;
    }

    /* Store credentials */
    strncpy(session->username, username, sizeof(session->username) - 1);
    session->username[sizeof(session->username) - 1] = '\0';
    strncpy(session->password, password, sizeof(session->password) - 1);
    session->password[sizeof(session->password) - 1] = '\0';

    /* Create authentication message */
    struct protocol_message msg;
    memset(&msg, 0, sizeof(msg));
    
    msg.header.type = PROTOCOL_TYPE_AUTH_REQUEST;
    msg.header.sequence = 1;
    
    /* Create simple auth payload with username:password */
    char auth_payload[320]; /* username(64) + ":" + password(256) */
    snprintf(auth_payload, sizeof(auth_payload), "%s:%s", username, password);
    
    msg.header.length = strlen(auth_payload);
    msg.payload = (uint8_t*)auth_payload;

    session->state = CLIENT_STATE_AUTHENTICATING;

    /* Send authentication request */
    uint8_t buffer[1024];
    size_t buffer_size = sizeof(buffer);
    int ret = protocol_serialize_message(&msg, buffer, &buffer_size);
    if (ret != SEED_OK) {
        log_error("Failed to serialize authentication message");
        return ret;
    }

    /* Send message to server */
    uv_write_t *write_req = malloc(sizeof(*write_req));
    if (!write_req) {
        log_error("Failed to allocate write request");
        return SEED_ERROR_OUT_OF_MEMORY;
    }

    uv_buf_t *write_buf = malloc(sizeof(*write_buf));
    if (!write_buf) {
        log_error("Failed to allocate write buffer");
        free(write_req);
        return SEED_ERROR_OUT_OF_MEMORY;
    }

    uint8_t *data = malloc(buffer_size);
    if (!data) {
        log_error("Failed to allocate message data");
        free(write_req);
        free(write_buf);
        return SEED_ERROR_OUT_OF_MEMORY;
    }

    memcpy(data, buffer, buffer_size);
    write_buf->base = (char*)data;
    write_buf->len = buffer_size;
    write_req->data = write_buf;

    ret = uv_write(write_req, (uv_stream_t*)&session->server_connection,
                   write_buf, 1, on_server_write);
    if (ret != 0) {
        log_error("Failed to send authentication: %s", uv_strerror(ret));
        free(write_req);
        free(write_buf);
        free(data);
        return SEED_ERROR_NETWORK;
    }

    log_info("Sent authentication request for user: %s", username);
    return SEED_OK;
}

int client_add_proxy(struct client_session *session, const char *name, 
                    enum proxy_type type, const char *local_addr,
                    uint16_t local_port, uint16_t remote_port,
                    bool encrypt, enum encrypt_impl encrypt_impl)
{
    if (!session || !name || !local_addr) {
        log_error("Invalid arguments to client_add_proxy");
        return SEED_ERROR_INVALID_ARGS;
    }

    if (session->proxy_count >= MAX_PROXY_INSTANCES) {
        log_error("Maximum proxy instances reached");
        return SEED_ERROR;
    }

    struct proxy_instance *proxy = &session->proxies[session->proxy_count];
    
    /* Initialize proxy instance */
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

    session->proxy_count++;

    log_info("Added proxy instance '%s': %s %s:%d -> %d (encrypt=%s)",
             name, (type == PROXY_TYPE_TCP) ? "TCP" : "UDP",
             local_addr, local_port, remote_port,
             encrypt ? "yes" : "no");

    return SEED_OK;
}

int client_start_proxies(struct client_session *session)
{
    if (!session) {
        log_error("Invalid arguments to client_start_proxies");
        return SEED_ERROR_INVALID_ARGS;
    }

    if (session->state != CLIENT_STATE_AUTHENTICATED) {
        log_error("Client must be authenticated to start proxies");
        return SEED_ERROR;
    }

    log_info("Starting %d proxy instances", session->proxy_count);

    /* For now, just mark proxies as active - actual implementation would */
    /* create proxy request messages and send to server */
    for (int i = 0; i < session->proxy_count; i++) {
        struct proxy_instance *proxy = &session->proxies[i];
        proxy->active = true;
        
        log_info("Started proxy instance '%s'", proxy->name);
    }

    return SEED_OK;
}

int client_stop_proxies(struct client_session *session)
{
    if (!session) {
        log_error("Invalid arguments to client_stop_proxies");
        return SEED_ERROR_INVALID_ARGS;
    }

    log_info("Stopping proxy instances");

    for (int i = 0; i < session->proxy_count; i++) {
        struct proxy_instance *proxy = &session->proxies[i];
        if (proxy->active) {
            proxy->active = false;
            log_info("Stopped proxy instance '%s'", proxy->name);
        }
    }

    return SEED_OK;
}

void client_disconnect(struct client_session *session)
{
    if (!session) {
        return;
    }

    log_info("Disconnecting from server");

    /* Stop keepalive timer */
    if (!uv_is_closing((uv_handle_t*)&session->keepalive_timer)) {
        uv_timer_stop(&session->keepalive_timer);
        uv_close((uv_handle_t*)&session->keepalive_timer, NULL);
    }

    /* Close server connection */
    if (!uv_is_closing((uv_handle_t*)&session->server_connection)) {
        uv_close((uv_handle_t*)&session->server_connection, on_server_close);
    }

    /* Stop all proxies */
    client_stop_proxies(session);

    session->state = CLIENT_STATE_DISCONNECTED;
}

void client_cleanup(struct client_session *session)
{
    if (!session) {
        return;
    }

    log_info("Cleaning up client session");

    /* Disconnect if still connected */
    if (session->state != CLIENT_STATE_DISCONNECTED) {
        client_disconnect(session);
    }

    /* Clear sensitive data */
    memset(session->password, 0, sizeof(session->password));
    memset(session, 0, sizeof(*session));
}

int client_handle_message(struct client_session *session, const struct protocol_message *msg)
{
    if (!session || !msg) {
        log_error("Invalid arguments to client_handle_message");
        return SEED_ERROR_INVALID_ARGS;
    }

    log_debug("Handling message type %d", msg->header.type);

    switch (msg->header.type) {
        case PROTOCOL_TYPE_HELLO_RESPONSE:
            log_info("Received HELLO response from server");
            /* Server accepted our connection, now authenticate */
            session->state = CLIENT_STATE_AUTHENTICATED;
            if (session->on_connected) {
                session->on_connected(session);
            }
            break;

        case PROTOCOL_TYPE_AUTH_RESPONSE:
            log_info("Received authentication response");
            if (msg->header.flags == 0) {
                log_info("Authentication successful");
                session->state = CLIENT_STATE_AUTHENTICATED;
                if (session->on_authenticated) {
                    session->on_authenticated(session);
                }
                
                /* Start keepalive timer */
                uv_timer_start(&session->keepalive_timer, on_keepalive_timer,
                              KEEPALIVE_INTERVAL * 1000, KEEPALIVE_INTERVAL * 1000);
            } else {
                log_error("Authentication failed");
                session->state = CLIENT_STATE_ERROR;
                if (session->on_error) {
                    session->on_error(session, SEED_ERROR_AUTH_FAILED);
                }
            }
            break;

        case PROTOCOL_TYPE_PROXY_RESPONSE:
            log_info("Received proxy response");
            /* Handle proxy setup response */
            break;

        case PROTOCOL_TYPE_KEEPALIVE:
            log_debug("Received keepalive from server");
            /* Server keepalive - no action needed */
            break;

        case PROTOCOL_TYPE_ERROR:
            log_error("Received error from server");
            session->state = CLIENT_STATE_ERROR;
            if (session->on_error) {
                session->on_error(session, SEED_ERROR_PROTOCOL);
            }
            break;

        default:
            log_warning("Unknown message type: %d", msg->header.type);
            break;
    }

    return SEED_OK;
}

int client_send_keepalive(struct client_session *session)
{
    if (!session) {
        log_error("Invalid arguments to client_send_keepalive");
        return SEED_ERROR_INVALID_ARGS;
    }

    if (session->state != CLIENT_STATE_AUTHENTICATED) {
        return SEED_OK; /* Don't send keepalives if not authenticated */
    }

    /* Create keepalive message */
    struct protocol_message msg;
    memset(&msg, 0, sizeof(msg));
    msg.header.type = PROTOCOL_TYPE_KEEPALIVE;
    msg.header.sequence = 0;
    msg.header.length = 0;
    msg.payload = NULL;

    /* Serialize and send */
    uint8_t buffer[256];
    size_t buffer_size = sizeof(buffer);
    int ret = protocol_serialize_message(&msg, buffer, &buffer_size);
    if (ret != SEED_OK) {
        log_error("Failed to serialize keepalive message");
        return ret;
    }

    /* Send message */
    uv_write_t *write_req = malloc(sizeof(*write_req));
    if (!write_req) {
        return SEED_ERROR_OUT_OF_MEMORY;
    }

    uv_buf_t *write_buf = malloc(sizeof(*write_buf));
    if (!write_buf) {
        free(write_req);
        return SEED_ERROR_OUT_OF_MEMORY;
    }

    uint8_t *data = malloc(buffer_size);
    if (!data) {
        free(write_req);
        free(write_buf);
        return SEED_ERROR_OUT_OF_MEMORY;
    }

    memcpy(data, buffer, buffer_size);
    write_buf->base = (char*)data;
    write_buf->len = buffer_size;
    write_req->data = write_buf;

    ret = uv_write(write_req, (uv_stream_t*)&session->server_connection,
                   write_buf, 1, on_server_write);
    if (ret != 0) {
        log_error("Failed to send keepalive: %s", uv_strerror(ret));
        free(write_req);
        free(write_buf);
        free(data);
        return SEED_ERROR_NETWORK;
    }

    log_debug("Sent keepalive to server");
    return SEED_OK;
}

/* Static callback functions */

static void on_server_connect(uv_connect_t *req, int status)
{
    struct client_session *session = (struct client_session*)req->data;
    free(req);

    if (status != 0) {
        log_error("Failed to connect to server: %s", uv_strerror(status));
        session->state = CLIENT_STATE_ERROR;
        if (session->on_error) {
            session->on_error(session, SEED_ERROR_NETWORK);
        }
        return;
    }

    log_info("Connected to server %s:%d", session->server_addr, session->server_port);

    /* Start reading from server */
    int ret = uv_read_start((uv_stream_t*)&session->server_connection, 
                           on_server_alloc, on_server_read);
    if (ret != 0) {
        log_error("Failed to start reading from server: %s", uv_strerror(ret));
        session->state = CLIENT_STATE_ERROR;
        if (session->on_error) {
            session->on_error(session, SEED_ERROR_NETWORK);
        }
        return;
    }

    /* Send HELLO message */
    struct protocol_message hello_msg;
    memset(&hello_msg, 0, sizeof(hello_msg));
    hello_msg.header.type = PROTOCOL_TYPE_HELLO;
    hello_msg.header.sequence = 0;
    hello_msg.header.length = 0;
    hello_msg.payload = NULL;

    uint8_t buffer[256];
    size_t buffer_size = sizeof(buffer);
    ret = protocol_serialize_message(&hello_msg, buffer, &buffer_size);
    if (ret != SEED_OK) {
        log_error("Failed to serialize HELLO message");
        session->state = CLIENT_STATE_ERROR;
        if (session->on_error) {
            session->on_error(session, SEED_ERROR_PROTOCOL);
        }
        return;
    }

    /* Send HELLO message */
    uv_write_t *write_req = malloc(sizeof(*write_req));
    if (!write_req) {
        log_error("Failed to allocate write request");
        return;
    }

    uv_buf_t *write_buf = malloc(sizeof(*write_buf));
    if (!write_buf) {
        free(write_req);
        return;
    }

    uint8_t *data = malloc(buffer_size);
    if (!data) {
        free(write_req);
        free(write_buf);
        return;
    }

    memcpy(data, buffer, buffer_size);
    write_buf->base = (char*)data;
    write_buf->len = buffer_size;
    write_req->data = write_buf;

    ret = uv_write(write_req, (uv_stream_t*)&session->server_connection,
                   write_buf, 1, on_server_write);
    if (ret != 0) {
        log_error("Failed to send HELLO: %s", uv_strerror(ret));
        free(write_req);
        free(write_buf);
        free(data);
    } else {
        log_info("Sent HELLO message to server");
    }
}

static void on_server_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    /* Allocate buffer for reading */
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
}

static void on_server_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    struct client_session *session = (struct client_session*)stream->data;

    if (nread < 0) {
        if (nread != UV_EOF) {
            log_error("Read error from server: %s", uv_strerror(nread));
        } else {
            log_info("Server disconnected");
        }
        
        if (session->on_disconnected) {
            session->on_disconnected(session);
        }
        
        client_disconnect(session);
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

    /* Parse received message */
    struct protocol_message msg;
    int ret = protocol_parse_message((const uint8_t*)buf->base, nread, &msg);
    if (ret == SEED_OK) {
        client_handle_message(session, &msg);
    } else {
        log_error("Failed to parse message from server");
    }

    if (buf->base) {
        free(buf->base);
    }
}

static void on_server_write(uv_write_t *req, int status)
{
    uv_buf_t *write_buf = (uv_buf_t*)req->data;
    
    if (status != 0) {
        log_error("Write error to server: %s", uv_strerror(status));
    }

    if (write_buf) {
        if (write_buf->base) {
            free(write_buf->base);
        }
        free(write_buf);
    }
    free(req);
}

static void on_keepalive_timer(uv_timer_t *timer)
{
    struct client_session *session = (struct client_session*)timer->data;
    client_send_keepalive(session);
}

static void on_server_close(uv_handle_t *handle)
{
    log_debug("Server connection closed");
}