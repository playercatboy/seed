/**
 * @file client.c
 * @brief Client mode implementation for Seed reverse proxy
 * @author Seed Development Team
 * @date 2025
 */

#include "client.h"
#include "log.h"
#include "protocol.h"
#include "auth.h"
#include "jwt.h"
#include <uv.h>

/* Forward declarations */
static int send_echo_response(struct client_session *session, const struct msg_data *data_msg);
static void on_data_backward_write(uv_write_t *req, int status);
static int handle_data_forward(struct client_session *session, const struct msg_data *data_msg, const uint8_t *raw_buffer);
static int handle_udp_data(struct client_session *session, const struct msg_udp_data *udp_msg, const uint8_t *raw_buffer);
static struct local_connection *find_local_connection(struct client_session *session, const char *proxy_id, uint32_t connection_id);
static struct local_connection *create_local_connection(struct client_session *session, const char *proxy_id, uint32_t connection_id);
static void on_local_connect(uv_connect_t *req, int status);
static void on_local_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
static void on_local_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
static void on_local_write(uv_write_t *req, int status);

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
 * @brief Authentication timer callback
 */
static void on_auth_timer(uv_timer_t *timer);

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
    
    /* Copy credentials from config */
    strncpy(session->username, config->username, sizeof(session->username) - 1);
    session->username[sizeof(session->username) - 1] = '\0';
    strncpy(session->password, config->password, sizeof(session->password) - 1);
    session->password[sizeof(session->password) - 1] = '\0';

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

    if (session->state != CLIENT_STATE_CONNECTING && session->state != CLIENT_STATE_CONNECTED) {
        log_error("Client is not in a state to authenticate");
        return SEED_ERROR;
    }

    /* Store credentials */
    strncpy(session->username, username, sizeof(session->username) - 1);
    session->username[sizeof(session->username) - 1] = '\0';
    strncpy(session->password, password, sizeof(session->password) - 1);
    session->password[sizeof(session->password) - 1] = '\0';

    log_debug("client_authenticate called with username='%s', password='%s'", username, password);

    /* Create authentication message */
    struct protocol_message msg;
    protocol_init_message(&msg, MSG_TYPE_AUTH_REQUEST);
    
    /* Fill auth request payload */
    strncpy(msg.payload.auth_req.username, username, sizeof(msg.payload.auth_req.username) - 1);
    strncpy(msg.payload.auth_req.password, password, sizeof(msg.payload.auth_req.password) - 1);

    session->state = CLIENT_STATE_AUTHENTICATING;

    /* Send authentication request */
    uint8_t buffer[1024];
    int ret = protocol_serialize(&msg, buffer, sizeof(buffer));
    if (ret < 0) {
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

    uint8_t *data = malloc(ret);
    if (!data) {
        log_error("Failed to allocate message data");
        free(write_req);
        free(write_buf);
        return SEED_ERROR_OUT_OF_MEMORY;
    }

    memcpy(data, buffer, ret);
    write_buf->base = (char*)data;
    write_buf->len = ret;
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

    /* Send PROXY_REQUEST messages to server for each proxy instance */
    for (int i = 0; i < session->proxy_count; i++) {
        struct proxy_instance *proxy = &session->proxies[i];
        
        /* Create PROXY_REQUEST message */
        struct protocol_message msg;
        protocol_init_message(&msg, MSG_TYPE_PROXY_REQUEST);
        
        struct msg_proxy_request *req = &msg.payload.proxy_req;
        strncpy(req->proxy_name, proxy->name, sizeof(req->proxy_name) - 1);
        req->proxy_name[sizeof(req->proxy_name) - 1] = '\0';
        req->proxy_type = proxy->type;
        strncpy(req->local_addr, proxy->local_addr, sizeof(req->local_addr) - 1);
        req->local_addr[sizeof(req->local_addr) - 1] = '\0';
        req->local_port = proxy->local_port;
        req->remote_port = proxy->remote_port;
        req->encrypt_type = proxy->encrypt ? proxy->encrypt_impl : ENCRYPT_NONE;
        
        log_debug("Sending PROXY_REQUEST: name='%s' type=%d local=%s:%d remote_port=%d encrypt_type=%d",
                 req->proxy_name, req->proxy_type, req->local_addr, req->local_port, 
                 req->remote_port, req->encrypt_type);
        
        /* Serialize and send */
        uint8_t buffer[512];
        int ret = protocol_serialize(&msg, buffer, sizeof(buffer));
        if (ret < 0) {
            log_error("Failed to serialize PROXY_REQUEST message for '%s'", proxy->name);
            continue;
        }
        
        /* Send message */
        uv_write_t *write_req = malloc(sizeof(*write_req));
        if (!write_req) {
            log_error("Failed to allocate write request for proxy '%s'", proxy->name);
            continue;
        }
        
        uv_buf_t *write_buf = malloc(sizeof(*write_buf));
        if (!write_buf) {
            log_error("Failed to allocate write buffer for proxy '%s'", proxy->name);
            free(write_req);
            continue;
        }
        
        write_buf->base = malloc(ret);
        if (!write_buf->base) {
            log_error("Failed to allocate write buffer data for proxy '%s'", proxy->name);
            free(write_buf);
            free(write_req);
            continue;
        }
        
        memcpy(write_buf->base, buffer, ret);
        write_buf->len = ret;
        write_req->data = write_buf;
        
        int write_result = uv_write(write_req, (uv_stream_t*)&session->server_connection, write_buf, 1, on_server_write);
        if (write_result != 0) {
            log_error("Failed to send PROXY_REQUEST for '%s': %s", proxy->name, uv_strerror(write_result));
            free(write_buf->base);
            free(write_buf);
            free(write_req);
            continue;
        }
        
        proxy->active = true;
        log_info("Sent PROXY_REQUEST for proxy instance '%s'", proxy->name);
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

int client_handle_message(struct client_session *session, const struct protocol_message *msg, const uint8_t *raw_buffer)
{
    if (!session || !msg) {
        log_error("Invalid arguments to client_handle_message");
        return SEED_ERROR_INVALID_ARGS;
    }

    log_debug("Handling message type %d", msg->header.type);

    switch (msg->header.type) {
        case MSG_TYPE_HELLO:
            log_info("Received HELLO response from server");
            /* Server accepted our connection, now authenticate */
            session->state = CLIENT_STATE_AUTHENTICATED;
            if (session->on_connected) {
                session->on_connected(session);
            }
            break;

        case MSG_TYPE_AUTH_RESPONSE:
            {
                const struct msg_auth_response *auth_resp = &msg->payload.auth_resp;
                log_info("Received authentication response");
                log_debug("AUTH_RESPONSE status: %d, message: '%s'", 
                         auth_resp->status, auth_resp->message);
                
                if (auth_resp->status == 0) {
                    log_info("Authentication successful");
                    session->state = CLIENT_STATE_AUTHENTICATED;
                    if (session->on_authenticated) {
                        session->on_authenticated(session);
                    }
                    
                    /* Start keepalive timer */
                    uv_timer_start(&session->keepalive_timer, on_keepalive_timer,
                                  KEEPALIVE_INTERVAL * 1000, KEEPALIVE_INTERVAL * 1000);
                    
                    /* Start proxy instances */
                    log_info("Starting proxy instances");
                    int proxy_result = client_start_proxies(session);
                    if (proxy_result != SEED_OK) {
                        log_error("Failed to start proxy instances: %d", proxy_result);
                    }
                } else {
                    log_error("Authentication failed: %s", auth_resp->message);
                    session->state = CLIENT_STATE_ERROR;
                    if (session->on_error) {
                        session->on_error(session, SEED_ERROR_AUTH_FAILED);
                    }
                }
            }
            break;

        case MSG_TYPE_PROXY_RESPONSE:
            {
                struct msg_proxy_response *resp = &msg->payload.proxy_resp;
                log_info("Received proxy response for '%s': status=%d", 
                         resp->proxy_id, resp->status);
                
                if (resp->status == 0) {
                    log_info("Proxy '%s' setup successful on port %d", 
                             resp->proxy_id, resp->assigned_port);
                } else {
                    log_error("Proxy '%s' setup failed with status %d: %s", 
                             resp->proxy_id, resp->status, resp->message);
                }
            }
            break;

        case MSG_TYPE_KEEPALIVE:
            log_debug("Received keepalive from server");
            /* Server keepalive - no action needed */
            break;

        case MSG_TYPE_ERROR:
            log_error("Received error from server");
            session->state = CLIENT_STATE_ERROR;
            if (session->on_error) {
                session->on_error(session, SEED_ERROR_PROTOCOL);
            }
            break;

        case MSG_TYPE_DATA_FORWARD:
            {
                const struct msg_data *data_msg = &msg->payload.data;
                log_debug("Received DATA_FORWARD: proxy_id='%s' connection_id=%u data_length=%u",
                         data_msg->proxy_id, data_msg->connection_id, data_msg->data_length);
                
                /* Handle data forwarding to local service */
                if (handle_data_forward(session, data_msg, raw_buffer) != 0) {
                    log_error("Failed to forward data to local service");
                }
            }
            break;

        case MSG_TYPE_UDP_DATA:
            {
                const struct msg_udp_data *udp_msg = &msg->payload.udp_data;
                log_debug("Received UDP_DATA: proxy_id='%s' src=%u:%u dst_port=%u data_length=%u",
                         udp_msg->proxy_id, udp_msg->src_addr, udp_msg->src_port, 
                         udp_msg->dst_port, udp_msg->data_length);
                
                /* Handle UDP data forwarding to local service */
                if (handle_udp_data(session, udp_msg, raw_buffer) != 0) {
                    log_error("Failed to forward UDP data to local service");
                }
            }
            break;

        default:
            log_warning("Unknown message type: %d", msg->header.type);
            break;
    }

    return SEED_OK;
}

/**
 * @brief Write callback for DATA_BACKWARD messages
 */
static void on_data_backward_write(uv_write_t *req, int status)
{
    uint8_t *buffer = (uint8_t*)req->data;
    
    if (status < 0) {
        log_error("Failed to send DATA_BACKWARD message: %s", uv_strerror(status));
    } else {
        log_debug("DATA_BACKWARD message sent successfully");
    }
    
    free(buffer);
    free(req);
}

/**
 * @brief Send DATA_BACKWARD message with echo response
 */
static int send_echo_response(struct client_session *session, const struct msg_data *data_msg)
{
    if (!session || !data_msg) {
        return -1;
    }
    
    /* Create a simple echo response with the same data length */
    const char *echo_message = "Echo: Hello TCP Echo Test!";
    size_t echo_len = strlen(echo_message);
    
    /* Calculate total message size */
    size_t total_size = sizeof(struct protocol_header) + sizeof(struct msg_data) + echo_len;
    
    /* Allocate buffer for the complete message */
    uint8_t *buffer = malloc(total_size);
    if (!buffer) {
        log_error("Failed to allocate buffer for DATA_BACKWARD message");
        return -1;
    }
    
    /* Build protocol header */
    struct protocol_header header = {0};
    header.magic = PROTOCOL_MAGIC;
    header.version = PROTOCOL_VERSION;
    header.type = MSG_TYPE_DATA_BACKWARD;
    header.flags = 0;
    header.sequence = 0;
    header.length = sizeof(struct msg_data) + echo_len;
    header.checksum = 0;
    
    /* Calculate checksum */
    header.checksum = protocol_checksum(&header);
    
    /* Build data message */
    struct msg_data echo_data_msg = {0};
    strncpy(echo_data_msg.proxy_id, data_msg->proxy_id, sizeof(echo_data_msg.proxy_id) - 1);
    echo_data_msg.connection_id = data_msg->connection_id;
    echo_data_msg.data_length = echo_len;
    
    /* Copy header, data message, and payload to buffer */
    memcpy(buffer, &header, sizeof(struct protocol_header));
    memcpy(buffer + sizeof(struct protocol_header), &echo_data_msg, sizeof(struct msg_data));
    memcpy(buffer + sizeof(struct protocol_header) + sizeof(struct msg_data), echo_message, echo_len);
    
    /* Send using network send data */
    /* Send using uv_write directly like other client messages */
    uv_write_t *write_req = malloc(sizeof(*write_req));
    if (!write_req) {
        free(buffer);
        return -1;
    }
    
    uv_buf_t write_buf = uv_buf_init((char*)buffer, total_size);
    write_req->data = buffer; /* Store buffer for cleanup */
    
    int result = uv_write(write_req, (uv_stream_t*)&session->server_connection,
                         &write_buf, 1, on_data_backward_write);
    
    if (result == 0) {
        log_info("Queued DATA_BACKWARD echo response (%zu bytes) for connection %u", 
                 echo_len, data_msg->connection_id);
    } else {
        log_error("Failed to queue DATA_BACKWARD message: %s", uv_strerror(result));
        free(buffer);
        free(write_req);
    }
    
    /* Don't free buffer here - will be freed in callback */
    return result;
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
    msg.header.type = MSG_TYPE_KEEPALIVE;
    msg.header.sequence = 0;
    msg.header.length = 0;
    /* No payload for keepalive */

    /* Serialize and send */
    uint8_t buffer[256];
    int ret = protocol_serialize(&msg, buffer, sizeof(buffer));
    if (ret < 0) {
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

    uint8_t *data = malloc(ret);
    if (!data) {
        free(write_req);
        free(write_buf);
        return SEED_ERROR_OUT_OF_MEMORY;
    }

    memcpy(data, buffer, ret);
    write_buf->base = (char*)data;
    write_buf->len = ret;
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

    /* Set session data for callbacks */
    session->server_connection.data = session;

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
    protocol_init_message(&hello_msg, MSG_TYPE_HELLO);
    
    /* Fill hello payload */
    strncpy(hello_msg.payload.hello.client_id, "client_001", sizeof(hello_msg.payload.hello.client_id) - 1);
    hello_msg.payload.hello.protocol_version = PROTOCOL_VERSION;
    hello_msg.payload.hello.capabilities = 0;

    uint8_t buffer[256];
    ret = protocol_serialize(&hello_msg, buffer, sizeof(buffer));
    if (ret < 0) {
        log_error("Failed to serialize HELLO message");
        session->state = CLIENT_STATE_ERROR;
        if (session->on_error) {
            session->on_error(session, SEED_ERROR_PROTOCOL);
        }
        return;
    }
    size_t message_size = (size_t)ret;

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

    uint8_t *data = malloc(message_size);
    if (!data) {
        free(write_req);
        free(write_buf);
        return;
    }

    memcpy(data, buffer, message_size);
    write_buf->base = (char*)data;
    write_buf->len = (ULONG)message_size;
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
        session->state = CLIENT_STATE_CONNECTED;
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

    /* Debug: dump received data */
    log_debug("Received %zd bytes from server", nread);
    
    /* Check for multiple messages early */
    if (nread > 100) {
        log_debug("Large buffer received - likely multiple messages");
    }
    if (nread >= 4) {
        uint32_t *magic = (uint32_t*)buf->base;
        log_debug("First 4 bytes: 0x%08X (expected magic: 0x%08X)", *magic, PROTOCOL_MAGIC);
    }
    if (nread >= 24) {
        struct protocol_header *hdr = (struct protocol_header*)buf->base;
        log_debug("Header: magic=0x%08X version=%d type=%d length=%d", 
                  hdr->magic, hdr->version, hdr->type, hdr->length);
        
        /* Check if there might be multiple messages */
        size_t first_msg_size = 24 + hdr->length;
        log_debug("First message size: %zu, total received: %zd", first_msg_size, nread);
        if (nread > first_msg_size) {
            log_debug("Buffer contains multiple messages: received %zd, first message is %zu", 
                      nread, first_msg_size);
        }
    }

    /* Parse received messages - handle multiple messages in buffer */
    log_debug("Starting message parsing loop for %zd bytes", nread);
    size_t offset = 0;
    int message_count = 0;
    while (offset < (size_t)nread) {
        message_count++;
        log_debug("Processing message #%d at offset %zu", message_count, offset);
        
        struct protocol_message msg;
        int ret = protocol_deserialize(&msg, (const uint8_t*)buf->base + offset, nread - offset);
        if (ret > 0) {
            log_debug("Successfully parsed message #%d (%d bytes)", message_count, ret);
            client_handle_message(session, &msg, (const uint8_t*)buf->base + offset);
            offset += ret;
        } else {
            log_error("Failed to parse message #%d from server (ret=%d, offset=%zu)", 
                      message_count, ret, offset);
            break;
        }
    }
    log_debug("Processed %d messages from buffer", message_count);

    if (buf->base) {
        free(buf->base);
    }
}

static void on_server_write(uv_write_t *req, int status)
{
    uv_buf_t *write_buf = (uv_buf_t*)req->data;
    struct client_session *session = NULL;
    
    /* Get session from the stream */
    if (req->handle && req->handle->data) {
        session = (struct client_session*)req->handle->data;
    }
    
    if (status != 0) {
        log_error("Write error to server: %s", uv_strerror(status));
    } else if (session && write_buf && write_buf->base) {
        /* Check if this was a HELLO message by examining the message type */
        struct protocol_header *hdr = (struct protocol_header*)write_buf->base;
        if (hdr->magic == PROTOCOL_MAGIC && hdr->type == MSG_TYPE_HELLO) {
            log_debug("HELLO message write completed successfully");
            
            /* Set up authentication timer */
            log_debug("Setting up auth timer for username: '%s'", session->username);
            uv_timer_t *auth_timer = malloc(sizeof(*auth_timer));
            if (auth_timer) {
                uv_timer_init(session->network->loop, auth_timer);
                auth_timer->data = session;
                int timer_result = uv_timer_start(auth_timer, on_auth_timer, 100, 0);
                log_debug("Auth timer start result: %d", timer_result);
            } else {
                log_error("Failed to allocate auth timer");
            }
        }
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

static void on_auth_timer(uv_timer_t *timer)
{
    struct client_session *session = (struct client_session*)timer->data;
    
    log_debug("Authentication timer triggered for username: %s", session->username);
    log_debug("Client password from config: '%s'", session->password);
    
    /* Send authentication request */
    int auth_result = client_authenticate(session, session->username, session->password);
    log_debug("Authentication call result: %d", auth_result);
    
    /* Clean up timer */
    uv_close((uv_handle_t*)timer, (uv_close_cb)free);
}

static void on_server_close(uv_handle_t *handle)
{
    log_debug("Server connection closed");
}

/**
 * @brief Handle DATA_FORWARD message by connecting to local service
 */
static int handle_data_forward(struct client_session *session, const struct msg_data *data_msg, const uint8_t *raw_buffer)
{
    struct local_connection *conn = find_local_connection(session, data_msg->proxy_id, data_msg->connection_id);
    
    if (!conn) {
        /* Create new local connection */
        conn = create_local_connection(session, data_msg->proxy_id, data_msg->connection_id);
        if (!conn) {
            log_error("Failed to create local connection for proxy_id=%s connection_id=%u", 
                     data_msg->proxy_id, data_msg->connection_id);
            return SEED_ERROR_OUT_OF_MEMORY;
        }
    }
    
    /* Forward data to local service */
    if (conn->active) {
        uv_write_t *write_req = malloc(sizeof(*write_req));
        if (!write_req) {
            return SEED_ERROR_OUT_OF_MEMORY;
        }
        
        uv_buf_t *write_buf = malloc(sizeof(*write_buf));
        if (!write_buf) {
            free(write_req);
            return SEED_ERROR_OUT_OF_MEMORY;
        }
        
        uint8_t *data = malloc(data_msg->data_length);
        if (!data) {
            free(write_req);
            free(write_buf);
            return SEED_ERROR_OUT_OF_MEMORY;
        }
        
        /* Extract data from raw buffer - data follows after header + msg_data structure */
        size_t data_offset = sizeof(struct protocol_header) + sizeof(struct msg_data);
        const uint8_t *actual_data = raw_buffer + data_offset;
        memcpy(data, actual_data, data_msg->data_length);
        write_buf->base = (char*)data;
        write_buf->len = data_msg->data_length;
        
        write_req->data = write_buf;
        
        int ret = uv_write(write_req, (uv_stream_t*)&conn->tcp_handle, write_buf, 1, on_local_write);
        
        if (ret < 0) {
            free(data);
            free(write_buf);
            free(write_req);
            log_error("Failed to write to local connection: %s", uv_strerror(ret));
            return SEED_ERROR_NETWORK;
        }
        
        log_debug("Forwarded %u bytes to local service", data_msg->data_length);
    } else {
        log_warning("Local connection not active for proxy_id=%s connection_id=%u", 
                   data_msg->proxy_id, data_msg->connection_id);
    }
    
    return SEED_OK;
}

/**
 * @brief Handle UDP data from server and forward to local service
 */
static int handle_udp_data(struct client_session *session, const struct msg_udp_data *udp_msg, const uint8_t *raw_buffer)
{
    /* Find the proxy instance */
    struct proxy_instance *proxy = NULL;
    for (int i = 0; i < session->proxy_count; i++) {
        if (strncmp(session->proxies[i].name, udp_msg->proxy_id, strlen(session->proxies[i].name)) == 0) {
            proxy = &session->proxies[i];
            break;
        }
    }
    
    if (!proxy || proxy->type != PROXY_TYPE_UDP) {
        log_error("UDP proxy not found for proxy_id='%s'", udp_msg->proxy_id);
        return SEED_ERROR_FILE_NOT_FOUND;
    }
    
    /* Create UDP socket if not exists */
    static uv_udp_t udp_socket;
    static bool udp_initialized = false;
    
    if (!udp_initialized) {
        int ret = uv_udp_init(session->network->loop, &udp_socket);
        if (ret != 0) {
            log_error("Failed to initialize UDP socket: %s", uv_strerror(ret));
            return SEED_ERROR_NETWORK;
        }
        udp_initialized = true;
    }
    
    /* Forward UDP data to local service */
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(proxy->local_port);
    
    /* Parse local address */
    int ret = uv_ip4_addr(proxy->local_addr, proxy->local_port, &dest_addr);
    if (ret != 0) {
        log_error("Invalid local address %s:%u", proxy->local_addr, proxy->local_port);
        return SEED_ERROR_INVALID_ARGS;
    }
    
    /* Extract UDP data from raw buffer */
    size_t data_offset = sizeof(struct protocol_header) + sizeof(struct msg_udp_data);
    const uint8_t *udp_data = raw_buffer + data_offset;
    
    /* Allocate send request */
    uv_udp_send_t *send_req = malloc(sizeof(*send_req));
    if (!send_req) {
        return SEED_ERROR_OUT_OF_MEMORY;
    }
    
    /* Copy data for send */
    uint8_t *send_data = malloc(udp_msg->data_length);
    if (!send_data) {
        free(send_req);
        return SEED_ERROR_OUT_OF_MEMORY;
    }
    
    memcpy(send_data, udp_data, udp_msg->data_length);
    
    uv_buf_t send_buf = uv_buf_init((char*)send_data, udp_msg->data_length);
    
    /* Send UDP packet to local service */
    ret = uv_udp_send(send_req, &udp_socket, &send_buf, 1, 
                     (const struct sockaddr*)&dest_addr, NULL);
    
    if (ret != 0) {
        free(send_data);
        free(send_req);
        log_error("Failed to send UDP packet: %s", uv_strerror(ret));
        return SEED_ERROR_NETWORK;
    }
    
    log_debug("Forwarded UDP packet (%u bytes) to %s:%u", 
             udp_msg->data_length, proxy->local_addr, proxy->local_port);
    
    return SEED_OK;
}

/**
 * @brief Find existing local connection
 */
static struct local_connection *find_local_connection(struct client_session *session, 
                                                     const char *proxy_id, uint32_t connection_id)
{
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        struct local_connection *conn = &session->local_connections[i];
        if (conn->active && conn->connection_id == connection_id && 
            strcmp(conn->proxy_id, proxy_id) == 0) {
            return conn;
        }
    }
    return NULL;
}

/**
 * @brief Create new local connection
 */
static struct local_connection *create_local_connection(struct client_session *session, 
                                                       const char *proxy_id, uint32_t connection_id)
{
    /* Find empty slot */
    struct local_connection *conn = NULL;
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (!session->local_connections[i].active) {
            conn = &session->local_connections[i];
            break;
        }
    }
    
    if (!conn) {
        log_error("No available slots for local connections");
        return NULL;
    }
    
    /* Initialize connection */
    conn->connection_id = connection_id;
    strncpy(conn->proxy_id, proxy_id, sizeof(conn->proxy_id) - 1);
    conn->proxy_id[sizeof(conn->proxy_id) - 1] = '\0';
    conn->session = session;
    conn->active = false;
    
    /* Initialize TCP handle */
    int ret = uv_tcp_init(session->network->loop, &conn->tcp_handle);
    if (ret < 0) {
        log_error("Failed to init TCP handle: %s", uv_strerror(ret));
        return NULL;
    }
    
    conn->tcp_handle.data = conn;
    
    /* Find proxy configuration by matching prefix */
    struct proxy_instance *proxy = NULL;
    for (int i = 0; i < session->proxy_count; i++) {
        char expected_prefix[128];
        snprintf(expected_prefix, sizeof(expected_prefix), "client_001_%s", session->proxies[i].name);
        
        /* Check if proxy_id starts with expected prefix */
        if (strncmp(proxy_id, expected_prefix, strlen(expected_prefix)) == 0) {
            proxy = &session->proxies[i];
            break;
        }
    }
    
    if (!proxy) {
        log_error("Proxy configuration not found for proxy_id: %s", proxy_id);
        return NULL;
    }
    
    /* Connect to local service */
    struct sockaddr_in local_addr;
    uv_ip4_addr(proxy->local_addr, proxy->local_port, &local_addr);
    
    uv_connect_t *connect_req = malloc(sizeof(*connect_req));
    if (!connect_req) {
        return NULL;
    }
    
    connect_req->data = conn;
    
    ret = uv_tcp_connect(connect_req, &conn->tcp_handle, (const struct sockaddr*)&local_addr, on_local_connect);
    if (ret < 0) {
        log_error("Failed to connect to local service %s:%u: %s", 
                 proxy->local_addr, proxy->local_port, uv_strerror(ret));
        free(connect_req);
        return NULL;
    }
    
    log_info("Connecting to local service %s:%u for proxy_id=%s connection_id=%u", 
             proxy->local_addr, proxy->local_port, proxy_id, connection_id);
    
    return conn;
}

/**
 * @brief Local connection callback
 */
static void on_local_connect(uv_connect_t *req, int status)
{
    struct local_connection *conn = (struct local_connection*)req->data;
    free(req);
    
    if (status < 0) {
        log_error("Local connection failed: %s", uv_strerror(status));
        conn->active = false;
        return;
    }
    
    conn->active = true;
    conn->session->active_local_connections++;
    
    /* Start reading from local service */
    int ret = uv_read_start((uv_stream_t*)&conn->tcp_handle, on_local_alloc, on_local_read);
    if (ret < 0) {
        log_error("Failed to start reading from local connection: %s", uv_strerror(ret));
        conn->active = false;
        conn->session->active_local_connections--;
    } else {
        log_info("Local connection established for proxy_id=%s connection_id=%u", 
                 conn->proxy_id, conn->connection_id);
    }
}

/**
 * @brief Local connection read callback
 */
static void on_local_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    struct local_connection *conn = (struct local_connection*)stream->data;
    
    if (nread < 0) {
        if (nread != UV_EOF) {
            log_error("Local read error: %s", uv_strerror(nread));
        } else {
            log_debug("Local connection closed for proxy_id=%s connection_id=%u", 
                     conn->proxy_id, conn->connection_id);
        }
        
        conn->active = false;
        conn->session->active_local_connections--;
        uv_close((uv_handle_t*)&conn->tcp_handle, NULL);
        
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
    
    /* Send DATA_BACKWARD message to server */
    log_debug("Received %zd bytes from local service, sending to server", nread);
    
    /* Build DATA_BACKWARD message */
    struct protocol_message response;
    protocol_init_message(&response, MSG_TYPE_DATA_BACKWARD);
    
    strncpy(response.payload.data.proxy_id, conn->proxy_id, sizeof(response.payload.data.proxy_id) - 1);
    response.payload.data.connection_id = conn->connection_id;
    response.payload.data.data_length = (uint32_t)nread;
    
    /* Calculate total message size */
    size_t header_size = sizeof(struct protocol_header);
    size_t msg_data_size = sizeof(struct msg_data) - sizeof(uint8_t*);  /* Exclude data pointer */
    size_t total_size = header_size + msg_data_size + nread;
    
    uint8_t *message_buffer = malloc(total_size);
    if (!message_buffer) {
        log_error("Failed to allocate message buffer");
        free(buf->base);
        return;
    }
    
    /* Serialize header */
    struct protocol_header header = {0};
    header.magic = PROTOCOL_MAGIC;
    header.version = PROTOCOL_VERSION;
    header.type = MSG_TYPE_DATA_BACKWARD;
    header.length = (uint32_t)(msg_data_size + nread);
    header.checksum = protocol_checksum(&header);
    
    memcpy(message_buffer, &header, header_size);
    
    /* Serialize msg_data structure */
    memcpy(message_buffer + header_size, &response.payload.data, msg_data_size);
    
    /* Copy actual data */
    memcpy(message_buffer + header_size + msg_data_size, buf->base, nread);
    
    /* Send to server */
    uv_write_t *write_req = malloc(sizeof(*write_req));
    if (!write_req) {
        free(message_buffer);
        free(buf->base);
        return;
    }
    
    uv_buf_t *write_buf = malloc(sizeof(*write_buf));
    if (!write_buf) {
        free(write_req);
        free(message_buffer);
        free(buf->base);
        return;
    }
    
    write_buf->base = (char*)message_buffer;
    write_buf->len = total_size;
    write_req->data = write_buf;
    
    int ret = uv_write(write_req, (uv_stream_t*)&conn->session->server_connection, 
                      write_buf, 1, on_data_backward_write);
    if (ret < 0) {
        log_error("Failed to send DATA_BACKWARD: %s", uv_strerror(ret));
        free(write_buf->base);
        free(write_buf);
        free(write_req);
    } else {
        log_debug("Sent DATA_BACKWARD message with %zd bytes", nread);
    }
    
    free(buf->base);
}

/**
 * @brief Buffer allocation for local connections
 */
static void on_local_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    buf->base = malloc(suggested_size);
    buf->len = buf->base ? suggested_size : 0;
}

/**
 * @brief Write callback for local connections
 */
static void on_local_write(uv_write_t *req, int status)
{
    uv_buf_t *buf = (uv_buf_t*)req->data;
    free(buf->base);
    free(buf);
    free(req);
    if (status < 0) {
        log_error("Local write failed: %s", uv_strerror(status));
    }
}