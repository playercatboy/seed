/**
 * @file server.c
 * @brief Server mode implementation for Seed reverse proxy
 * @author Seed Development Team
 * @date 2025
 */

#include "server.h"
#include "log.h"
#include <signal.h>
#include <time.h>

/** Global server context for signal handling */
static struct server_context *g_server_ctx = NULL;

/**
 * @brief Signal handler for graceful shutdown
 *
 * @param[in] sig  Signal number
 */
static void signal_handler(int sig)
{
    (void)sig; /* Unused */
    
    log_info("Received shutdown signal, stopping server...");
    
    if (g_server_ctx) {
        server_stop(g_server_ctx);
    }
}

/**
 * @brief Generate unique proxy ID
 *
 * @param[out] proxy_id   Buffer to store proxy ID
 * @param[in]  buflen     Buffer length
 * @param[in]  client_id  Client ID
 * @param[in]  proxy_name Proxy name
 */
static void generate_proxy_id(char *proxy_id, size_t buflen, const char *client_id, const char *proxy_name)
{
    static uint32_t counter = 0;
    counter++;
    
    snprintf(proxy_id, buflen, "%s_%s_%u", client_id, proxy_name, counter);
}

/**
 * @brief Handle authentication request
 *
 * @param[in,out] ctx      Server context
 * @param[in,out] client   Client session
 * @param[in]     auth_req Authentication request
 */
static void handle_auth_request(struct server_context *ctx, struct server_client_session *client, 
                               const struct msg_auth_request *auth_req)
{
    struct protocol_message response;
    int auth_result;
    
    log_info("Authentication request from %s: username='%s'", 
             network_connection_info(client->conn, NULL, 0), auth_req->username);
    
    client->state = CLIENT_STATE_AUTHENTICATING;
    
    /* Authenticate user */
    auth_result = auth_db_authenticate(&ctx->auth, auth_req->username, auth_req->password);
    
    /* Prepare response */
    protocol_init_message(&response, MSG_TYPE_AUTH_RESPONSE);
    
    if (auth_result == SEED_OK) {
        /* Authentication successful */
        client->state = CLIENT_STATE_AUTHENTICATED;
        client->auth_time = time(NULL);
        strncpy(client->username, auth_req->username, sizeof(client->username) - 1);
        
        response.payload.auth_resp.status = 0;
        strncpy(response.payload.auth_resp.message, "Authentication successful", 
                sizeof(response.payload.auth_resp.message) - 1);
        strncpy(response.payload.auth_resp.session_token, "session_token_placeholder",
                sizeof(response.payload.auth_resp.session_token) - 1);
        
        log_info("Client %s authenticated as '%s'", 
                 network_connection_info(client->conn, NULL, 0), client->username);
    } else {
        /* Authentication failed */
        client->state = CLIENT_STATE_ERROR;
        
        response.payload.auth_resp.status = 1;
        strncpy(response.payload.auth_resp.message, "Authentication failed", 
                sizeof(response.payload.auth_resp.message) - 1);
        
        log_warning("Authentication failed for %s: username='%s'", 
                    network_connection_info(client->conn, NULL, 0), auth_req->username);
    }
    
    /* Send response */
    network_send_message(client->conn, &response);
    
    /* Close connection if authentication failed */
    if (auth_result != SEED_OK) {
        network_close_connection(client->conn);
    }
}

/**
 * @brief Handle proxy request
 *
 * @param[in,out] ctx         Server context
 * @param[in,out] client      Client session
 * @param[in]     proxy_req   Proxy request
 */
static void handle_proxy_request(struct server_context *ctx, struct server_client_session *client, 
                                const struct msg_proxy_request *proxy_req)
{
    struct protocol_message response;
    int result;
    
    log_info("Proxy request from %s: name='%s' type=%s local=%s:%d remote=%d", 
             network_connection_info(client->conn, NULL, 0),
             proxy_req->proxy_name,
             proxy_req->proxy_type == PROXY_TYPE_TCP ? "TCP" : "UDP",
             proxy_req->local_addr,
             proxy_req->local_port,
             proxy_req->remote_port);
    
    /* Prepare response */
    protocol_init_message(&response, MSG_TYPE_PROXY_RESPONSE);
    
    /* Check if client is authenticated */
    if (client->state != CLIENT_STATE_AUTHENTICATED) {
        response.payload.proxy_resp.status = 1;
        strncpy(response.payload.proxy_resp.message, "Not authenticated", 
                sizeof(response.payload.proxy_resp.message) - 1);
        network_send_message(client->conn, &response);
        return;
    }
    
    /* Create proxy mapping */
    result = server_create_proxy_mapping(ctx, client, proxy_req);
    
    if (result == SEED_OK) {
        /* Success */
        response.payload.proxy_resp.status = 0;
        generate_proxy_id(response.payload.proxy_resp.proxy_id, 
                         sizeof(response.payload.proxy_resp.proxy_id),
                         client->client_id, proxy_req->proxy_name);
        response.payload.proxy_resp.assigned_port = proxy_req->remote_port;
        strncpy(response.payload.proxy_resp.message, "Proxy created successfully", 
                sizeof(response.payload.proxy_resp.message) - 1);
        
        log_info("Created proxy mapping: %s -> %s:%d", 
                 response.payload.proxy_resp.proxy_id,
                 proxy_req->local_addr, proxy_req->local_port);
    } else {
        /* Failed */
        response.payload.proxy_resp.status = 1;
        response.payload.proxy_resp.assigned_port = 0;
        strncpy(response.payload.proxy_resp.message, "Failed to create proxy", 
                sizeof(response.payload.proxy_resp.message) - 1);
        
        log_error("Failed to create proxy mapping for %s", proxy_req->proxy_name);
    }
    
    /* Send response */
    network_send_message(client->conn, &response);
}

/**
 * @brief Handle hello message
 *
 * @param[in,out] ctx     Server context
 * @param[in,out] client  Client session
 * @param[in]     hello   Hello message
 */
static void handle_hello(struct server_context *ctx, struct server_client_session *client, 
                        const struct msg_hello *hello)
{
    (void)ctx; /* Unused */
    
    log_info("Hello from %s: client_id='%s' version=%u capabilities=0x%08x", 
             network_connection_info(client->conn, NULL, 0),
             hello->client_id, hello->protocol_version, hello->capabilities);
    
    /* Store client ID */
    strncpy(client->client_id, hello->client_id, sizeof(client->client_id) - 1);
    
    /* Send hello response - for now just send back a keepalive */
    struct protocol_message response;
    protocol_init_message(&response, MSG_TYPE_KEEPALIVE);
    network_send_message(client->conn, &response);
}

/**
 * @brief Handle keepalive message
 *
 * @param[in,out] ctx     Server context
 * @param[in,out] client  Client session
 */
static void handle_keepalive(struct server_context *ctx, struct server_client_session *client)
{
    (void)ctx; /* Unused */
    
    log_debug("Keepalive from %s", network_connection_info(client->conn, NULL, 0));
    
    /* Send keepalive response */
    struct protocol_message response;
    protocol_init_message(&response, MSG_TYPE_KEEPALIVE);
    network_send_message(client->conn, &response);
}

/**
 * @brief Network callback for new connections
 */
static void on_new_connection(struct connection *conn, int status)
{
    struct server_context *ctx = (struct server_context *)conn->ctx->user_data;
    
    if (status < 0) {
        log_error("New connection failed: %s", uv_strerror(status));
        return;
    }
    
    server_handle_new_connection(ctx, conn);
}

/**
 * @brief Network callback for messages
 */
static void on_message(struct connection *conn, const struct protocol_message *msg)
{
    struct server_context *ctx = (struct server_context *)conn->ctx->user_data;
    server_handle_message(ctx, conn, msg);
}

/**
 * @brief Network callback for connection close
 */
static void on_connection_closed(struct connection *conn)
{
    struct server_context *ctx = (struct server_context *)conn->ctx->user_data;
    server_handle_disconnection(ctx, conn);
}

/**
 * @brief Initialize server context
 *
 * @param[out] ctx     Server context to initialize
 * @param[in]  config  Configuration
 *
 * @return 0 on success, negative error code on failure
 */
int server_init(struct server_context *ctx, struct seed_config *config)
{
    int result;
    
    if (!ctx || !config) {
        return SEED_ERROR_INVALID_ARGS;
    }
    
    memset(ctx, 0, sizeof(struct server_context));
    
    ctx->config = config;
    ctx->running = false;
    ctx->active_clients = 0;
    ctx->active_mappings = 0;
    
    /* Initialize network */
    result = network_init(&ctx->network, NULL);
    if (result != SEED_OK) {
        log_error("Failed to initialize network");
        return result;
    }
    
    /* Set up network callbacks */
    ctx->network.user_data = ctx;
    ctx->network.on_new_connection = on_new_connection;
    ctx->network.on_message = on_message;
    ctx->network.on_connection_closed = on_connection_closed;
    
    /* Load authentication database */
    result = auth_db_load(config->server.auth_file, &ctx->auth);
    if (result != SEED_OK) {
        log_error("Failed to load authentication database");
        network_cleanup(&ctx->network);
        return result;
    }
    
    /* Initialize client sessions */
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        ctx->clients[i].state = CLIENT_STATE_DISCONNECTED;
        ctx->clients[i].conn = NULL;
        ctx->clients[i].mapping_count = 0;
    }
    
    /* Initialize proxy mappings */
    for (int i = 0; i < MAX_PROXY_MAPPINGS; i++) {
        ctx->mappings[i].active = false;
    }
    
    log_info("Server initialized");
    
    return SEED_OK;
}

/**
 * @brief Start server
 *
 * @param[in,out] ctx  Server context
 *
 * @return 0 on success, negative error code on failure
 */
int server_start(struct server_context *ctx)
{
    int result;
    
    if (!ctx) {
        return SEED_ERROR_INVALID_ARGS;
    }
    
    /* Install signal handlers */
    g_server_ctx = ctx;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN); /* Ignore broken pipe signals */
#endif
    
    /* Start network server */
    result = network_start_server(&ctx->network, 
                                 ctx->config->server.bind_addr,
                                 ctx->config->server.bind_port);
    if (result != SEED_OK) {
        log_error("Failed to start network server");
        return result;
    }
    
    ctx->running = true;
    ctx->start_time = time(NULL);
    
    log_info("Seed server started on %s:%d", 
             ctx->config->server.bind_addr, 
             ctx->config->server.bind_port);
    
    return SEED_OK;
}

/**
 * @brief Stop server
 *
 * @param[in,out] ctx  Server context
 */
void server_stop(struct server_context *ctx)
{
    if (!ctx || !ctx->running) {
        return;
    }
    
    log_info("Stopping server...");
    
    ctx->running = false;
    
    /* Stop network */
    network_stop(&ctx->network);
    
    /* TODO: Clean up proxy mappings */
    
    log_info("Server stopped");
}

/**
 * @brief Run server main loop
 *
 * @param[in,out] ctx  Server context
 *
 * @return Exit code
 */
int server_run(struct server_context *ctx)
{
    if (!ctx) {
        return EXIT_FAILURE;
    }
    
    log_info("Server running... Press Ctrl+C to stop");
    
    /* Run network event loop */
    int result = network_run(&ctx->network);
    
    log_info("Server event loop finished with result: %d", result);
    
    return (result == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/**
 * @brief Cleanup server context
 *
 * @param[in,out] ctx  Server context to cleanup
 */
void server_cleanup(struct server_context *ctx)
{
    if (!ctx) return;
    
    /* Stop server if still running */
    if (ctx->running) {
        server_stop(ctx);
    }
    
    /* Cleanup network */
    network_cleanup(&ctx->network);
    
    /* Cleanup authentication database */
    auth_db_free(&ctx->auth);
    
    /* Reset signal handlers */
    signal(SIGINT, SIG_DFL);
    signal(SIGTERM, SIG_DFL);
    
    g_server_ctx = NULL;
    
    log_info("Server cleanup completed");
    
    memset(ctx, 0, sizeof(struct server_context));
}

/**
 * @brief Handle new client connection
 *
 * @param[in,out] ctx   Server context
 * @param[in]     conn  New connection
 */
void server_handle_new_connection(struct server_context *ctx, struct connection *conn)
{
    struct server_client_session *client = NULL;
    
    if (!ctx || !conn) return;
    
    /* Find available client session slot */
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (ctx->clients[i].state == CLIENT_STATE_DISCONNECTED) {
            client = &ctx->clients[i];
            break;
        }
    }
    
    if (!client) {
        log_warning("No available client session slots, rejecting connection");
        network_close_connection(conn);
        return;
    }
    
    /* Initialize client session */
    memset(client, 0, sizeof(struct server_client_session));
    client->conn = conn;
    client->state = CLIENT_STATE_CONNECTED;
    client->connect_time = time(NULL);
    client->mapping_count = 0;
    
    /* Set up connection callbacks */
    conn->on_message = on_message;
    conn->on_close = on_connection_closed;
    
    ctx->active_clients++;
    
    log_info("New client connected: %s (total: %d)", 
             network_connection_info(conn, NULL, 0), ctx->active_clients);
}

/**
 * @brief Handle client message
 *
 * @param[in,out] ctx   Server context
 * @param[in]     conn  Client connection
 * @param[in]     msg   Received message
 */
void server_handle_message(struct server_context *ctx, struct connection *conn, 
                          const struct protocol_message *msg)
{
    struct server_client_session *client;
    
    if (!ctx || !conn || !msg) return;
    
    /* Find client session */
    client = server_find_client(ctx, conn);
    if (!client) {
        log_error("Received message from unknown client");
        network_close_connection(conn);
        return;
    }
    
    log_debug("Received %s message from %s", 
              protocol_type_name((enum message_type)msg->header.type),
              network_connection_info(conn, NULL, 0));
    
    /* Handle message based on type */
    switch (msg->header.type) {
    case MSG_TYPE_HELLO:
        handle_hello(ctx, client, &msg->payload.hello);
        break;
        
    case MSG_TYPE_AUTH_REQUEST:
        handle_auth_request(ctx, client, &msg->payload.auth_req);
        break;
        
    case MSG_TYPE_PROXY_REQUEST:
        handle_proxy_request(ctx, client, &msg->payload.proxy_req);
        break;
        
    case MSG_TYPE_KEEPALIVE:
        handle_keepalive(ctx, client);
        break;
        
    case MSG_TYPE_DATA_FORWARD:
        /* TODO: Handle data forwarding */
        log_debug("Data forward message (not yet implemented)");
        break;
        
    default:
        log_warning("Unhandled message type: %s", 
                   protocol_type_name((enum message_type)msg->header.type));
        break;
    }
}

/**
 * @brief Handle client disconnection
 *
 * @param[in,out] ctx   Server context
 * @param[in]     conn  Disconnected connection
 */
void server_handle_disconnection(struct server_context *ctx, struct connection *conn)
{
    struct server_client_session *client;
    
    if (!ctx || !conn) return;
    
    /* Find client session */
    client = server_find_client(ctx, conn);
    if (!client) {
        return; /* Client not found, nothing to clean up */
    }
    
    log_info("Client disconnected: %s (was: %s)", 
             network_connection_info(conn, NULL, 0),
             client->username[0] ? client->username : "unauthenticated");
    
    /* TODO: Clean up proxy mappings for this client */
    
    /* Reset client session */
    memset(client, 0, sizeof(struct server_client_session));
    client->state = CLIENT_STATE_DISCONNECTED;
    
    ctx->active_clients--;
    
    log_debug("Active clients: %d", ctx->active_clients);
}

/**
 * @brief Find client session by connection
 *
 * @param[in] ctx   Server context
 * @param[in] conn  Connection to find
 *
 * @return Client session pointer, or NULL if not found
 */
struct server_client_session *server_find_client(struct server_context *ctx, struct connection *conn)
{
    if (!ctx || !conn) return NULL;
    
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (ctx->clients[i].conn == conn) {
            return &ctx->clients[i];
        }
    }
    
    return NULL;
}

/**
 * @brief Create proxy mapping
 *
 * @param[in,out] ctx      Server context
 * @param[in]     client   Client session
 * @param[in]     request  Proxy request
 *
 * @return 0 on success, negative error code on failure
 */
int server_create_proxy_mapping(struct server_context *ctx, struct server_client_session *client,
                               const struct msg_proxy_request *request)
{
    struct proxy_mapping *mapping = NULL;
    
    if (!ctx || !client || !request) {
        return SEED_ERROR_INVALID_ARGS;
    }
    
    /* Find available mapping slot */
    for (int i = 0; i < MAX_PROXY_MAPPINGS; i++) {
        if (!ctx->mappings[i].active) {
            mapping = &ctx->mappings[i];
            break;
        }
    }
    
    if (!mapping) {
        log_error("No available proxy mapping slots");
        return SEED_ERROR_OUT_OF_MEMORY;
    }
    
    /* Initialize mapping */
    memset(mapping, 0, sizeof(struct proxy_mapping));
    generate_proxy_id(mapping->proxy_id, sizeof(mapping->proxy_id),
                     client->client_id, request->proxy_name);
    strncpy(mapping->client_id, client->client_id, sizeof(mapping->client_id) - 1);
    mapping->client_conn = client->conn;
    mapping->type = (enum proxy_type)request->proxy_type;
    mapping->remote_port = request->remote_port;
    strncpy(mapping->local_addr, request->local_addr, sizeof(mapping->local_addr) - 1);
    mapping->local_port = request->local_port;
    mapping->encryption = (enum encrypt_impl)request->encrypt_type;
    mapping->active = true;
    mapping->created_time = time(NULL);
    
    /* TODO: Set up server-side listening socket */
    /* For now, just mark as active */
    
    ctx->active_mappings++;
    
    /* Add to client's mapping list */
    if (client->mapping_count < MAX_PROXY_INSTANCES) {
        client->mappings[client->mapping_count] = mapping;
        client->mapping_count++;
    }
    
    log_info("Created proxy mapping: %s (%s %s:%d -> server:%d)", 
             mapping->proxy_id,
             mapping->type == PROXY_TYPE_TCP ? "TCP" : "UDP",
             mapping->local_addr, mapping->local_port,
             mapping->remote_port);
    
    return SEED_OK;
}

/**
 * @brief Destroy proxy mapping
 *
 * @param[in,out] ctx       Server context
 * @param[in]     proxy_id  Proxy ID to destroy
 *
 * @return 0 on success, negative error code on failure
 */
int server_destroy_proxy_mapping(struct server_context *ctx, const char *proxy_id)
{
    if (!ctx || !proxy_id) {
        return SEED_ERROR_INVALID_ARGS;
    }
    
    /* Find mapping */
    for (int i = 0; i < MAX_PROXY_MAPPINGS; i++) {
        if (ctx->mappings[i].active && 
            strcmp(ctx->mappings[i].proxy_id, proxy_id) == 0) {
            
            log_info("Destroying proxy mapping: %s", proxy_id);
            
            /* TODO: Close server-side listening socket */
            
            /* Reset mapping */
            memset(&ctx->mappings[i], 0, sizeof(struct proxy_mapping));
            ctx->active_mappings--;
            
            return SEED_OK;
        }
    }
    
    return SEED_ERROR; /* Not found */
}

/**
 * @brief Print server statistics
 *
 * @param[in] ctx  Server context
 */
void server_print_statistics(const struct server_context *ctx)
{
    if (!ctx) return;
    
    time_t uptime = time(NULL) - ctx->start_time;
    
    printf("\n=== Seed Server Statistics ===\n");
    printf("Uptime: %ld seconds\n", (long)uptime);
    printf("Active Clients: %d\n", ctx->active_clients);
    printf("Active Mappings: %d\n", ctx->active_mappings);
    printf("==============================\n");
}