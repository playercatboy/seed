/**
 * @file udp_proxy.c
 * @brief UDP proxy implementation for Seed reverse proxy
 * @author Seed Development Team
 * @date 2025
 */

#include "udp_proxy.h"
#include "log.h"
#include <uv.h>

/**
 * @brief Receive callback for client packets
 */
static void on_client_recv(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                          const struct sockaddr *addr, unsigned flags);

/**
 * @brief Receive callback for target packets
 */
static void on_target_recv(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                          const struct sockaddr *addr, unsigned flags);

/**
 * @brief Allocate callback for UDP operations
 */
static void on_udp_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);

/**
 * @brief Send callback for UDP operations
 */
static void on_udp_send(uv_udp_send_t *req, int status);

/**
 * @brief Session timeout callback
 */
static void on_session_timeout(uv_timer_t *timer);

/**
 * @brief Cleanup timer callback
 */
static void on_cleanup_timer(uv_timer_t *timer);

/**
 * @brief Close callback for UDP handles
 */
static void on_udp_close(uv_handle_t *handle);

/**
 * @brief Add session to proxy's session list
 */
static void add_session(struct udp_proxy *proxy, struct udp_session *session);

/**
 * @brief Remove session from proxy's session list
 */
static void remove_session(struct udp_proxy *proxy, struct udp_session *session);

/**
 * @brief Find session by client address
 */
static struct udp_session* find_session_by_client(struct udp_proxy *proxy, 
                                                 const struct sockaddr_in *client_addr);

/**
 * @brief Forward UDP packet
 */
static int forward_udp_packet(uv_udp_t *socket, const uint8_t *data, size_t size,
                             const struct sockaddr *dest_addr);

/**
 * @brief Compare socket addresses
 */
static int sockaddr_in_compare(const struct sockaddr_in *a, const struct sockaddr_in *b);

int udp_proxy_init(struct udp_proxy *proxy, struct network_context *network,
                  const char *name, const char *bind_addr, uint16_t bind_port,
                  const char *target_addr, uint16_t target_port, bool encrypt)
{
    if (!proxy || !network || !name || !bind_addr || !target_addr) {
        log_error("Invalid arguments to udp_proxy_init");
        return SEED_ERROR_INVALID_ARGS;
    }

    /* Initialize proxy structure */
    memset(proxy, 0, sizeof(*proxy));
    proxy->network = network;
    proxy->encrypt = encrypt;
    proxy->sessions = NULL;
    proxy->session_count = 0;
    proxy->total_sessions = 0;
    proxy->active_sessions = 0;
    proxy->total_packets_forwarded = 0;
    proxy->total_bytes_forwarded = 0;

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

    /* Initialize server socket */
    ret = uv_udp_init(network->loop, &proxy->server_socket);
    if (ret != 0) {
        log_error("Failed to initialize UDP server socket: %s", uv_strerror(ret));
        return SEED_ERROR_NETWORK;
    }

    proxy->server_socket.data = proxy;

    /* Initialize cleanup timer */
    ret = uv_timer_init(network->loop, &proxy->cleanup_timer);
    if (ret != 0) {
        log_error("Failed to initialize cleanup timer: %s", uv_strerror(ret));
        uv_close((uv_handle_t*)&proxy->server_socket, NULL);
        return SEED_ERROR_NETWORK;
    }

    proxy->cleanup_timer.data = proxy;

    log_info("UDP proxy '%s' initialized: %s:%d -> %s:%d (encrypt=%s)",
             name, bind_addr, bind_port, target_addr, target_port,
             encrypt ? "yes" : "no");

    return SEED_OK;
}

int udp_proxy_start(struct udp_proxy *proxy)
{
    if (!proxy) {
        log_error("Invalid arguments to udp_proxy_start");
        return SEED_ERROR_INVALID_ARGS;
    }

    /* Bind to address */
    int ret = uv_udp_bind(&proxy->server_socket, 
                         (const struct sockaddr*)&proxy->bind_addr, 0);
    if (ret != 0) {
        log_error("Failed to bind UDP proxy '%s': %s", proxy->name, uv_strerror(ret));
        return SEED_ERROR_NETWORK;
    }

    /* Start receiving packets */
    ret = uv_udp_recv_start(&proxy->server_socket, on_udp_alloc, on_client_recv);
    if (ret != 0) {
        log_error("Failed to start receiving on UDP proxy '%s': %s", proxy->name, uv_strerror(ret));
        return SEED_ERROR_NETWORK;
    }

    /* Start cleanup timer (runs every 60 seconds) */
    ret = uv_timer_start(&proxy->cleanup_timer, on_cleanup_timer, 60000, 60000);
    if (ret != 0) {
        log_error("Failed to start cleanup timer: %s", uv_strerror(ret));
        return SEED_ERROR_NETWORK;
    }

    log_info("UDP proxy '%s' started and listening", proxy->name);
    return SEED_OK;
}

int udp_proxy_stop(struct udp_proxy *proxy)
{
    if (!proxy) {
        log_error("Invalid arguments to udp_proxy_stop");
        return SEED_ERROR_INVALID_ARGS;
    }

    log_info("Stopping UDP proxy '%s'", proxy->name);

    /* Stop cleanup timer */
    if (!uv_is_closing((uv_handle_t*)&proxy->cleanup_timer)) {
        uv_timer_stop(&proxy->cleanup_timer);
        uv_close((uv_handle_t*)&proxy->cleanup_timer, NULL);
    }

    /* Stop receiving packets */
    uv_udp_recv_stop(&proxy->server_socket);

    /* Close server socket */
    if (!uv_is_closing((uv_handle_t*)&proxy->server_socket)) {
        uv_close((uv_handle_t*)&proxy->server_socket, NULL);
    }

    /* Close all active sessions */
    struct udp_session *session = proxy->sessions;
    while (session) {
        struct udp_session *next = session->next;
        udp_session_close(session);
        session = next;
    }

    return SEED_OK;
}

int udp_proxy_get_stats(const struct udp_proxy *proxy, struct udp_proxy_stats *stats)
{
    if (!proxy || !stats) {
        log_error("Invalid arguments to udp_proxy_get_stats");
        return SEED_ERROR_INVALID_ARGS;
    }

    stats->total_sessions = proxy->total_sessions;
    stats->active_sessions = proxy->active_sessions;
    stats->total_packets_forwarded = proxy->total_packets_forwarded;
    stats->total_bytes_forwarded = proxy->total_bytes_forwarded;
    stats->packets_per_second = 0; /* TODO: Calculate packet rate */

    return SEED_OK;
}

struct udp_session* udp_proxy_find_or_create_session(struct udp_proxy *proxy, 
                                                    const struct sockaddr_in *client_addr)
{
    if (!proxy || !client_addr) {
        return NULL;
    }

    /* Try to find existing session */
    struct udp_session *session = find_session_by_client(proxy, client_addr);
    if (session) {
        /* Update activity timestamp */
        session->last_activity = uv_now(proxy->network->loop);
        return session;
    }

    /* Check session limit */
    if (proxy->session_count >= MAX_UDP_SESSIONS) {
        log_warning("Maximum UDP sessions reached for proxy '%s'", proxy->name);
        return NULL;
    }

    /* Create new session */
    session = malloc(sizeof(*session));
    if (!session) {
        log_error("Failed to allocate UDP session");
        return NULL;
    }

    memset(session, 0, sizeof(*session));
    session->proxy = proxy;
    session->state = UDP_SESSION_ACTIVE;
    session->client_addr = *client_addr;
    session->target_addr = proxy->target_addr;
    session->last_activity = uv_now(proxy->network->loop);

    /* Initialize target socket */
    int ret = uv_udp_init(proxy->network->loop, &session->target_socket);
    if (ret != 0) {
        log_error("Failed to initialize target socket: %s", uv_strerror(ret));
        free(session);
        return NULL;
    }

    session->target_socket.data = session;

    /* Start receiving from target */
    ret = uv_udp_recv_start(&session->target_socket, on_udp_alloc, on_target_recv);
    if (ret != 0) {
        log_error("Failed to start receiving from target: %s", uv_strerror(ret));
        uv_close((uv_handle_t*)&session->target_socket, NULL);
        free(session);
        return NULL;
    }

    /* Initialize session timeout timer */
    ret = uv_timer_init(proxy->network->loop, &session->timeout_timer);
    if (ret != 0) {
        log_error("Failed to initialize session timeout timer: %s", uv_strerror(ret));
        uv_close((uv_handle_t*)&session->target_socket, NULL);
        free(session);
        return NULL;
    }

    session->timeout_timer.data = session;

    /* Start timeout timer */
    ret = uv_timer_start(&session->timeout_timer, on_session_timeout, 
                        UDP_SESSION_TIMEOUT_SECS * 1000, 0);
    if (ret != 0) {
        log_error("Failed to start session timeout timer: %s", uv_strerror(ret));
        uv_close((uv_handle_t*)&session->target_socket, NULL);
        uv_close((uv_handle_t*)&session->timeout_timer, NULL);
        free(session);
        return NULL;
    }

    /* Add to proxy's session list */
    add_session(proxy, session);

    log_debug("Created new UDP session for client %s:%d",
             inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port));

    /* Notify callback */
    if (proxy->on_session_created) {
        proxy->on_session_created(proxy, session);
    }

    return session;
}

void udp_session_close(struct udp_session *session)
{
    if (!session || session->state == UDP_SESSION_CLOSED) {
        return;
    }

    log_debug("Closing UDP session");

    session->state = UDP_SESSION_CLOSED;

    /* Stop timeout timer */
    if (!uv_is_closing((uv_handle_t*)&session->timeout_timer)) {
        uv_timer_stop(&session->timeout_timer);
        uv_close((uv_handle_t*)&session->timeout_timer, NULL);
    }

    /* Close target socket */
    if (!uv_is_closing((uv_handle_t*)&session->target_socket)) {
        uv_udp_recv_stop(&session->target_socket);
        uv_close((uv_handle_t*)&session->target_socket, on_udp_close);
    }
}

void udp_proxy_cleanup(struct udp_proxy *proxy)
{
    if (!proxy) {
        return;
    }

    log_info("Cleaning up UDP proxy '%s'", proxy->name);

    /* Stop proxy first */
    udp_proxy_stop(proxy);

    /* Clear proxy structure */
    memset(proxy, 0, sizeof(*proxy));
}

/* Static helper functions */

static void add_session(struct udp_proxy *proxy, struct udp_session *session)
{
    if (!proxy || !session) {
        return;
    }

    /* Add to beginning of list */
    session->next = proxy->sessions;
    session->prev = NULL;
    
    if (proxy->sessions) {
        proxy->sessions->prev = session;
    }
    
    proxy->sessions = session;
    proxy->session_count++;
    proxy->active_sessions++;
    proxy->total_sessions++;

    log_debug("Added session to proxy '%s' (count: %d)", proxy->name, proxy->session_count);
}

static void remove_session(struct udp_proxy *proxy, struct udp_session *session)
{
    if (!proxy || !session) {
        return;
    }

    /* Remove from list */
    if (session->prev) {
        session->prev->next = session->next;
    } else {
        proxy->sessions = session->next;
    }
    
    if (session->next) {
        session->next->prev = session->prev;
    }

    proxy->session_count--;
    proxy->active_sessions--;

    log_debug("Removed session from proxy '%s' (count: %d)", proxy->name, proxy->session_count);

    /* Notify callback */
    if (proxy->on_session_closed) {
        proxy->on_session_closed(proxy, session);
    }

    /* Free session structure */
    free(session);
}

static struct udp_session* find_session_by_client(struct udp_proxy *proxy, 
                                                 const struct sockaddr_in *client_addr)
{
    if (!proxy || !client_addr) {
        return NULL;
    }

    struct udp_session *session = proxy->sessions;
    while (session) {
        if (sockaddr_in_compare(&session->client_addr, client_addr) == 0) {
            return session;
        }
        session = session->next;
    }

    return NULL;
}

static int forward_udp_packet(uv_udp_t *socket, const uint8_t *data, size_t size,
                             const struct sockaddr *dest_addr)
{
    if (!socket || !data || size == 0 || !dest_addr) {
        return SEED_ERROR_INVALID_ARGS;
    }

    /* Allocate send request and buffer */
    uv_udp_send_t *send_req = malloc(sizeof(*send_req));
    if (!send_req) {
        log_error("Failed to allocate UDP send request");
        return SEED_ERROR_OUT_OF_MEMORY;
    }

    uv_buf_t *send_buf = malloc(sizeof(*send_buf));
    if (!send_buf) {
        free(send_req);
        return SEED_ERROR_OUT_OF_MEMORY;
    }

    uint8_t *buffer_data = malloc(size);
    if (!buffer_data) {
        free(send_req);
        free(send_buf);
        return SEED_ERROR_OUT_OF_MEMORY;
    }

    /* Copy data */
    memcpy(buffer_data, data, size);
    
    send_buf->base = (char*)buffer_data;
    send_buf->len = size;
    send_req->data = send_buf;

    /* Send packet */
    int ret = uv_udp_send(send_req, socket, send_buf, 1, dest_addr, on_udp_send);
    if (ret != 0) {
        log_error("Failed to send UDP packet: %s", uv_strerror(ret));
        free(send_req);
        free(send_buf);
        free(buffer_data);
        return SEED_ERROR_NETWORK;
    }

    return SEED_OK;
}

static int sockaddr_in_compare(const struct sockaddr_in *a, const struct sockaddr_in *b)
{
    if (!a || !b) {
        return -1;
    }

    if (a->sin_addr.s_addr != b->sin_addr.s_addr) {
        return (int)(a->sin_addr.s_addr - b->sin_addr.s_addr);
    }

    if (a->sin_port != b->sin_port) {
        return (int)(a->sin_port - b->sin_port);
    }

    return 0;
}

/* libuv callback functions */

static void on_client_recv(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                          const struct sockaddr *addr, unsigned flags)
{
    struct udp_proxy *proxy = (struct udp_proxy*)handle->data;
    
    if (nread < 0) {
        log_error("UDP client receive error: %s", uv_strerror(nread));
        if (buf->base) {
            free(buf->base);
        }
        return;
    }

    if (nread == 0 || !addr) {
        if (buf->base) {
            free(buf->base);
        }
        return;
    }

    /* Find or create session for this client */
    struct udp_session *session = udp_proxy_find_or_create_session(proxy, 
                                                                  (const struct sockaddr_in*)addr);
    if (!session) {
        log_error("Failed to find or create UDP session");
        if (buf->base) {
            free(buf->base);
        }
        return;
    }

    /* Forward packet to target */
    int ret = forward_udp_packet(&session->target_socket, (const uint8_t*)buf->base, nread,
                                (const struct sockaddr*)&session->target_addr);
    if (ret != SEED_OK) {
        log_error("Failed to forward packet to target");
    } else {
        session->packets_received++;
        session->bytes_received += nread;
        proxy->total_packets_forwarded++;
        proxy->total_bytes_forwarded += nread;
        
        if (proxy->on_packet_forwarded) {
            proxy->on_packet_forwarded(proxy, nread);
        }
    }

    if (buf->base) {
        free(buf->base);
    }
}

static void on_target_recv(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                          const struct sockaddr *addr, unsigned flags)
{
    struct udp_session *session = (struct udp_session*)handle->data;
    struct udp_proxy *proxy = session->proxy;
    
    if (nread < 0) {
        log_error("UDP target receive error: %s", uv_strerror(nread));
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

    /* Forward packet back to client */
    int ret = forward_udp_packet(&proxy->server_socket, (const uint8_t*)buf->base, nread,
                                (const struct sockaddr*)&session->client_addr);
    if (ret != SEED_OK) {
        log_error("Failed to forward packet to client");
    } else {
        session->packets_sent++;
        session->bytes_sent += nread;
        proxy->total_packets_forwarded++;
        proxy->total_bytes_forwarded += nread;
        
        /* Update activity timestamp */
        session->last_activity = uv_now(proxy->network->loop);
        
        if (proxy->on_packet_forwarded) {
            proxy->on_packet_forwarded(proxy, nread);
        }
    }

    if (buf->base) {
        free(buf->base);
    }
}

static void on_udp_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    /* Allocate buffer for UDP packet */
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
}

static void on_udp_send(uv_udp_send_t *req, int status)
{
    uv_buf_t *send_buf = (uv_buf_t*)req->data;
    
    if (status != 0) {
        log_debug("UDP send error: %s", uv_strerror(status));
    }

    if (send_buf) {
        if (send_buf->base) {
            free(send_buf->base);
        }
        free(send_buf);
    }
    free(req);
}

static void on_session_timeout(uv_timer_t *timer)
{
    struct udp_session *session = (struct udp_session*)timer->data;
    
    log_debug("UDP session timeout");
    udp_session_close(session);
}

static void on_cleanup_timer(uv_timer_t *timer)
{
    struct udp_proxy *proxy = (struct udp_proxy*)timer->data;
    uint64_t now = uv_now(proxy->network->loop);
    
    /* Clean up expired sessions */
    struct udp_session *session = proxy->sessions;
    while (session) {
        struct udp_session *next = session->next;
        
        if (now - session->last_activity > (UDP_SESSION_TIMEOUT_SECS * 1000)) {
            log_debug("Cleaning up expired UDP session");
            udp_session_close(session);
        }
        
        session = next;
    }
}

static void on_udp_close(uv_handle_t *handle)
{
    struct udp_session *session = (struct udp_session*)handle->data;
    
    if (!session) {
        return;
    }

    /* Check if all handles are closed */
    if (uv_is_closing((uv_handle_t*)&session->target_socket) && 
        uv_is_closing((uv_handle_t*)&session->timeout_timer)) {
        
        log_debug("UDP session closed (received: %llu packets, sent: %llu packets)",
                 (unsigned long long)session->packets_received,
                 (unsigned long long)session->packets_sent);
        
        /* Remove from proxy's session list */
        remove_session(session->proxy, session);
    }
}