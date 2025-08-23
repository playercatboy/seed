/**
 * @file ssh_encrypt.c
 * @brief SSH tunneling implementation for TCP proxy connections
 * @author Seed Development Team
 * @date 2025
 */

#include "ssh_encrypt.h"
#include "log.h"
#include <string.h>
#include <stdlib.h>

#ifdef ENABLE_SSH_ENCRYPTION
#include <libssh/libssh.h>
#include <libssh/server.h>
#endif

/* Static variables */
static bool ssh_encrypt_initialized = false;

int ssh_encrypt_init(void)
{
    if (ssh_encrypt_initialized) {
        return 0;
    }
    
    log_debug("Initializing SSH encryption module");
    
#ifdef ENABLE_SSH_ENCRYPTION
    /* Initialize libssh */
    int rc = ssh_init();
    if (rc != SSH_OK) {
        log_error("Failed to initialize libssh");
        return SEED_ERROR;
    }
    
    log_info("SSH encryption module initialized with libssh");
#else
    log_warning("SSH encryption module initialized in stub mode (libssh not available)");
#endif
    
    ssh_encrypt_initialized = true;
    return 0;
}

void ssh_encrypt_cleanup(void)
{
    if (!ssh_encrypt_initialized) {
        return;
    }
    
    log_debug("Cleaning up SSH encryption module");
    
#ifdef ENABLE_SSH_ENCRYPTION
    ssh_finalize();
#endif
    
    ssh_encrypt_initialized = false;
}

int ssh_context_create(const struct ssh_config *config, struct ssh_context **ctx)
{
    if (!config || !ctx) {
        log_error("Invalid arguments to ssh_context_create");
        return SEED_ERROR_INVALID_ARGS;
    }
    
    if (!ssh_encrypt_initialized) {
        log_error("SSH encryption module not initialized");
        return SEED_ERROR;
    }
    
#ifndef ENABLE_SSH_ENCRYPTION
    log_error("SSH encryption not available (compiled without libssh support)");
    return SEED_ERROR_NOT_IMPLEMENTED;
#else
    
    struct ssh_context *context = malloc(sizeof(struct ssh_context));
    if (!context) {
        log_error("Failed to allocate SSH context");
        return SEED_ERROR_OUT_OF_MEMORY;
    }
    
    memset(context, 0, sizeof(struct ssh_context));
    
    if (config->server_mode) {
        /* Create SSH bind for server mode */
        context->sshbind = ssh_bind_new();
        if (!context->sshbind) {
            log_error("Failed to create SSH bind");
            free(context);
            return SEED_ERROR;
        }
        
        /* Configure SSH bind */
        ssh_bind_options_set(context->sshbind, SSH_BIND_OPTIONS_BINDPORT, &config->port);
        ssh_bind_options_set(context->sshbind, SSH_BIND_OPTIONS_BINDADDR, config->host);
        
        /* Set host keys */
        if (strlen(config->private_key) > 0) {
            ssh_bind_options_set(context->sshbind, SSH_BIND_OPTIONS_HOSTKEY, config->private_key);
        }
        
    } else {
        /* Create SSH session for client mode */
        context->session = ssh_new();
        if (!context->session) {
            log_error("Failed to create SSH session");
            free(context);
            return SEED_ERROR;
        }
        
        /* Configure SSH session */
        ssh_options_set(context->session, SSH_OPTIONS_HOST, config->host);
        ssh_options_set(context->session, SSH_OPTIONS_PORT, &config->port);
        ssh_options_set(context->session, SSH_OPTIONS_USER, config->username);
        
        /* Set known hosts file if specified */
        if (strlen(config->known_hosts) > 0) {
            ssh_options_set(context->session, SSH_OPTIONS_KNOWNHOSTS, config->known_hosts);
        }
    }
    
    context->connected = false;
    context->channel_ready = false;
    *ctx = context;
    
    log_debug("SSH context created in %s mode", config->server_mode ? "server" : "client");
    return 0;
    
#endif
}

void ssh_context_destroy(struct ssh_context *ctx)
{
    if (!ctx) {
        return;
    }
    
    log_debug("Destroying SSH context");
    
#ifdef ENABLE_SSH_ENCRYPTION
    if (ctx->channel) {
        ssh_channel_close(ctx->channel);
        ssh_channel_free(ctx->channel);
    }
    if (ctx->session) {
        ssh_disconnect(ctx->session);
        ssh_free(ctx->session);
    }
    if (ctx->sshbind) {
        ssh_bind_free(ctx->sshbind);
    }
    if (ctx->pending_data.base) {
        free(ctx->pending_data.base);
    }
#endif
    
    memset(ctx, 0, sizeof(struct ssh_context));
    free(ctx);
}

int ssh_connect(struct ssh_context *ctx)
{
    if (!ctx) {
        log_error("Invalid SSH context");
        return SEED_ERROR_INVALID_ARGS;
    }
    
#ifndef ENABLE_SSH_ENCRYPTION
    log_error("SSH connect not available (compiled without libssh support)");
    return SEED_ERROR_NOT_IMPLEMENTED;
#else
    
    if (ctx->connected) {
        return 0; /* Already connected */
    }
    
    if (!ctx->session) {
        log_error("SSH session not initialized");
        return SEED_ERROR;
    }
    
    /* Connect to SSH server */
    int rc = ssh_connect(ctx->session);
    if (rc != SSH_OK) {
        log_error("SSH connection failed: %s", ssh_get_error(ctx->session));
        return SEED_ERROR_NETWORK;
    }
    
    /* Verify server identity (optional) */
    rc = ssh_session_is_known_server(ctx->session);
    if (rc == SSH_KNOWN_HOSTS_ERROR) {
        log_error("SSH server verification failed");
        return SEED_ERROR_AUTH_FAILED;
    }
    
    ctx->connected = true;
    log_info("SSH connection established");
    return 0;
    
#endif
}

int ssh_accept(struct ssh_context *ctx)
{
    if (!ctx) {
        log_error("Invalid SSH context");
        return SEED_ERROR_INVALID_ARGS;
    }
    
#ifndef ENABLE_SSH_ENCRYPTION
    log_error("SSH accept not available (compiled without libssh support)");
    return SEED_ERROR_NOT_IMPLEMENTED;
#else
    
    if (!ctx->sshbind) {
        log_error("SSH bind not initialized");
        return SEED_ERROR;
    }
    
    /* Bind SSH server */
    int rc = ssh_bind_listen(ctx->sshbind);
    if (rc != SSH_OK) {
        log_error("SSH bind failed: %s", ssh_get_error(ctx->sshbind));
        return SEED_ERROR_NETWORK;
    }
    
    /* Create session for incoming connection */
    ctx->session = ssh_new();
    if (!ctx->session) {
        log_error("Failed to create SSH session");
        return SEED_ERROR_OUT_OF_MEMORY;
    }
    
    /* Accept incoming connection */
    rc = ssh_bind_accept(ctx->sshbind, ctx->session);
    if (rc != SSH_OK) {
        log_error("SSH accept failed: %s", ssh_get_error(ctx->sshbind));
        ssh_free(ctx->session);
        ctx->session = NULL;
        return SEED_ERROR_NETWORK;
    }
    
    /* Perform key exchange */
    rc = ssh_handle_key_exchange(ctx->session);
    if (rc != SSH_OK) {
        log_error("SSH key exchange failed: %s", ssh_get_error(ctx->session));
        ssh_free(ctx->session);
        ctx->session = NULL;
        return SEED_ERROR_AUTH_FAILED;
    }
    
    ctx->connected = true;
    log_info("SSH connection accepted");
    return 0;
    
#endif
}

int ssh_authenticate_password(struct ssh_context *ctx, const char *password)
{
    if (!ctx || !password) {
        log_error("Invalid arguments to ssh_authenticate_password");
        return SEED_ERROR_INVALID_ARGS;
    }
    
#ifndef ENABLE_SSH_ENCRYPTION
    log_error("SSH password auth not available (compiled without libssh support)");
    return SEED_ERROR_NOT_IMPLEMENTED;
#else
    
    if (!ctx->session || !ctx->connected) {
        log_error("SSH session not connected");
        return SEED_ERROR;
    }
    
    int rc = ssh_userauth_password(ctx->session, NULL, password);
    if (rc != SSH_AUTH_SUCCESS) {
        log_error("SSH password authentication failed");
        return SEED_ERROR_AUTH_FAILED;
    }
    
    log_info("SSH password authentication successful");
    return 0;
    
#endif
}

int ssh_authenticate_key(struct ssh_context *ctx, const char *private_key, 
                         const char *passphrase)
{
    if (!ctx || !private_key) {
        log_error("Invalid arguments to ssh_authenticate_key");
        return SEED_ERROR_INVALID_ARGS;
    }
    
#ifndef ENABLE_SSH_ENCRYPTION
    log_error("SSH key auth not available (compiled without libssh support)");
    return SEED_ERROR_NOT_IMPLEMENTED;
#else
    
    if (!ctx->session || !ctx->connected) {
        log_error("SSH session not connected");
        return SEED_ERROR;
    }
    
    /* Load private key */
    ssh_key privkey;
    int rc = ssh_pki_import_privkey_file(private_key, passphrase, NULL, NULL, &privkey);
    if (rc != SSH_OK) {
        log_error("Failed to load SSH private key: %s", private_key);
        return SEED_ERROR_CONFIG;
    }
    
    /* Authenticate with key */
    rc = ssh_userauth_publickey(ctx->session, NULL, privkey);
    ssh_key_free(privkey);
    
    if (rc != SSH_AUTH_SUCCESS) {
        log_error("SSH key authentication failed");
        return SEED_ERROR_AUTH_FAILED;
    }
    
    log_info("SSH key authentication successful");
    return 0;
    
#endif
}

int ssh_create_tunnel(struct ssh_context *ctx, const char *remote_host, int remote_port)
{
    if (!ctx || !remote_host) {
        log_error("Invalid arguments to ssh_create_tunnel");
        return SEED_ERROR_INVALID_ARGS;
    }
    
#ifndef ENABLE_SSH_ENCRYPTION
    log_error("SSH tunnel not available (compiled without libssh support)");
    return SEED_ERROR_NOT_IMPLEMENTED;
#else
    
    if (!ctx->session || !ctx->connected) {
        log_error("SSH session not connected");
        return SEED_ERROR;
    }
    
    /* Create new channel */
    ctx->channel = ssh_channel_new(ctx->session);
    if (!ctx->channel) {
        log_error("Failed to create SSH channel");
        return SEED_ERROR;
    }
    
    /* Open channel */
    int rc = ssh_channel_open_session(ctx->channel);
    if (rc != SSH_OK) {
        log_error("Failed to open SSH channel");
        ssh_channel_free(ctx->channel);
        ctx->channel = NULL;
        return SEED_ERROR_NETWORK;
    }
    
    /* Request port forwarding */
    rc = ssh_channel_request_port_forward(ctx->channel, remote_host, remote_port);
    if (rc != SSH_OK) {
        log_error("Failed to request SSH port forward to %s:%d", remote_host, remote_port);
        ssh_channel_close(ctx->channel);
        ssh_channel_free(ctx->channel);
        ctx->channel = NULL;
        return SEED_ERROR_NETWORK;
    }
    
    ctx->channel_ready = true;
    log_info("SSH tunnel created to %s:%d", remote_host, remote_port);
    return 0;
    
#endif
}

int ssh_send_data(struct ssh_context *ctx, const char *data, size_t len)
{
    if (!ctx || !data) {
        log_error("Invalid arguments to ssh_send_data");
        return SEED_ERROR_INVALID_ARGS;
    }
    
#ifndef ENABLE_SSH_ENCRYPTION
    log_error("SSH send not available (compiled without libssh support)");
    return SEED_ERROR_NOT_IMPLEMENTED;
#else
    
    if (!ctx->channel || !ctx->channel_ready) {
        log_error("SSH channel not ready");
        return SEED_ERROR;
    }
    
    int bytes_sent = ssh_channel_write(ctx->channel, data, len);
    if (bytes_sent < 0) {
        log_error("SSH send failed");
        return SEED_ERROR_NETWORK;
    }
    
    log_debug("Sent %d bytes through SSH tunnel", bytes_sent);
    return bytes_sent;
    
#endif
}

int ssh_receive_data(struct ssh_context *ctx, char *buffer, size_t buffer_size, 
                     size_t *received)
{
    if (!ctx || !buffer || !received) {
        log_error("Invalid arguments to ssh_receive_data");
        return SEED_ERROR_INVALID_ARGS;
    }
    
    *received = 0;
    
#ifndef ENABLE_SSH_ENCRYPTION
    log_error("SSH receive not available (compiled without libssh support)");
    return SEED_ERROR_NOT_IMPLEMENTED;
#else
    
    if (!ctx->channel || !ctx->channel_ready) {
        log_error("SSH channel not ready");
        return SEED_ERROR;
    }
    
    int bytes_read = ssh_channel_read(ctx->channel, buffer, buffer_size, 0);
    if (bytes_read < 0) {
        log_error("SSH receive failed");
        return SEED_ERROR_NETWORK;
    }
    
    if (bytes_read == 0) {
        /* Check if channel is closed */
        if (ssh_channel_is_eof(ctx->channel)) {
            log_debug("SSH channel closed by peer");
            return SEED_ERROR_CONNECTION_CLOSED;
        }
        return 0; /* No data available */
    }
    
    *received = bytes_read;
    log_debug("Received %d bytes through SSH tunnel", bytes_read);
    return 0;
    
#endif
}

bool ssh_is_ready(const struct ssh_context *ctx)
{
    if (!ctx) {
        return false;
    }
    
#ifdef ENABLE_SSH_ENCRYPTION
    return ctx->connected && ctx->channel_ready;
#else
    return false;
#endif
}

void ssh_disconnect(struct ssh_context *ctx)
{
    if (!ctx) {
        return;
    }
    
    log_debug("Disconnecting SSH session");
    
#ifdef ENABLE_SSH_ENCRYPTION
    if (ctx->channel) {
        ssh_channel_close(ctx->channel);
        ssh_channel_free(ctx->channel);
        ctx->channel = NULL;
    }
    
    if (ctx->session) {
        ssh_disconnect(ctx->session);
        ssh_free(ctx->session);
        ctx->session = NULL;
    }
#endif
    
    ctx->connected = false;
    ctx->channel_ready = false;
}

int ssh_get_info(const struct ssh_context *ctx, char *info, size_t info_size)
{
    if (!ctx || !info) {
        log_error("Invalid arguments to ssh_get_info");
        return SEED_ERROR_INVALID_ARGS;
    }
    
#ifndef ENABLE_SSH_ENCRYPTION
    snprintf(info, info_size, "SSH not available");
    return SEED_ERROR_NOT_IMPLEMENTED;
#else
    
    if (!ctx->session || !ctx->connected) {
        snprintf(info, info_size, "SSH not connected");
        return SEED_ERROR;
    }
    
    /* Get SSH version and server banner */
    const char *server_banner = ssh_get_serverbanner(ctx->session);
    const char *client_banner = ssh_get_clientbanner(ctx->session);
    
    snprintf(info, info_size, "SSH connected (server: %s, client: %s, ready: %s)",
             server_banner ? server_banner : "unknown",
             client_banner ? client_banner : "unknown", 
             ctx->channel_ready ? "yes" : "no");
    
    return 0;
    
#endif
}