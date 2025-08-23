/**
 * @file ssh_encrypt.h
 * @brief SSH tunneling encryption module for TCP proxy connections
 * @author Seed Development Team
 * @date 2025
 */

#ifndef SSH_ENCRYPT_H
#define SSH_ENCRYPT_H

#include "common.h"

#ifdef ENABLE_SSH_ENCRYPTION
#include <libssh/libssh.h>
#include <libssh/server.h>
#else
/* Forward declarations for libssh types */
typedef void* ssh_session;
typedef void* ssh_channel;
typedef void* ssh_bind;
#endif

#ifdef ENABLE_UV_INTEGRATION
#include <uv.h>
#else
typedef struct {
    char* base;
    size_t len;
} uv_buf_t;
#endif

/** SSH configuration */
struct ssh_config {
    char host[256];                     /**< SSH server hostname */
    int port;                          /**< SSH server port */
    char username[64];                 /**< SSH username */
    char password[128];                /**< SSH password (optional) */
    char private_key[MAX_PATH_LENGTH]; /**< Private key file path */
    char public_key[MAX_PATH_LENGTH];  /**< Public key file path */
    char known_hosts[MAX_PATH_LENGTH]; /**< Known hosts file path */
    int local_port;                    /**< Local port to forward */
    char remote_host[256];             /**< Remote host to forward to */
    int remote_port;                   /**< Remote port to forward to */
    bool server_mode;                  /**< Server or client mode */
};

/** SSH connection context */
struct ssh_context {
    ssh_session session;               /**< SSH session */
    ssh_channel channel;               /**< SSH channel */
    ssh_bind sshbind;                  /**< SSH bind (server mode) */
    bool connected;                    /**< Connection status */
    bool channel_ready;                /**< Channel ready status */
    uv_buf_t pending_data;             /**< Pending data buffer */
    size_t pending_size;               /**< Size of pending data */
};

/**
 * @brief Initialize SSH encryption module
 *
 * @return 0 on success, negative error code on failure
 */
int ssh_encrypt_init(void);

/**
 * @brief Cleanup SSH encryption module
 */
void ssh_encrypt_cleanup(void);

/**
 * @brief Create SSH context
 *
 * @param[in] config  SSH configuration
 * @param[out] ctx    SSH context to create
 *
 * @return 0 on success, negative error code on failure
 */
int ssh_context_create(const struct ssh_config *config, struct ssh_context **ctx);

/**
 * @brief Destroy SSH context
 *
 * @param[in,out] ctx  SSH context to destroy
 */
void ssh_context_destroy(struct ssh_context *ctx);

/**
 * @brief Connect to SSH server (client mode)
 *
 * @param[in,out] ctx  SSH context
 *
 * @return 0 on success, negative error code on failure
 */
int ssh_connect(struct ssh_context *ctx);

/**
 * @brief Accept SSH connection (server mode)
 *
 * @param[in,out] ctx  SSH context
 *
 * @return 0 on success, negative error code on failure
 */
int ssh_accept(struct ssh_context *ctx);

/**
 * @brief Create SSH tunnel channel
 *
 * @param[in,out] ctx  SSH context
 * @param[in] remote_host Remote host to forward to
 * @param[in] remote_port Remote port to forward to
 *
 * @return 0 on success, negative error code on failure
 */
int ssh_create_tunnel(struct ssh_context *ctx, const char *remote_host, int remote_port);

/**
 * @brief Send data through SSH tunnel
 *
 * @param[in,out] ctx  SSH context
 * @param[in] data     Data to send
 * @param[in] len      Length of data
 *
 * @return Number of bytes sent, negative error code on failure
 */
int ssh_send_data(struct ssh_context *ctx, const char *data, size_t len);

/**
 * @brief Receive data from SSH tunnel
 *
 * @param[in,out] ctx  SSH context
 * @param[out] buffer  Buffer to receive data
 * @param[in] buffer_size Size of receive buffer
 * @param[out] received Number of bytes received
 *
 * @return 0 on success, negative error code on failure
 */
int ssh_receive_data(struct ssh_context *ctx, char *buffer, size_t buffer_size, 
                     size_t *received);

/**
 * @brief Check if SSH tunnel is ready for data transfer
 *
 * @param[in] ctx  SSH context
 *
 * @return true if ready, false otherwise
 */
bool ssh_is_ready(const struct ssh_context *ctx);

/**
 * @brief Disconnect SSH session
 *
 * @param[in,out] ctx  SSH context
 */
void ssh_disconnect(struct ssh_context *ctx);

/**
 * @brief Get SSH connection information
 *
 * @param[in] ctx     SSH context
 * @param[out] info   Connection information buffer
 * @param[in] info_size Size of info buffer
 *
 * @return 0 on success, negative error code on failure
 */
int ssh_get_info(const struct ssh_context *ctx, char *info, size_t info_size);

/**
 * @brief Authenticate SSH connection with password
 *
 * @param[in,out] ctx  SSH context
 * @param[in] password Password for authentication
 *
 * @return 0 on success, negative error code on failure
 */
int ssh_authenticate_password(struct ssh_context *ctx, const char *password);

/**
 * @brief Authenticate SSH connection with public key
 *
 * @param[in,out] ctx  SSH context
 * @param[in] private_key Private key file path
 * @param[in] passphrase Key passphrase (optional)
 *
 * @return 0 on success, negative error code on failure
 */
int ssh_authenticate_key(struct ssh_context *ctx, const char *private_key, 
                         const char *passphrase);

#endif /* SSH_ENCRYPT_H */