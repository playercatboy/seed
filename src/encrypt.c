/**
 * @file encrypt.c
 * @brief Main encryption manager implementation for Seed reverse proxy
 * @author Seed Development Team
 * @date 2025
 */

#include "encrypt.h"
#include "tls_encrypt.h"
#include "ssh_encrypt.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>

/* Global encryption initialization status */
static bool encrypt_initialized = false;

int encrypt_init(void)
{
    if (encrypt_initialized) {
        return 0;
    }
    
    log_debug("Initializing encryption subsystem");
    
    /* Initialize table encryption module */
    int ret = table_encrypt_init();
    if (ret != 0) {
        log_error("Failed to initialize table encryption module");
        return ret;
    }
    
    /* Initialize TLS encryption module */
    ret = tls_encrypt_init();
    if (ret != 0) {
        log_warning("Failed to initialize TLS encryption module (may not be available)");
        /* Continue anyway - TLS is optional */
    }
    
    /* Initialize SSH encryption module */
    ret = ssh_encrypt_init();
    if (ret != 0) {
        log_warning("Failed to initialize SSH encryption module (may not be available)");
        /* Continue anyway - SSH is optional */
    }
    
    encrypt_initialized = true;
    log_info("Encryption subsystem initialized");
    return 0;
}

void encrypt_cleanup(void)
{
    if (!encrypt_initialized) {
        return;
    }
    
    log_debug("Cleaning up encryption subsystem");
    
    /* Cleanup table encryption */
    table_encrypt_cleanup();
    
    /* Cleanup TLS encryption */
    tls_encrypt_cleanup();
    
    /* Cleanup SSH encryption */
    ssh_encrypt_cleanup();
    
    encrypt_initialized = false;
    log_info("Encryption subsystem cleaned up");
}

const char *encrypt_type_string(enum encrypt_impl type)
{
    switch (type) {
        case ENCRYPT_NONE:  return "none";
        case ENCRYPT_TLS:   return "tls";
        case ENCRYPT_SSH:   return "ssh";
        case ENCRYPT_TABLE: return "table";
        default:            return "unknown";
    }
}

int encrypt_create_instance(const struct proxy_config *proxy_config, 
                           struct encryption_instance **instance)
{
    if (!proxy_config || !instance) {
        log_error("Invalid arguments to encrypt_create_instance");
        return -1;
    }
    
    if (!encrypt_initialized) {
        log_error("Encryption subsystem not initialized");
        return -1;
    }
    
    /* Check if encryption is enabled */
    if (!proxy_config->encrypt) {
        *instance = NULL;
        log_debug("Encryption not enabled for proxy '%s'", proxy_config->name);
        return 0;
    }
    
    /* Allocate encryption instance */
    struct encryption_instance *enc = malloc(sizeof(struct encryption_instance));
    if (!enc) {
        log_error("Failed to allocate encryption instance");
        return -1;
    }
    
    memset(enc, 0, sizeof(*enc));
    enc->type = proxy_config->encrypt_impl;
    enc->initialized = false;
    enc->ready = false;
    
    /* Create appropriate encryption context based on type */
    int ret = 0;
    switch (proxy_config->encrypt_impl) {
        case ENCRYPT_NONE:
            /* No encryption context needed */
            enc->ready = true;
            break;
            
        case ENCRYPT_TABLE:
            if (proxy_config->type != PROXY_TYPE_UDP) {
                log_error("Table encryption only supported for UDP proxies");
                free(enc);
                return -1;
            }
            /* Table encryption context will be created when connection is initialized */
            break;
            
        case ENCRYPT_TLS:
            if (proxy_config->type != PROXY_TYPE_TCP) {
                log_error("TLS encryption only supported for TCP proxies");
                free(enc);
                return -1;
            }
            /* Create TLS configuration */
            struct tls_config tls_cfg = {0};
            tls_cfg.server_mode = false;  /* Client mode by default */
            tls_cfg.verify_peer = true;   /* Verify server certificate */
            
            /* Use config values if available */
            if (strlen(proxy_config->tls_cert_file) > 0) {
                strncpy(tls_cfg.cert_file, proxy_config->tls_cert_file, sizeof(tls_cfg.cert_file) - 1);
            }
            if (strlen(proxy_config->tls_key_file) > 0) {
                strncpy(tls_cfg.key_file, proxy_config->tls_key_file, sizeof(tls_cfg.key_file) - 1);
            }
            if (strlen(proxy_config->tls_ca_file) > 0) {
                strncpy(tls_cfg.ca_file, proxy_config->tls_ca_file, sizeof(tls_cfg.ca_file) - 1);
            }
            tls_cfg.verify_peer = proxy_config->tls_verify_peer;
            
            ret = tls_context_create(&tls_cfg, &enc->ctx.tls);
            if (ret != 0) {
                log_error("Failed to create TLS encryption context");
                free(enc);
                return ret;
            }
            break;
            
        case ENCRYPT_SSH:
            if (proxy_config->type != PROXY_TYPE_TCP) {
                log_error("SSH encryption only supported for TCP proxies");
                free(enc);
                return -1;
            }
            /* Create SSH configuration */
            struct ssh_config ssh_cfg = {0};
            ssh_cfg.server_mode = false;  /* Client mode by default */
            ssh_cfg.port = proxy_config->ssh_port > 0 ? proxy_config->ssh_port : 22;
            
            /* Use config values */
            if (strlen(proxy_config->ssh_host) > 0) {
                strncpy(ssh_cfg.host, proxy_config->ssh_host, sizeof(ssh_cfg.host) - 1);
            }
            if (strlen(proxy_config->ssh_username) > 0) {
                strncpy(ssh_cfg.username, proxy_config->ssh_username, sizeof(ssh_cfg.username) - 1);
            }
            if (strlen(proxy_config->ssh_password) > 0) {
                strncpy(ssh_cfg.password, proxy_config->ssh_password, sizeof(ssh_cfg.password) - 1);
            }
            if (strlen(proxy_config->ssh_private_key) > 0) {
                strncpy(ssh_cfg.private_key, proxy_config->ssh_private_key, sizeof(ssh_cfg.private_key) - 1);
            }
            if (strlen(proxy_config->ssh_known_hosts) > 0) {
                strncpy(ssh_cfg.known_hosts, proxy_config->ssh_known_hosts, sizeof(ssh_cfg.known_hosts) - 1);
            }
            if (strlen(proxy_config->ssh_remote_host) > 0) {
                strncpy(ssh_cfg.remote_host, proxy_config->ssh_remote_host, sizeof(ssh_cfg.remote_host) - 1);
            } else {
                strcpy(ssh_cfg.remote_host, "127.0.0.1"); /* Default */
            }
            ssh_cfg.remote_port = proxy_config->ssh_remote_port > 0 ? 
                                proxy_config->ssh_remote_port : proxy_config->remote_port;
            
            ret = ssh_context_create(&ssh_cfg, &enc->ctx.ssh);
            if (ret != 0) {
                log_error("Failed to create SSH encryption context");
                free(enc);
                return ret;
            }
            break;
            
        default:
            log_error("Unknown encryption type: %d", proxy_config->encrypt_impl);
            free(enc);
            return -1;
    }
    
    enc->initialized = true;
    *instance = enc;
    
    log_info("Created encryption instance for proxy '%s' with %s encryption",
             proxy_config->name, encrypt_type_string(enc->type));
    return 0;
}

void encrypt_destroy_instance(struct encryption_instance *instance)
{
    if (!instance) {
        return;
    }
    
    log_debug("Destroying encryption instance (type: %s)", 
              encrypt_type_string(instance->type));
    
    /* Cleanup encryption context based on type */
    switch (instance->type) {
        case ENCRYPT_NONE:
            /* Nothing to cleanup */
            break;
            
        case ENCRYPT_TABLE:
            if (instance->ctx.table) {
                table_context_destroy(instance->ctx.table);
                instance->ctx.table = NULL;
            }
            break;
            
        case ENCRYPT_TLS:
            if (instance->ctx.tls) {
                tls_context_destroy(instance->ctx.tls);
                instance->ctx.tls = NULL;
            }
            break;
            
        case ENCRYPT_SSH:
            if (instance->ctx.ssh) {
                ssh_context_destroy(instance->ctx.ssh);
                instance->ctx.ssh = NULL;
            }
            break;
    }
    
    /* Clear and free instance */
    memset(instance, 0, sizeof(*instance));
    free(instance);
}

int encrypt_init_connection(struct encryption_instance *instance, 
                           struct proxy_connection *connection)
{
    if (!instance || !connection) {
        log_error("Invalid arguments to encrypt_init_connection");
        return -1;
    }
    
    if (!instance->initialized) {
        log_error("Encryption instance not initialized");
        return -1;
    }
    
    /* Initialize encryption context based on type */
    switch (instance->type) {
        case ENCRYPT_NONE:
            instance->ready = true;
            break;
            
        case ENCRYPT_TABLE:
            /* Table encryption doesn't need per-connection initialization */
            /* Context should already be created during proxy setup */
            instance->ready = (instance->ctx.table != NULL);
            break;
            
        case ENCRYPT_TLS:
            /* TODO: Initialize TLS connection when implemented */
            log_error("TLS encryption not yet implemented");
            return -1;
            
        case ENCRYPT_SSH:
            /* TODO: Initialize SSH connection when implemented */
            log_error("SSH encryption not yet implemented");
            return -1;
            
        default:
            log_error("Unknown encryption type: %d", instance->type);
            return -1;
    }
    
    log_debug("Initialized encryption for connection (type: %s, ready: %s)",
              encrypt_type_string(instance->type), 
              instance->ready ? "yes" : "no");
    return 0;
}

int encrypt_process_handshake(struct encryption_instance *instance,
                             const char *input, size_t input_len,
                             char **output, size_t *output_len)
{
    if (!instance || !output || !output_len) {
        log_error("Invalid arguments to encrypt_process_handshake");
        return -1;
    }
    
    *output = NULL;
    *output_len = 0;
    
    switch (instance->type) {
        case ENCRYPT_NONE:
        case ENCRYPT_TABLE:
            /* No handshake needed */
            return 1;
            
        case ENCRYPT_TLS:
            if (!instance->ctx.tls) {
                log_error("TLS context not initialized");
                return -1;
            }
            return tls_handshake(instance->ctx.tls, 
                               input, input_len, output, output_len);
            
        case ENCRYPT_SSH:
            if (!instance->ctx.ssh) {
                log_error("SSH context not initialized");
                return -1;
            }
            /* SSH handshake is handled during connection establishment */
            return ssh_is_ready(instance->ctx.ssh) ? 1 : 0;
            
        default:
            log_error("Unknown encryption type for handshake: %s",
                      encrypt_type_string(instance->type));
            return -1;
    }
}

int encrypt_data(struct encryption_instance *instance,
                 const char *plaintext, size_t plain_len,
                 char **ciphertext, size_t *cipher_len)
{
    if (!instance || !plaintext || !ciphertext || !cipher_len) {
        log_error("Invalid arguments to encrypt_data");
        return -1;
    }
    
    if (!instance->ready) {
        log_error("Encryption instance not ready for data transfer");
        return -1;
    }
    
    switch (instance->type) {
        case ENCRYPT_NONE:
            /* No encryption - just copy data */
            *ciphertext = malloc(plain_len);
            if (!*ciphertext) {
                log_error("Failed to allocate memory for plaintext copy");
                return -1;
            }
            memcpy(*ciphertext, plaintext, plain_len);
            *cipher_len = plain_len;
            break;
            
        case ENCRYPT_TABLE:
            /* Table encryption - encrypt in-place copy */
            if (!instance->ctx.table) {
                log_error("Table encryption context not initialized");
                return -1;
            }
            
            *ciphertext = malloc(plain_len);
            if (!*ciphertext) {
                log_error("Failed to allocate memory for encrypted data");
                return -1;
            }
            
            /* Copy and encrypt */
            int ret = table_encrypt_copy(instance->ctx.table, 
                                       (const uint8_t*)plaintext, 
                                       (uint8_t*)*ciphertext, plain_len);
            if (ret != 0) {
                free(*ciphertext);
                *ciphertext = NULL;
                log_error("Failed to encrypt data with table encryption");
                return -1;
            }
            *cipher_len = plain_len;
            break;
            
        case ENCRYPT_TLS:
            if (!instance->ctx.tls) {
                log_error("TLS context not initialized");
                return -1;
            }
            return tls_encrypt(instance->ctx.tls,
                             plaintext, plain_len, ciphertext, cipher_len);
            
        case ENCRYPT_SSH:
            if (!instance->ctx.ssh) {
                log_error("SSH context not initialized");
                return -1;
            }
            /* SSH encryption is handled by sending data through tunnel */
            int bytes_sent = ssh_send_data(instance->ctx.ssh, plaintext, plain_len);
            if (bytes_sent < 0) {
                return bytes_sent;
            }
            /* For SSH, we don't return encrypted data but indicate success */
            *ciphertext = NULL;
            *cipher_len = 0;
            return 0;
            
        default:
            log_error("Unknown encryption type: %d", instance->type);
            return -1;
    }
    
    return 0;
}

int decrypt_data(struct encryption_instance *instance,
                 const char *ciphertext, size_t cipher_len,
                 char **plaintext, size_t *plain_len)
{
    if (!instance || !ciphertext || !plaintext || !plain_len) {
        log_error("Invalid arguments to decrypt_data");
        return -1;
    }
    
    if (!instance->ready) {
        log_error("Encryption instance not ready for data transfer");
        return -1;
    }
    
    switch (instance->type) {
        case ENCRYPT_NONE:
            /* No decryption - just copy data */
            *plaintext = malloc(cipher_len);
            if (!*plaintext) {
                log_error("Failed to allocate memory for plaintext copy");
                return -1;
            }
            memcpy(*plaintext, ciphertext, cipher_len);
            *plain_len = cipher_len;
            break;
            
        case ENCRYPT_TABLE:
            /* Table decryption - decrypt in-place copy */
            if (!instance->ctx.table) {
                log_error("Table encryption context not initialized");
                return -1;
            }
            
            *plaintext = malloc(cipher_len);
            if (!*plaintext) {
                log_error("Failed to allocate memory for decrypted data");
                return -1;
            }
            
            /* Copy and decrypt */
            int ret = table_decrypt_copy(instance->ctx.table, 
                                       (const uint8_t*)ciphertext, 
                                       (uint8_t*)*plaintext, cipher_len);
            if (ret != 0) {
                free(*plaintext);
                *plaintext = NULL;
                log_error("Failed to decrypt data with table encryption");
                return -1;
            }
            *plain_len = cipher_len;
            break;
            
        case ENCRYPT_TLS:
            if (!instance->ctx.tls) {
                log_error("TLS context not initialized");
                return -1;
            }
            return tls_decrypt(instance->ctx.tls,
                             ciphertext, cipher_len, plaintext, plain_len);
            
        case ENCRYPT_SSH:
            if (!instance->ctx.ssh) {
                log_error("SSH context not initialized");
                return -1;
            }
            /* SSH decryption is handled by receiving data from tunnel */
            char buffer[8192];
            size_t received = 0;
            int ssh_ret = ssh_receive_data(instance->ctx.ssh, buffer, sizeof(buffer), &received);
            if (ssh_ret != 0) {
                return ssh_ret;
            }
            if (received > 0) {
                *plaintext = malloc(received);
                if (!*plaintext) {
                    return SEED_ERROR_OUT_OF_MEMORY;
                }
                memcpy(*plaintext, buffer, received);
                *plain_len = received;
            } else {
                *plaintext = NULL;
                *plain_len = 0;
            }
            return 0;
            
        default:
            log_error("Unknown encryption type: %d", instance->type);
            return -1;
    }
    
    return 0;
}

bool encrypt_is_ready(const struct encryption_instance *instance)
{
    if (!instance || !instance->initialized) {
        return false;
    }
    
    /* For TLS, check if handshake is complete */
    if (instance->type == ENCRYPT_TLS && instance->ctx.tls) {
        return tls_is_ready(instance->ctx.tls);
    }
    
    /* For SSH, check if tunnel is ready */
    if (instance->type == ENCRYPT_SSH && instance->ctx.ssh) {
        return ssh_is_ready(instance->ctx.ssh);
    }
    
    return instance->ready;
}

int encrypt_get_info(const struct encryption_instance *instance,
                     char *info, size_t info_size)
{
    if (!instance || !info || info_size == 0) {
        log_error("Invalid arguments to encrypt_get_info");
        return -1;
    }
    
    switch (instance->type) {
        case ENCRYPT_NONE:
            snprintf(info, info_size, "No encryption");
            break;
            
        case ENCRYPT_TABLE:
            snprintf(info, info_size, "Table encryption (ready: %s)", 
                    instance->ready ? "yes" : "no");
            break;
            
        case ENCRYPT_TLS:
            if (instance->ctx.tls) {
                char cipher[128] = {0};
                char version[64] = {0};
                if (tls_get_info(instance->ctx.tls, 
                               cipher, sizeof(cipher), version, sizeof(version)) == 0) {
                    snprintf(info, info_size, "TLS encryption (%s, %s, ready: %s)",
                           version, cipher, encrypt_is_ready(instance) ? "yes" : "no");
                } else {
                    snprintf(info, info_size, "TLS encryption (ready: %s)", 
                           encrypt_is_ready(instance) ? "yes" : "no");
                }
            } else {
                snprintf(info, info_size, "TLS encryption (context not initialized)");
            }
            break;
            
        case ENCRYPT_SSH:
            if (instance->ctx.ssh) {
                char ssh_info[256] = {0};
                if (ssh_get_info(instance->ctx.ssh, ssh_info, sizeof(ssh_info)) == 0) {
                    snprintf(info, info_size, "SSH tunneling (%s)", ssh_info);
                } else {
                    snprintf(info, info_size, "SSH tunneling (ready: %s)", 
                           encrypt_is_ready(instance) ? "yes" : "no");
                }
            } else {
                snprintf(info, info_size, "SSH tunneling (context not initialized)");
            }
            break;
            
        default:
            snprintf(info, info_size, "Unknown encryption type: %d", instance->type);
            break;
    }
    
    return 0;
}