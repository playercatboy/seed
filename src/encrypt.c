/**
 * @file encrypt.c
 * @brief Main encryption manager implementation for Seed reverse proxy
 * @author Seed Development Team
 * @date 2025
 */

#include "encrypt.h"
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
    
    /* TODO: Initialize TLS encryption when implemented */
    /* TODO: Initialize SSH encryption when implemented */
    
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
    
    /* TODO: Cleanup TLS encryption when implemented */
    /* TODO: Cleanup SSH encryption when implemented */
    
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
            /* TODO: Create TLS context when implemented */
            log_warning("TLS encryption not yet implemented");
            free(enc);
            return -1;
            
        case ENCRYPT_SSH:
            if (proxy_config->type != PROXY_TYPE_TCP) {
                log_error("SSH encryption only supported for TCP proxies");
                free(enc);
                return -1;
            }
            /* TODO: Create SSH context when implemented */
            log_warning("SSH encryption not yet implemented");
            free(enc);
            return -1;
            
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
            /* TODO: Cleanup TLS context when implemented */
            break;
            
        case ENCRYPT_SSH:
            /* TODO: Cleanup SSH context when implemented */
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
    
    /* Table encryption doesn't use handshakes */
    if (instance->type == ENCRYPT_TABLE || instance->type == ENCRYPT_NONE) {
        *output = NULL;
        *output_len = 0;
        return 1; /* Handshake "complete" */
    }
    
    /* TODO: Process TLS/SSH handshakes when implemented */
    log_error("Handshake processing not implemented for encryption type: %s",
              encrypt_type_string(instance->type));
    return -1;
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
            /* TODO: Implement TLS encryption */
            log_error("TLS encryption not yet implemented");
            return -1;
            
        case ENCRYPT_SSH:
            /* TODO: Implement SSH encryption */
            log_error("SSH encryption not yet implemented");
            return -1;
            
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
            /* TODO: Implement TLS decryption */
            log_error("TLS decryption not yet implemented");
            return -1;
            
        case ENCRYPT_SSH:
            /* TODO: Implement SSH decryption */
            log_error("SSH decryption not yet implemented");
            return -1;
            
        default:
            log_error("Unknown encryption type: %d", instance->type);
            return -1;
    }
    
    return 0;
}

bool encrypt_is_ready(const struct encryption_instance *instance)
{
    return instance && instance->initialized && instance->ready;
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
            snprintf(info, info_size, "TLS encryption (not implemented)");
            break;
            
        case ENCRYPT_SSH:
            snprintf(info, info_size, "SSH encryption (not implemented)");
            break;
            
        default:
            snprintf(info, info_size, "Unknown encryption type: %d", instance->type);
            break;
    }
    
    return 0;
}