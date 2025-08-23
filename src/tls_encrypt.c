/**
 * @file tls_encrypt.c
 * @brief TLS encryption implementation for TCP proxy connections
 * @author Seed Development Team
 * @date 2025
 */

#include "tls_encrypt.h"
#include "log.h"
#include <string.h>
#include <stdlib.h>

#ifdef ENABLE_TLS_ENCRYPTION
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#endif

/* Static variables */
static bool tls_encrypt_initialized = false;

int tls_encrypt_init(void)
{
    if (tls_encrypt_initialized) {
        return 0;
    }
    
    log_debug("Initializing TLS encryption module");
    
#ifdef ENABLE_TLS_ENCRYPTION
    /* Initialize OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    
    log_info("TLS encryption module initialized with OpenSSL");
#else
    log_warning("TLS encryption module initialized in stub mode (OpenSSL not available)");
#endif
    
    tls_encrypt_initialized = true;
    return 0;
}

void tls_encrypt_cleanup(void)
{
    if (!tls_encrypt_initialized) {
        return;
    }
    
    log_debug("Cleaning up TLS encryption module");
    
#ifdef ENABLE_TLS_ENCRYPTION
    ERR_free_strings();
    EVP_cleanup();
#endif
    
    tls_encrypt_initialized = false;
}

int tls_context_create(const struct tls_config *config, struct tls_context **ctx)
{
    if (!config || !ctx) {
        log_error("Invalid arguments to tls_context_create");
        return SEED_ERROR_INVALID_ARGS;
    }
    
    if (!tls_encrypt_initialized) {
        log_error("TLS encryption module not initialized");
        return SEED_ERROR;
    }
    
#ifndef ENABLE_TLS_ENCRYPTION
    log_error("TLS encryption not available (compiled without OpenSSL support)");
    return SEED_ERROR_NOT_IMPLEMENTED;
#else
    
    struct tls_context *context = malloc(sizeof(struct tls_context));
    if (!context) {
        log_error("Failed to allocate TLS context");
        return SEED_ERROR_OUT_OF_MEMORY;
    }
    
    memset(context, 0, sizeof(struct tls_context));
    
    /* Create SSL context */
    const SSL_METHOD *method;
    if (config->server_mode) {
        method = TLS_server_method();
    } else {
        method = TLS_client_method();
    }
    
    context->ssl_ctx = SSL_CTX_new(method);
    if (!context->ssl_ctx) {
        log_error("Failed to create SSL context");
        free(context);
        return SEED_ERROR;
    }
    
    /* Set security level and cipher suites */
    SSL_CTX_set_security_level(context->ssl_ctx, 2);
    SSL_CTX_set_cipher_list(context->ssl_ctx, "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4");
    
    /* Load certificate and private key for server mode */
    if (config->server_mode) {
        if (strlen(config->cert_file) > 0) {
            if (SSL_CTX_use_certificate_file(context->ssl_ctx, config->cert_file, SSL_FILETYPE_PEM) != 1) {
                log_error("Failed to load certificate file: %s", config->cert_file);
                SSL_CTX_free(context->ssl_ctx);
                free(context);
                return SEED_ERROR_CONFIG;
            }
        }
        
        if (strlen(config->key_file) > 0) {
            if (SSL_CTX_use_PrivateKey_file(context->ssl_ctx, config->key_file, SSL_FILETYPE_PEM) != 1) {
                log_error("Failed to load private key file: %s", config->key_file);
                SSL_CTX_free(context->ssl_ctx);
                free(context);
                return SEED_ERROR_CONFIG;
            }
            
            /* Verify private key matches certificate */
            if (SSL_CTX_check_private_key(context->ssl_ctx) != 1) {
                log_error("Private key does not match certificate");
                SSL_CTX_free(context->ssl_ctx);
                free(context);
                return SEED_ERROR_CONFIG;
            }
        }
    }
    
    /* Load CA certificate for peer verification */
    if (strlen(config->ca_file) > 0) {
        if (SSL_CTX_load_verify_locations(context->ssl_ctx, config->ca_file, NULL) != 1) {
            log_error("Failed to load CA certificate file: %s", config->ca_file);
            SSL_CTX_free(context->ssl_ctx);
            free(context);
            return SEED_ERROR_CONFIG;
        }
    }
    
    /* Set verification mode */
    if (config->verify_peer) {
        int verify_mode = SSL_VERIFY_PEER;
        if (config->server_mode) {
            verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        }
        SSL_CTX_set_verify(context->ssl_ctx, verify_mode, NULL);
    } else {
        SSL_CTX_set_verify(context->ssl_ctx, SSL_VERIFY_NONE, NULL);
    }
    
    /* Create SSL connection */
    context->ssl = SSL_new(context->ssl_ctx);
    if (!context->ssl) {
        log_error("Failed to create SSL connection");
        SSL_CTX_free(context->ssl_ctx);
        free(context);
        return SEED_ERROR;
    }
    
    /* Create memory BIOs for non-blocking operation */
    context->bio_in = BIO_new(BIO_s_mem());
    context->bio_out = BIO_new(BIO_s_mem());
    if (!context->bio_in || !context->bio_out) {
        log_error("Failed to create SSL BIOs");
        if (context->bio_in) BIO_free(context->bio_in);
        if (context->bio_out) BIO_free(context->bio_out);
        SSL_free(context->ssl);
        SSL_CTX_free(context->ssl_ctx);
        free(context);
        return SEED_ERROR;
    }
    
    /* Set BIOs */
    SSL_set_bio(context->ssl, context->bio_in, context->bio_out);
    
    /* Set server/client mode */
    if (config->server_mode) {
        SSL_set_accept_state(context->ssl);
    } else {
        SSL_set_connect_state(context->ssl);
    }
    
    context->handshake_done = false;
    *ctx = context;
    
    log_debug("TLS context created in %s mode", config->server_mode ? "server" : "client");
    return 0;
    
#endif
}

void tls_context_destroy(struct tls_context *ctx)
{
    if (!ctx) {
        return;
    }
    
    log_debug("Destroying TLS context");
    
#ifdef ENABLE_TLS_ENCRYPTION
    if (ctx->ssl) {
        SSL_free(ctx->ssl);  /* This also frees the BIOs */
    }
    if (ctx->ssl_ctx) {
        SSL_CTX_free(ctx->ssl_ctx);
    }
    if (ctx->pending_data.base) {
        free(ctx->pending_data.base);
    }
#endif
    
    memset(ctx, 0, sizeof(struct tls_context));
    free(ctx);
}

int tls_handshake(struct tls_context *ctx, const char *data, size_t len,
                  char **output, size_t *out_len)
{
    if (!ctx || !output || !out_len) {
        log_error("Invalid arguments to tls_handshake");
        return SEED_ERROR_INVALID_ARGS;
    }
    
    *output = NULL;
    *out_len = 0;
    
#ifndef ENABLE_TLS_ENCRYPTION
    log_error("TLS handshake not available (compiled without OpenSSL support)");
    return SEED_ERROR_NOT_IMPLEMENTED;
#else
    
    if (ctx->handshake_done) {
        return 1;  /* Handshake already complete */
    }
    
    /* Feed input data to SSL */
    if (data && len > 0) {
        int written = BIO_write(ctx->bio_in, data, (int)len);
        if (written <= 0) {
            log_error("Failed to write data to SSL input BIO");
            return SEED_ERROR;
        }
        log_debug("Fed %d bytes to TLS handshake", written);
    }
    
    /* Perform handshake */
    int handshake_ret = SSL_do_handshake(ctx->ssl);
    int ssl_error = SSL_get_error(ctx->ssl, handshake_ret);
    
    /* Check for output data */
    int pending = BIO_pending(ctx->bio_out);
    if (pending > 0) {
        *output = malloc(pending);
        if (!*output) {
            log_error("Failed to allocate memory for TLS handshake output");
            return SEED_ERROR_OUT_OF_MEMORY;
        }
        
        int read = BIO_read(ctx->bio_out, *output, pending);
        if (read > 0) {
            *out_len = read;
            log_debug("Generated %d bytes of TLS handshake data", read);
        } else {
            free(*output);
            *output = NULL;
            *out_len = 0;
        }
    }
    
    /* Check handshake status */
    if (handshake_ret == 1) {
        ctx->handshake_done = true;
        log_info("TLS handshake completed successfully");
        return 1;  /* Handshake complete */
    }
    
    if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
        log_debug("TLS handshake needs more data");
        return 0;  /* Need more data */
    }
    
    /* Handshake error */
    char err_buf[256];
    ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
    log_error("TLS handshake failed: %s", err_buf);
    return SEED_ERROR;
    
#endif
}

int tls_encrypt(struct tls_context *ctx, const char *plaintext, size_t plain_len,
                char **ciphertext, size_t *cipher_len)
{
    if (!ctx || !plaintext || !ciphertext || !cipher_len) {
        log_error("Invalid arguments to tls_encrypt");
        return SEED_ERROR_INVALID_ARGS;
    }
    
    *ciphertext = NULL;
    *cipher_len = 0;
    
#ifndef ENABLE_TLS_ENCRYPTION
    log_error("TLS encryption not available (compiled without OpenSSL support)");
    return SEED_ERROR_NOT_IMPLEMENTED;
#else
    
    if (!ctx->handshake_done) {
        log_error("TLS handshake not complete");
        return SEED_ERROR;
    }
    
    /* Write plaintext to SSL */
    int written = SSL_write(ctx->ssl, plaintext, (int)plain_len);
    if (written <= 0) {
        int ssl_error = SSL_get_error(ctx->ssl, written);
        if (ssl_error == SSL_ERROR_WANT_WRITE || ssl_error == SSL_ERROR_WANT_READ) {
            log_debug("TLS encrypt would block");
            return 0;  /* Would block */
        }
        
        char err_buf[256];
        ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
        log_error("TLS encryption failed: %s", err_buf);
        return SEED_ERROR;
    }
    
    /* Read encrypted data from output BIO */
    int pending = BIO_pending(ctx->bio_out);
    if (pending > 0) {
        *ciphertext = malloc(pending);
        if (!*ciphertext) {
            log_error("Failed to allocate memory for encrypted data");
            return SEED_ERROR_OUT_OF_MEMORY;
        }
        
        int read = BIO_read(ctx->bio_out, *ciphertext, pending);
        if (read > 0) {
            *cipher_len = read;
            log_debug("Encrypted %d bytes to %zu bytes", written, *cipher_len);
            return 0;
        } else {
            free(*ciphertext);
            *ciphertext = NULL;
        }
    }
    
    log_debug("TLS encryption generated no output data");
    return 0;
    
#endif
}

int tls_decrypt(struct tls_context *ctx, const char *ciphertext, size_t cipher_len,
                char **plaintext, size_t *plain_len)
{
    if (!ctx || !ciphertext || !plaintext || !plain_len) {
        log_error("Invalid arguments to tls_decrypt");
        return SEED_ERROR_INVALID_ARGS;
    }
    
    *plaintext = NULL;
    *plain_len = 0;
    
#ifndef ENABLE_TLS_ENCRYPTION
    log_error("TLS decryption not available (compiled without OpenSSL support)");
    return SEED_ERROR_NOT_IMPLEMENTED;
#else
    
    if (!ctx->handshake_done) {
        log_error("TLS handshake not complete");
        return SEED_ERROR;
    }
    
    /* Feed ciphertext to SSL */
    int written = BIO_write(ctx->bio_in, ciphertext, (int)cipher_len);
    if (written <= 0) {
        log_error("Failed to write ciphertext to SSL input BIO");
        return SEED_ERROR;
    }
    
    /* Try to read decrypted data */
    char buffer[8192];  /* Buffer for decrypted data */
    int read = SSL_read(ctx->ssl, buffer, sizeof(buffer));
    
    if (read > 0) {
        *plaintext = malloc(read);
        if (!*plaintext) {
            log_error("Failed to allocate memory for decrypted data");
            return SEED_ERROR_OUT_OF_MEMORY;
        }
        
        memcpy(*plaintext, buffer, read);
        *plain_len = read;
        log_debug("Decrypted %zu bytes to %d bytes", cipher_len, read);
        return 0;
    }
    
    if (read == 0) {
        log_debug("TLS connection closed by peer");
        return SEED_ERROR_CONNECTION_CLOSED;
    }
    
    /* Check for SSL errors */
    int ssl_error = SSL_get_error(ctx->ssl, read);
    if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
        log_debug("TLS decrypt would block");
        return 0;  /* Would block, need more data */
    }
    
    char err_buf[256];
    ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
    log_error("TLS decryption failed: %s", err_buf);
    return SEED_ERROR;
    
#endif
}

bool tls_is_ready(const struct tls_context *ctx)
{
    if (!ctx) {
        return false;
    }
    
#ifdef ENABLE_TLS_ENCRYPTION
    return ctx->handshake_done;
#else
    return false;
#endif
}

int tls_get_info(const struct tls_context *ctx, char *cipher, size_t cipher_size,
                 char *version, size_t version_size)
{
    if (!ctx || !cipher || !version) {
        log_error("Invalid arguments to tls_get_info");
        return SEED_ERROR_INVALID_ARGS;
    }
    
#ifndef ENABLE_TLS_ENCRYPTION
    snprintf(cipher, cipher_size, "TLS not available");
    snprintf(version, version_size, "N/A");
    return SEED_ERROR_NOT_IMPLEMENTED;
#else
    
    if (!ctx->handshake_done) {
        snprintf(cipher, cipher_size, "Handshake incomplete");
        snprintf(version, version_size, "N/A");
        return SEED_ERROR;
    }
    
    /* Get cipher suite */
    const char *cipher_name = SSL_get_cipher(ctx->ssl);
    if (cipher_name) {
        snprintf(cipher, cipher_size, "%s", cipher_name);
    } else {
        snprintf(cipher, cipher_size, "Unknown");
    }
    
    /* Get TLS version */
    const char *version_name = SSL_get_version(ctx->ssl);
    if (version_name) {
        snprintf(version, version_size, "%s", version_name);
    } else {
        snprintf(version, version_size, "Unknown");
    }
    
    return 0;
    
#endif
}