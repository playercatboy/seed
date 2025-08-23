/**
 * @file tls_encrypt.h
 * @brief TLS encryption module for TCP proxy connections
 * @author Seed Development Team
 * @date 2025
 */

#ifndef TLS_ENCRYPT_H
#define TLS_ENCRYPT_H

#include "common.h"

#ifdef ENABLE_TLS_ENCRYPTION
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#ifdef ENABLE_UV_INTEGRATION
#include <uv.h>
#endif

/** TLS configuration */
struct tls_config {
    char cert_file[MAX_PATH_LENGTH];    /**< Certificate file path */
    char key_file[MAX_PATH_LENGTH];     /**< Private key file path */
    char ca_file[MAX_PATH_LENGTH];      /**< CA certificate file path */
    bool verify_peer;                   /**< Verify peer certificate */
    bool server_mode;                   /**< Server or client mode */
};

/** Forward declarations for OpenSSL types */
#ifdef ENABLE_TLS_ENCRYPTION
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;
typedef struct bio_st BIO;
#else
typedef void SSL_CTX;
typedef void SSL;
typedef void BIO;
#endif

#ifdef ENABLE_UV_INTEGRATION
typedef struct uv_buf_t tls_uv_buf_t;
#else
typedef struct {
    char* base;
    size_t len;
} tls_uv_buf_t;
#endif

/** TLS connection context */
struct tls_context {
    SSL_CTX *ssl_ctx;                  /**< OpenSSL context */
    SSL *ssl;                          /**< SSL connection */
    BIO *bio_in;                       /**< Input BIO */
    BIO *bio_out;                      /**< Output BIO */
    bool handshake_done;               /**< Handshake completion flag */
    tls_uv_buf_t pending_data;         /**< Pending encrypted data */
    size_t pending_size;               /**< Size of pending data */
};

/**
 * @brief Initialize TLS encryption module
 *
 * @return 0 on success, negative error code on failure
 */
int tls_encrypt_init(void);

/**
 * @brief Cleanup TLS encryption module
 */
void tls_encrypt_cleanup(void);

/**
 * @brief Create TLS context
 *
 * @param[in] config  TLS configuration
 * @param[out] ctx    TLS context to create
 *
 * @return 0 on success, negative error code on failure
 */
int tls_context_create(const struct tls_config *config, struct tls_context **ctx);

/**
 * @brief Destroy TLS context
 *
 * @param[in,out] ctx  TLS context to destroy
 */
void tls_context_destroy(struct tls_context *ctx);

/**
 * @brief Perform TLS handshake
 *
 * @param[in,out] ctx  TLS context
 * @param[in] data     Input data for handshake
 * @param[in] len      Length of input data
 * @param[out] output  Output buffer for handshake data
 * @param[out] out_len Length of output data
 *
 * @return 1 if handshake complete, 0 if more data needed, negative on error
 */
int tls_handshake(struct tls_context *ctx, const char *data, size_t len, 
                  char **output, size_t *out_len);

/**
 * @brief Encrypt data using TLS
 *
 * @param[in,out] ctx  TLS context
 * @param[in] plaintext Input plaintext data
 * @param[in] plain_len Length of plaintext
 * @param[out] ciphertext Output encrypted data buffer
 * @param[out] cipher_len Length of encrypted data
 *
 * @return 0 on success, negative error code on failure
 */
int tls_encrypt(struct tls_context *ctx, const char *plaintext, size_t plain_len,
                char **ciphertext, size_t *cipher_len);

/**
 * @brief Decrypt data using TLS
 *
 * @param[in,out] ctx  TLS context
 * @param[in] ciphertext Input encrypted data
 * @param[in] cipher_len Length of encrypted data
 * @param[out] plaintext Output decrypted data buffer
 * @param[out] plain_len Length of decrypted data
 *
 * @return 0 on success, negative error code on failure
 */
int tls_decrypt(struct tls_context *ctx, const char *ciphertext, size_t cipher_len,
                char **plaintext, size_t *plain_len);

/**
 * @brief Check if TLS context is ready for data transfer
 *
 * @param[in] ctx  TLS context
 *
 * @return true if ready, false otherwise
 */
bool tls_is_ready(const struct tls_context *ctx);

/**
 * @brief Get TLS connection information
 *
 * @param[in] ctx     TLS context
 * @param[out] cipher Current cipher suite
 * @param[in] cipher_size Size of cipher buffer
 * @param[out] version TLS version string
 * @param[in] version_size Size of version buffer
 *
 * @return 0 on success, negative error code on failure
 */
int tls_get_info(const struct tls_context *ctx, char *cipher, size_t cipher_size,
                 char *version, size_t version_size);

#endif /* TLS_ENCRYPT_H */