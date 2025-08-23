/**
 * @file encrypt.h
 * @brief Main encryption manager for Seed reverse proxy
 * @author Seed Development Team
 * @date 2025
 */

#ifndef ENCRYPT_H
#define ENCRYPT_H

#include "common.h"
#include "config.h"
#include "tls_encrypt.h"
#include "ssh_encrypt.h"
#include "table_encrypt.h"

/** Forward declarations */
struct proxy_connection;

/** Generic encryption context union */
union encrypt_context {
    struct tls_context *tls;           /**< TLS context */
    struct ssh_context *ssh;           /**< SSH context */
    struct table_encrypt_context *table; /**< Table context */
};

/** Encryption instance for a proxy connection */
struct encryption_instance {
    enum encrypt_impl type;            /**< Encryption type */
    union encrypt_context ctx;         /**< Encryption context */
    bool initialized;                  /**< Initialization status */
    bool ready;                        /**< Ready for data transfer */
};

/**
 * @brief Initialize encryption subsystem
 *
 * @return 0 on success, negative error code on failure
 */
int encrypt_init(void);

/**
 * @brief Cleanup encryption subsystem
 */
void encrypt_cleanup(void);

/**
 * @brief Create encryption instance for proxy connection
 *
 * @param[in] proxy_config Proxy configuration
 * @param[out] instance    Encryption instance to create
 *
 * @return 0 on success, negative error code on failure
 */
int encrypt_create_instance(const struct proxy_config *proxy_config, 
                            struct encryption_instance **instance);

/**
 * @brief Destroy encryption instance
 *
 * @param[in,out] instance Encryption instance to destroy
 */
void encrypt_destroy_instance(struct encryption_instance *instance);

/**
 * @brief Initialize encryption for connection
 *
 * @param[in,out] instance Encryption instance
 * @param[in] connection   Proxy connection
 *
 * @return 0 on success, negative error code on failure
 */
int encrypt_init_connection(struct encryption_instance *instance, 
                           struct proxy_connection *connection);

/**
 * @brief Process handshake data for connection encryption
 *
 * @param[in,out] instance Encryption instance
 * @param[in] input        Input handshake data
 * @param[in] input_len    Length of input data
 * @param[out] output      Output handshake data
 * @param[out] output_len  Length of output data
 *
 * @return 1 if handshake complete, 0 if more data needed, negative on error
 */
int encrypt_process_handshake(struct encryption_instance *instance,
                              const char *input, size_t input_len,
                              char **output, size_t *output_len);

/**
 * @brief Encrypt data for transmission
 *
 * @param[in,out] instance Encryption instance
 * @param[in] plaintext    Input plaintext data
 * @param[in] plain_len    Length of plaintext
 * @param[out] ciphertext  Output encrypted data
 * @param[out] cipher_len  Length of encrypted data
 *
 * @return 0 on success, negative error code on failure
 */
int encrypt_data(struct encryption_instance *instance,
                 const char *plaintext, size_t plain_len,
                 char **ciphertext, size_t *cipher_len);

/**
 * @brief Decrypt received data
 *
 * @param[in,out] instance Encryption instance
 * @param[in] ciphertext   Input encrypted data
 * @param[in] cipher_len   Length of encrypted data
 * @param[out] plaintext   Output decrypted data
 * @param[out] plain_len   Length of decrypted data
 *
 * @return 0 on success, negative error code on failure
 */
int decrypt_data(struct encryption_instance *instance,
                 const char *ciphertext, size_t cipher_len,
                 char **plaintext, size_t *plain_len);

/**
 * @brief Check if encryption instance is ready for data transfer
 *
 * @param[in] instance Encryption instance
 *
 * @return true if ready, false otherwise
 */
bool encrypt_is_ready(const struct encryption_instance *instance);

/**
 * @brief Get encryption information string
 *
 * @param[in] instance  Encryption instance
 * @param[out] info     Information buffer
 * @param[in] info_size Size of info buffer
 *
 * @return 0 on success, negative error code on failure
 */
int encrypt_get_info(const struct encryption_instance *instance,
                     char *info, size_t info_size);

/**
 * @brief Get encryption type string
 *
 * @param[in] type Encryption type
 *
 * @return String representation of encryption type
 */
const char *encrypt_type_string(enum encrypt_impl type);

#endif /* ENCRYPT_H */