/**
 * @file table_encrypt.h
 * @brief Table-based encryption module for UDP proxy packets
 * @author Seed Development Team
 * @date 2025
 */

#ifndef TABLE_ENCRYPT_H
#define TABLE_ENCRYPT_H

#include "common.h"

/** Table encryption key size (256 bytes for full byte mapping) */
#define TABLE_KEY_SIZE 256

/** Table encryption context */
struct table_encrypt_context {
    uint8_t encrypt_table[TABLE_KEY_SIZE]; /**< Encryption lookup table */
    uint8_t decrypt_table[TABLE_KEY_SIZE]; /**< Decryption lookup table */
    bool initialized;                      /**< Context initialization status */
};

/**
 * @brief Initialize table encryption module
 *
 * @return 0 on success, negative error code on failure
 */
int table_encrypt_init(void);

/**
 * @brief Cleanup table encryption module
 */
void table_encrypt_cleanup(void);

/**
 * @brief Create table encryption context from password
 *
 * @param[in] password Password to generate encryption table from
 * @param[out] ctx     Table encryption context to create
 *
 * @return 0 on success, negative error code on failure
 */
int table_context_create(const char *password, struct table_encrypt_context **ctx);

/**
 * @brief Create table encryption context from raw key
 *
 * @param[in] key      Raw 256-byte key for encryption table
 * @param[out] ctx     Table encryption context to create
 *
 * @return 0 on success, negative error code on failure
 */
int table_context_create_from_key(const uint8_t key[TABLE_KEY_SIZE], 
                                  struct table_encrypt_context **ctx);

/**
 * @brief Destroy table encryption context
 *
 * @param[in,out] ctx  Table encryption context to destroy
 */
void table_context_destroy(struct table_encrypt_context *ctx);

/**
 * @brief Encrypt data using table encryption (in-place)
 *
 * @param[in,out] ctx  Table encryption context
 * @param[in,out] data Data to encrypt (modified in-place)
 * @param[in] len      Length of data
 *
 * @return 0 on success, negative error code on failure
 */
int table_encrypt_data(struct table_encrypt_context *ctx, uint8_t *data, size_t len);

/**
 * @brief Decrypt data using table encryption (in-place)
 *
 * @param[in,out] ctx  Table encryption context
 * @param[in,out] data Data to decrypt (modified in-place)
 * @param[in] len      Length of data
 *
 * @return 0 on success, negative error code on failure
 */
int table_decrypt_data(struct table_encrypt_context *ctx, uint8_t *data, size_t len);

/**
 * @brief Copy encrypt data using table encryption (not in-place)
 *
 * @param[in] ctx      Table encryption context
 * @param[in] input    Input data to encrypt
 * @param[out] output  Output buffer for encrypted data
 * @param[in] len      Length of data
 *
 * @return 0 on success, negative error code on failure
 */
int table_encrypt_copy(const struct table_encrypt_context *ctx, 
                       const uint8_t *input, uint8_t *output, size_t len);

/**
 * @brief Copy decrypt data using table encryption (not in-place)
 *
 * @param[in] ctx      Table encryption context
 * @param[in] input    Input data to decrypt
 * @param[out] output  Output buffer for decrypted data
 * @param[in] len      Length of data
 *
 * @return 0 on success, negative error code on failure
 */
int table_decrypt_copy(const struct table_encrypt_context *ctx, 
                       const uint8_t *input, uint8_t *output, size_t len);

/**
 * @brief Generate encryption table from password using SHA-256
 *
 * @param[in] password Password to derive key from
 * @param[out] table   256-byte encryption table
 *
 * @return 0 on success, negative error code on failure
 */
int table_generate_from_password(const char *password, uint8_t table[TABLE_KEY_SIZE]);

/**
 * @brief Generate random encryption table
 *
 * @param[out] table   256-byte encryption table
 *
 * @return 0 on success, negative error code on failure
 */
int table_generate_random(uint8_t table[TABLE_KEY_SIZE]);

/**
 * @brief Validate encryption table (ensure all bytes 0-255 are present once)
 *
 * @param[in] table    256-byte encryption table to validate
 *
 * @return true if valid, false otherwise
 */
bool table_validate(const uint8_t table[TABLE_KEY_SIZE]);

/**
 * @brief Create inverse/decrypt table from encrypt table
 *
 * @param[in] encrypt_table 256-byte encryption table
 * @param[out] decrypt_table 256-byte decryption table
 *
 * @return 0 on success, negative error code on failure
 */
int table_create_inverse(const uint8_t encrypt_table[TABLE_KEY_SIZE], 
                         uint8_t decrypt_table[TABLE_KEY_SIZE]);

/**
 * @brief Export encryption table to base64 string
 *
 * @param[in] table    256-byte encryption table
 * @param[out] base64  Base64 encoded table string
 * @param[in] base64_size Size of base64 buffer (should be at least 344 bytes)
 *
 * @return 0 on success, negative error code on failure
 */
int table_export_base64(const uint8_t table[TABLE_KEY_SIZE], 
                        char *base64, size_t base64_size);

/**
 * @brief Import encryption table from base64 string
 *
 * @param[in] base64   Base64 encoded table string
 * @param[out] table   256-byte encryption table
 *
 * @return 0 on success, negative error code on failure
 */
int table_import_base64(const char *base64, uint8_t table[TABLE_KEY_SIZE]);

#endif /* TABLE_ENCRYPT_H */