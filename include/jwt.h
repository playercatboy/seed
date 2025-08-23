/**
 * @file jwt.h
 * @brief JWT token generation and validation for Seed
 * @author Seed Development Team
 * @date 2025
 */

#ifndef JWT_H
#define JWT_H

#include "common.h"

/** Maximum JWT token length */
#define MAX_JWT_LENGTH 512

/**
 * @brief Generate JWT token from password
 *
 * @param[in]  password  The password to hash
 * @param[out] token     Buffer to store the generated token
 * @param[in]  token_len Maximum length of token buffer
 *
 * @return 0 on success, negative error code on failure
 */
int jwt_generate(const char *password, char *token, size_t token_len);

/**
 * @brief Verify password against JWT token
 *
 * @param[in] password  The password to verify
 * @param[in] token     The JWT token to verify against
 *
 * @return 0 if match, negative error code if no match or error
 */
int jwt_verify(const char *password, const char *token);

/**
 * @brief Hash password using SHA256
 *
 * @param[in]  password     The password to hash
 * @param[out] hash         Buffer to store the hash (32 bytes)
 * @param[out] hash_hex     Buffer to store hex string (65 bytes including null)
 *
 * @return 0 on success, negative error code on failure
 */
int jwt_hash_password(const char *password, unsigned char *hash, char *hash_hex);

#endif /* JWT_H */