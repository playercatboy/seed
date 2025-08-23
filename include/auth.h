/**
 * @file auth.h
 * @brief Authentication management for Seed
 * @author Seed Development Team
 * @date 2025
 */

#ifndef AUTH_H
#define AUTH_H

#include "common.h"

/** Maximum number of users */
#define MAX_USERS 100

/** User credential structure */
struct user_credential {
    char username[64];     /** Username */
    char token[MAX_TOKEN_LENGTH]; /** JWT token */
};

/** Authentication database structure */
struct auth_db {
    struct user_credential users[MAX_USERS]; /** User array */
    int user_count;                          /** Number of users */
};

/**
 * @brief Initialize authentication database
 *
 * @param[out] db  Database structure to initialize
 */
void auth_db_init(struct auth_db *db);

/**
 * @brief Load authentication database from file
 *
 * @param[in]  filename  Authentication file path
 * @param[out] db        Database structure to fill
 *
 * @return 0 on success, negative error code on failure
 */
int auth_db_load(const char *filename, struct auth_db *db);

/**
 * @brief Save authentication database to file
 *
 * @param[in] filename  Authentication file path
 * @param[in] db        Database structure to save
 *
 * @return 0 on success, negative error code on failure
 */
int auth_db_save(const char *filename, const struct auth_db *db);

/**
 * @brief Add user to database
 *
 * @param[in,out] db       Database structure
 * @param[in]     username Username
 * @param[in]     token    JWT token
 *
 * @return 0 on success, negative error code on failure
 */
int auth_db_add_user(struct auth_db *db, const char *username, const char *token);

/**
 * @brief Authenticate user
 *
 * @param[in] db       Database structure
 * @param[in] username Username
 * @param[in] password Password to verify
 *
 * @return 0 if authenticated, negative error code if not
 */
int auth_db_authenticate(const struct auth_db *db, const char *username, const char *password);

/**
 * @brief Find user by username
 *
 * @param[in]  db       Database structure
 * @param[in]  username Username to find
 * @param[out] user     User credential if found
 *
 * @return 0 if found, negative error code if not
 */
int auth_db_find_user(const struct auth_db *db, const char *username, struct user_credential *user);

/**
 * @brief Free authentication database resources
 *
 * @param[in,out] db  Database to free
 */
void auth_db_free(struct auth_db *db);

#endif /* AUTH_H */