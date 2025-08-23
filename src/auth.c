/**
 * @file auth.c
 * @brief Authentication management implementation
 * @author Seed Development Team
 * @date 2025
 */

#include "auth.h"
#include "jwt.h"
#include "log.h"
#include <ctype.h>

/**
 * @brief Trim whitespace from string
 *
 * @param[in,out] str  String to trim
 *
 * @return Trimmed string pointer
 */
static char *trim_whitespace(char *str)
{
    char *end;
    
    /* Trim leading whitespace */
    while (isspace((unsigned char)*str)) str++;
    
    /* All whitespace */
    if (*str == 0) return str;
    
    /* Trim trailing whitespace */
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    
    /* Write new null terminator */
    end[1] = '\0';
    
    return str;
}

/**
 * @brief Initialize authentication database
 *
 * @param[out] db  Database structure to initialize
 */
void auth_db_init(struct auth_db *db)
{
    if (!db) return;
    
    memset(db, 0, sizeof(struct auth_db));
    db->user_count = 0;
}

/**
 * @brief Load authentication database from file
 *
 * @param[in]  filename  Authentication file path
 * @param[out] db        Database structure to fill
 *
 * @return 0 on success, negative error code on failure
 */
int auth_db_load(const char *filename, struct auth_db *db)
{
    FILE *file;
    char line[MAX_LINE_LENGTH];
    char *username, *token, *colon;
    int line_num = 0;
    
    if (!filename || !db) {
        return SEED_ERROR_INVALID_ARGS;
    }
    
    /* Initialize database */
    auth_db_init(db);
    
    /* Open file */
    file = fopen(filename, "r");
    if (!file) {
        log_error("Failed to open authentication file: %s", filename);
        return SEED_ERROR_FILE_NOT_FOUND;
    }
    
    /* Read line by line */
    while (fgets(line, sizeof(line), file)) {
        line_num++;
        
        /* Remove newline */
        line[strcspn(line, "\r\n")] = '\0';
        
        /* Skip empty lines and comments */
        if (line[0] == '\0' || line[0] == '#' || line[0] == ';') {
            continue;
        }
        
        /* Find colon separator */
        colon = strchr(line, ':');
        if (!colon) {
            log_warning("Invalid auth entry at line %d (missing colon)", line_num);
            continue;
        }
        
        /* Split username and token */
        *colon = '\0';
        username = trim_whitespace(line);
        token = trim_whitespace(colon + 1);
        
        /* Validate username and token */
        if (strlen(username) == 0 || strlen(token) == 0) {
            log_warning("Invalid auth entry at line %d (empty username or token)", line_num);
            continue;
        }
        
        /* Add user to database */
        if (db->user_count >= MAX_USERS) {
            log_warning("Maximum user limit reached (%d), ignoring remaining entries", MAX_USERS);
            break;
        }
        
        strncpy(db->users[db->user_count].username, username, 
                sizeof(db->users[db->user_count].username) - 1);
        strncpy(db->users[db->user_count].token, token, 
                sizeof(db->users[db->user_count].token) - 1);
        
        db->user_count++;
        
        log_debug("Loaded user: %s", username);
    }
    
    fclose(file);
    
    log_info("Loaded %d users from authentication file", db->user_count);
    
    return SEED_OK;
}

/**
 * @brief Save authentication database to file
 *
 * @param[in] filename  Authentication file path
 * @param[in] db        Database structure to save
 *
 * @return 0 on success, negative error code on failure
 */
int auth_db_save(const char *filename, const struct auth_db *db)
{
    FILE *file;
    int i;
    
    if (!filename || !db) {
        return SEED_ERROR_INVALID_ARGS;
    }
    
    /* Open file for writing */
    file = fopen(filename, "w");
    if (!file) {
        log_error("Failed to open authentication file for writing: %s", filename);
        return SEED_ERROR_PERMISSION_DENIED;
    }
    
    /* Write header comment */
    fprintf(file, "# Seed Authentication Database\n");
    fprintf(file, "# Format: username: jwt-token\n");
    fprintf(file, "#\n");
    
    /* Write each user */
    for (i = 0; i < db->user_count; i++) {
        fprintf(file, "%s: %s\n", 
                db->users[i].username, 
                db->users[i].token);
    }
    
    fclose(file);
    
    log_info("Saved %d users to authentication file", db->user_count);
    
    return SEED_OK;
}

/**
 * @brief Add user to database
 *
 * @param[in,out] db       Database structure
 * @param[in]     username Username
 * @param[in]     token    JWT token
 *
 * @return 0 on success, negative error code on failure
 */
int auth_db_add_user(struct auth_db *db, const char *username, const char *token)
{
    int i;
    
    if (!db || !username || !token) {
        return SEED_ERROR_INVALID_ARGS;
    }
    
    /* Check if user already exists */
    for (i = 0; i < db->user_count; i++) {
        if (strcmp(db->users[i].username, username) == 0) {
            /* Update existing user's token */
            strncpy(db->users[i].token, token, 
                    sizeof(db->users[i].token) - 1);
            log_info("Updated token for user: %s", username);
            return SEED_OK;
        }
    }
    
    /* Check if database is full */
    if (db->user_count >= MAX_USERS) {
        log_error("Cannot add user: database is full");
        return SEED_ERROR_OUT_OF_MEMORY;
    }
    
    /* Add new user */
    strncpy(db->users[db->user_count].username, username, 
            sizeof(db->users[db->user_count].username) - 1);
    strncpy(db->users[db->user_count].token, token, 
            sizeof(db->users[db->user_count].token) - 1);
    
    db->user_count++;
    
    log_info("Added new user: %s", username);
    
    return SEED_OK;
}

/**
 * @brief Authenticate user
 *
 * @param[in] db       Database structure
 * @param[in] username Username
 * @param[in] password Password to verify
 *
 * @return 0 if authenticated, negative error code if not
 */
int auth_db_authenticate(const struct auth_db *db, const char *username, const char *password)
{
    struct user_credential user;
    
    if (!db || !username || !password) {
        return SEED_ERROR_INVALID_ARGS;
    }
    
    /* Find user */
    if (auth_db_find_user(db, username, &user) != SEED_OK) {
        log_warning("Authentication failed: user '%s' not found", username);
        return SEED_ERROR_AUTH_FAILED;
    }
    
    /* Verify password against token */
    if (jwt_verify(password, user.token) != SEED_OK) {
        log_warning("Authentication failed: invalid password for user '%s'", username);
        return SEED_ERROR_AUTH_FAILED;
    }
    
    log_info("User '%s' authenticated successfully", username);
    
    return SEED_OK;
}

/**
 * @brief Find user by username
 *
 * @param[in]  db       Database structure
 * @param[in]  username Username to find
 * @param[out] user     User credential if found
 *
 * @return 0 if found, negative error code if not
 */
int auth_db_find_user(const struct auth_db *db, const char *username, struct user_credential *user)
{
    int i;
    
    if (!db || !username || !user) {
        return SEED_ERROR_INVALID_ARGS;
    }
    
    /* Search for user */
    for (i = 0; i < db->user_count; i++) {
        if (strcmp(db->users[i].username, username) == 0) {
            /* Found user */
            memcpy(user, &db->users[i], sizeof(struct user_credential));
            return SEED_OK;
        }
    }
    
    return SEED_ERROR_AUTH_FAILED;
}

/**
 * @brief Free authentication database resources
 *
 * @param[in,out] db  Database to free
 */
void auth_db_free(struct auth_db *db)
{
    if (db) {
        memset(db, 0, sizeof(struct auth_db));
    }
}