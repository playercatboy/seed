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

int auth_db_load_encrypted(const char *filename, const char *password, struct auth_db *db)
{
    FILE *file;
    uint8_t *encrypted_data = NULL;
    char *decrypted_data = NULL;
    size_t file_size, data_size;
    struct table_encrypt_context *ctx = NULL;
    int ret = SEED_ERROR;
    
    /* Magic header for validation */
    const char magic_header[] = "SEED_AUTH_ENC_V1\n";
    
    if (!filename || !password || !db) {
        log_error("Invalid arguments to auth_db_load_encrypted");
        return SEED_ERROR_INVALID_ARGS;
    }
    
    /* Initialize table encryption */
    ret = table_encrypt_init();
    if (ret != 0) {
        log_error("Failed to initialize table encryption");
        return SEED_ERROR;
    }
    
    /* Create encryption context */
    ret = table_context_create(password, &ctx);
    if (ret != 0) {
        log_error("Failed to create encryption context for auth file");
        return SEED_ERROR;
    }
    
    /* Open encrypted file */
    file = fopen(filename, "rb");
    if (!file) {
        log_error("Failed to open encrypted auth file: %s", filename);
        table_context_destroy(ctx);
        return SEED_ERROR_FILE_NOT_FOUND;
    }
    
    /* Get file size */
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (file_size == 0) {
        log_warning("Empty encrypted auth file: %s", filename);
        auth_db_init(db);
        fclose(file);
        table_context_destroy(ctx);
        return SEED_OK;
    }
    
    /* Allocate buffer for encrypted data */
    encrypted_data = malloc(file_size);
    if (!encrypted_data) {
        log_error("Failed to allocate memory for encrypted auth data");
        fclose(file);
        table_context_destroy(ctx);
        return SEED_ERROR_OUT_OF_MEMORY;
    }
    
    /* Read encrypted data */
    data_size = fread(encrypted_data, 1, file_size, file);
    fclose(file);
    
    if (data_size != file_size) {
        log_error("Failed to read complete encrypted auth file");
        free(encrypted_data);
        table_context_destroy(ctx);
        return SEED_ERROR_CONFIG;
    }
    
    /* Decrypt data in-place */
    ret = table_decrypt_data(ctx, encrypted_data, data_size);
    if (ret != 0) {
        log_error("Failed to decrypt auth file data");
        free(encrypted_data);
        table_context_destroy(ctx);
        return SEED_ERROR;
    }
    
    /* Null-terminate the decrypted data */
    decrypted_data = malloc(data_size + 1);
    if (!decrypted_data) {
        log_error("Failed to allocate memory for decrypted auth data");
        free(encrypted_data);
        table_context_destroy(ctx);
        return SEED_ERROR_OUT_OF_MEMORY;
    }
    
    memcpy(decrypted_data, encrypted_data, data_size);
    decrypted_data[data_size] = '\0';
    
    /* Clean up encrypted data */
    memset(encrypted_data, 0, data_size);
    free(encrypted_data);
    table_context_destroy(ctx);
    
    /* Validate magic header */
    if (strlen(decrypted_data) < strlen(magic_header) || 
        memcmp(decrypted_data, magic_header, strlen(magic_header)) != 0) {
        log_error("Invalid magic header in encrypted auth file (wrong password?)");
        memset(decrypted_data, 0, strlen(decrypted_data));
        free(decrypted_data);
        return SEED_ERROR_AUTH_FAILED;
    }
    
    /* Parse decrypted data */
    auth_db_init(db);
    
    /* Skip magic header */
    char *line_start = decrypted_data + strlen(magic_header);
    char *line_end;
    int line_num = 0;
    
    while (line_start && *line_start) {
        line_num++;
        line_end = strchr(line_start, '\n');
        
        if (line_end) {
            *line_end = '\0';
        }
        
        /* Remove carriage return if present */
        char *cr = strchr(line_start, '\r');
        if (cr) *cr = '\0';
        
        /* Skip empty lines and comments */
        if (*line_start != '\0' && *line_start != '#' && *line_start != ';') {
            char *colon = strchr(line_start, ':');
            if (colon) {
                *colon = '\0';
                char *username = trim_whitespace(line_start);
                char *token = trim_whitespace(colon + 1);
                
                if (strlen(username) > 0 && strlen(token) > 0) {
                    ret = auth_db_add_user(db, username, token);
                    if (ret != SEED_OK) {
                        log_warning("Failed to add user '%s' from encrypted auth file", username);
                    }
                }
            } else {
                log_warning("Invalid auth entry at line %d in encrypted file (missing colon)", line_num);
            }
        }
        
        if (!line_end) break;
        line_start = line_end + 1;
    }
    
    /* Clean up decrypted data */
    memset(decrypted_data, 0, strlen(decrypted_data));
    free(decrypted_data);
    
    log_info("Loaded encrypted auth file with %d users", db->user_count);
    return SEED_OK;
}

int auth_db_save_encrypted(const char *filename, const char *password, const struct auth_db *db)
{
    FILE *file;
    char *plaintext_data = NULL;
    uint8_t *encrypted_data = NULL;
    size_t data_len, total_len = 0;
    struct table_encrypt_context *ctx = NULL;
    int ret = SEED_ERROR;
    
    /* Magic header for validation */
    const char magic_header[] = "SEED_AUTH_ENC_V1\n";
    
    if (!filename || !password || !db) {
        log_error("Invalid arguments to auth_db_save_encrypted");
        return SEED_ERROR_INVALID_ARGS;
    }
    
    /* Initialize table encryption */
    ret = table_encrypt_init();
    if (ret != 0) {
        log_error("Failed to initialize table encryption");
        return SEED_ERROR;
    }
    
    /* Create encryption context */
    ret = table_context_create(password, &ctx);
    if (ret != 0) {
        log_error("Failed to create encryption context for auth file");
        return SEED_ERROR;
    }
    
    /* Calculate required buffer size */
    total_len = strlen(magic_header);
    for (int i = 0; i < db->user_count; i++) {
        total_len += strlen(db->users[i].username) + strlen(db->users[i].token) + 3; /* username: token\n */
    }
    
    if (total_len == strlen(magic_header)) {
        /* Only header, no users */
        total_len = strlen(magic_header);
    }
    
    /* Allocate buffer for plaintext data */
    plaintext_data = malloc(total_len + 1);
    if (!plaintext_data) {
        log_error("Failed to allocate memory for auth plaintext");
        table_context_destroy(ctx);
        return SEED_ERROR_OUT_OF_MEMORY;
    }
    
    /* Build plaintext content with magic header */
    strcpy(plaintext_data, magic_header);
    for (int i = 0; i < db->user_count; i++) {
        char line[512];
        snprintf(line, sizeof(line), "%s: %s\n", 
                db->users[i].username, db->users[i].token);
        strcat(plaintext_data, line);
    }
    
    data_len = strlen(plaintext_data);
    
    /* Allocate buffer for encrypted data */
    encrypted_data = malloc(data_len);
    if (!encrypted_data) {
        log_error("Failed to allocate memory for encrypted auth data");
        memset(plaintext_data, 0, strlen(plaintext_data));
        free(plaintext_data);
        table_context_destroy(ctx);
        return SEED_ERROR_OUT_OF_MEMORY;
    }
    
    /* Encrypt data */
    ret = table_encrypt_copy(ctx, (const uint8_t*)plaintext_data, encrypted_data, data_len);
    if (ret != 0) {
        log_error("Failed to encrypt auth file data");
        memset(plaintext_data, 0, strlen(plaintext_data));
        free(plaintext_data);
        free(encrypted_data);
        table_context_destroy(ctx);
        return SEED_ERROR;
    }
    
    /* Clean up plaintext data */
    memset(plaintext_data, 0, strlen(plaintext_data));
    free(plaintext_data);
    table_context_destroy(ctx);
    
    /* Write encrypted data to file */
    file = fopen(filename, "wb");
    if (!file) {
        log_error("Failed to create encrypted auth file: %s", filename);
        memset(encrypted_data, 0, data_len);
        free(encrypted_data);
        return SEED_ERROR_CONFIG;
    }
    
    size_t written = fwrite(encrypted_data, 1, data_len, file);
    fclose(file);
    
    /* Clean up encrypted data */
    memset(encrypted_data, 0, data_len);
    free(encrypted_data);
    
    if (written != data_len) {
        log_error("Failed to write complete encrypted auth file");
        return SEED_ERROR_CONFIG;
    }
    
    log_info("Saved encrypted auth file with %d users", db->user_count);
    return SEED_OK;
}