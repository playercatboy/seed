/**
 * @file config.c
 * @brief Configuration management implementation
 * @author Seed Development Team
 * @date 2025
 */

#include "config.h"
#include "log.h"
#include "inih/ini.h"
#include <ctype.h>

/** Current section being parsed */
static char current_section[64] = {0};

/** Current proxy index being configured */
static int current_proxy_index = -1;

/**
 * @brief Convert string to lowercase
 *
 * @param[in,out] str  String to convert
 */
static void str_tolower(char *str)
{
    if (!str) return;
    while (*str) {
        *str = tolower((unsigned char)*str);
        str++;
    }
}

/**
 * @brief Parse boolean value from string
 *
 * @param[in] value  String value
 *
 * @return true or false
 */
static bool parse_bool(const char *value)
{
    char lower[32];
    strncpy(lower, value, sizeof(lower) - 1);
    lower[sizeof(lower) - 1] = '\0';
    str_tolower(lower);
    
    return (strcmp(lower, "true") == 0 || 
            strcmp(lower, "yes") == 0 || 
            strcmp(lower, "1") == 0);
}

/**
 * @brief Parse log level from string
 *
 * @param[in] value  String value
 *
 * @return Log level enum value
 */
static enum log_level parse_log_level(const char *value)
{
    char lower[32];
    strncpy(lower, value, sizeof(lower) - 1);
    lower[sizeof(lower) - 1] = '\0';
    str_tolower(lower);
    
    if (strcmp(lower, "error") == 0) return LOG_ERROR;
    if (strcmp(lower, "warning") == 0) return LOG_WARNING;
    if (strcmp(lower, "info") == 0) return LOG_INFO;
    if (strcmp(lower, "debug") == 0) return LOG_DEBUG;
    
    return LOG_ERROR; /* Default */
}

/**
 * @brief Parse proxy type from string
 *
 * @param[in] value  String value
 *
 * @return Proxy type enum value
 */
static enum proxy_type parse_proxy_type(const char *value)
{
    char lower[32];
    strncpy(lower, value, sizeof(lower) - 1);
    lower[sizeof(lower) - 1] = '\0';
    str_tolower(lower);
    
    if (strcmp(lower, "tcp") == 0) return PROXY_TYPE_TCP;
    if (strcmp(lower, "udp") == 0) return PROXY_TYPE_UDP;
    
    return PROXY_TYPE_TCP; /* Default */
}

/**
 * @brief Parse encryption implementation from string
 *
 * @param[in] value  String value
 * @param[in] type   Proxy type (for validation)
 *
 * @return Encryption implementation enum value
 */
static enum encrypt_impl parse_encrypt_impl(const char *value, enum proxy_type type)
{
    char lower[32];
    strncpy(lower, value, sizeof(lower) - 1);
    lower[sizeof(lower) - 1] = '\0';
    str_tolower(lower);
    
    if (strcmp(lower, "none") == 0) return ENCRYPT_NONE;
    
    if (type == PROXY_TYPE_TCP) {
        if (strcmp(lower, "tls") == 0) return ENCRYPT_TLS;
        if (strcmp(lower, "ssh") == 0) return ENCRYPT_SSH;
    } else if (type == PROXY_TYPE_UDP) {
        if (strcmp(lower, "table") == 0) return ENCRYPT_TABLE;
    }
    
    return ENCRYPT_NONE; /* Default */
}

/**
 * @brief INI file handler callback
 *
 * @param[in] user     User data (config structure)
 * @param[in] section  Section name
 * @param[in] name     Key name
 * @param[in] value    Value
 *
 * @return 1 on success, 0 on error
 */
static int config_ini_handler(void *user, const char *section, const char *name, const char *value)
{
    struct seed_config *config = (struct seed_config *)user;
    
    /* Track current section */
    if (strcmp(current_section, section) != 0) {
        strncpy(current_section, section, sizeof(current_section) - 1);
        current_section[sizeof(current_section) - 1] = '\0';
        
        /* Check if this is a new proxy instance */
        if (strcmp(section, "seed") != 0 && strcmp(section, "server") != 0) {
            /* This is a proxy instance */
            if (config->mode == MODE_CLIENT) {
                current_proxy_index++;
                if (current_proxy_index < MAX_PROXY_INSTANCES) {
                    strncpy(config->proxies[current_proxy_index].name, section, 
                            sizeof(config->proxies[current_proxy_index].name) - 1);
                    config->proxy_count = current_proxy_index + 1;
                }
            }
        }
    }
    
    /* Parse [seed] section */
    if (strcmp(section, "seed") == 0) {
        if (strcmp(name, "mode") == 0) {
            char lower[32];
            strncpy(lower, value, sizeof(lower) - 1);
            lower[sizeof(lower) - 1] = '\0';
            str_tolower(lower);
            
            if (strcmp(lower, "server") == 0) {
                config->mode = MODE_SERVER;
            } else if (strcmp(lower, "client") == 0) {
                config->mode = MODE_CLIENT;
            }
        } else if (strcmp(name, "log_level") == 0) {
            config->log_level = parse_log_level(value);
        }
    }
    /* Parse [server] section */
    else if (strcmp(section, "server") == 0) {
        if (strcmp(name, "bind_addr") == 0) {
            strncpy(config->server.bind_addr, value, sizeof(config->server.bind_addr) - 1);
        } else if (strcmp(name, "bind_port") == 0) {
            config->server.bind_port = atoi(value);
        } else if (strcmp(name, "auth_file") == 0) {
            strncpy(config->server.auth_file, value, sizeof(config->server.auth_file) - 1);
        }
    }
    /* Parse proxy instance sections (client mode only) */
    else if (config->mode == MODE_CLIENT && current_proxy_index >= 0 && 
             current_proxy_index < MAX_PROXY_INSTANCES) {
        struct proxy_config *proxy = &config->proxies[current_proxy_index];
        
        if (strcmp(name, "type") == 0) {
            proxy->type = parse_proxy_type(value);
        } else if (strcmp(name, "local_addr") == 0) {
            strncpy(proxy->local_addr, value, sizeof(proxy->local_addr) - 1);
        } else if (strcmp(name, "local_port") == 0) {
            proxy->local_port = atoi(value);
        } else if (strcmp(name, "remote_port") == 0) {
            proxy->remote_port = atoi(value);
        } else if (strcmp(name, "encrypt") == 0) {
            proxy->encrypt = parse_bool(value);
        } else if (strcmp(name, "encrypt_impl") == 0) {
            proxy->encrypt_impl = parse_encrypt_impl(value, proxy->type);
        }
    }
    
    return 1;
}

/**
 * @brief Initialize configuration with defaults
 *
 * @param[out] config  Configuration structure to initialize
 */
void config_init(struct seed_config *config)
{
    if (!config) return;
    
    memset(config, 0, sizeof(struct seed_config));
    
    /* Set defaults */
    config->mode = MODE_UNKNOWN;
    config->log_level = LOG_ERROR;
    config->server.bind_port = DEFAULT_SERVER_PORT;
    strcpy(config->server.bind_addr, "0.0.0.0");
    strcpy(config->server.auth_file, DEFAULT_AUTH_FILE);
    config->proxy_count = 0;
}

/**
 * @brief Load configuration from file
 *
 * @param[in]  filename  Configuration file path
 * @param[out] config    Configuration structure to fill
 *
 * @return 0 on success, negative error code on failure
 */
int config_load(const char *filename, struct seed_config *config)
{
    int result;
    
    if (!filename || !config) {
        return SEED_ERROR_INVALID_ARGS;
    }
    
    /* Reset parsing state */
    current_section[0] = '\0';
    current_proxy_index = -1;
    
    /* Initialize config with defaults */
    config_init(config);
    
    /* Parse INI file */
    result = ini_parse(filename, config_ini_handler, config);
    if (result < 0) {
        log_error("Failed to open configuration file: %s", filename);
        return SEED_ERROR_FILE_NOT_FOUND;
    } else if (result > 0) {
        log_error("Configuration parse error at line %d", result);
        return SEED_ERROR_CONFIG;
    }
    
    return SEED_OK;
}

/**
 * @brief Validate configuration
 *
 * @param[in] config  Configuration to validate
 *
 * @return 0 if valid, negative error code if invalid
 */
int config_validate(const struct seed_config *config)
{
    if (!config) {
        return SEED_ERROR_INVALID_ARGS;
    }
    
    /* Check mode */
    if (config->mode == MODE_UNKNOWN) {
        log_error("Invalid or missing mode in configuration");
        return SEED_ERROR_CONFIG;
    }
    
    /* Validate server configuration */
    if (config->mode == MODE_SERVER) {
        if (config->server.bind_port <= 0 || config->server.bind_port > 65535) {
            log_error("Invalid server bind port: %d", config->server.bind_port);
            return SEED_ERROR_CONFIG;
        }
        
        if (strlen(config->server.auth_file) == 0) {
            log_error("Missing authentication file in server configuration");
            return SEED_ERROR_CONFIG;
        }
    }
    
    /* Validate client configuration */
    if (config->mode == MODE_CLIENT) {
        if (config->proxy_count == 0) {
            log_error("No proxy instances configured for client mode");
            return SEED_ERROR_CONFIG;
        }
        
        /* Validate each proxy instance */
        for (int i = 0; i < config->proxy_count; i++) {
            const struct proxy_config *proxy = &config->proxies[i];
            
            if (proxy->local_port <= 0 || proxy->local_port > 65535) {
                log_error("Invalid local port for proxy '%s': %d", 
                         proxy->name, proxy->local_port);
                return SEED_ERROR_CONFIG;
            }
            
            if (proxy->remote_port <= 0 || proxy->remote_port > 65535) {
                log_error("Invalid remote port for proxy '%s': %d", 
                         proxy->name, proxy->remote_port);
                return SEED_ERROR_CONFIG;
            }
            
            if (strlen(proxy->local_addr) == 0) {
                log_error("Missing local address for proxy '%s'", proxy->name);
                return SEED_ERROR_CONFIG;
            }
        }
    }
    
    return SEED_OK;
}

/**
 * @brief Print configuration for debugging
 *
 * @param[in] config  Configuration to print
 */
void config_print(const struct seed_config *config)
{
    if (!config) return;
    
    printf("=== Seed Configuration ===\n");
    printf("Mode: %s\n", config->mode == MODE_SERVER ? "server" : "client");
    printf("Log Level: %d\n", config->log_level);
    
    if (config->mode == MODE_SERVER) {
        printf("\n=== Server Configuration ===\n");
        printf("Bind Address: %s\n", config->server.bind_addr);
        printf("Bind Port: %d\n", config->server.bind_port);
        printf("Auth File: %s\n", config->server.auth_file);
    } else if (config->mode == MODE_CLIENT) {
        printf("\n=== Client Configuration ===\n");
        printf("Proxy Count: %d\n", config->proxy_count);
        
        for (int i = 0; i < config->proxy_count; i++) {
            const struct proxy_config *proxy = &config->proxies[i];
            printf("\n--- Proxy: %s ---\n", proxy->name);
            printf("  Type: %s\n", proxy->type == PROXY_TYPE_TCP ? "TCP" : "UDP");
            printf("  Local: %s:%d\n", proxy->local_addr, proxy->local_port);
            printf("  Remote Port: %d\n", proxy->remote_port);
            printf("  Encryption: %s\n", proxy->encrypt ? "enabled" : "disabled");
            if (proxy->encrypt) {
                const char *impl_names[] = {"none", "tls", "ssh", "table"};
                printf("  Encryption Type: %s\n", impl_names[proxy->encrypt_impl]);
            }
        }
    }
    
    printf("========================\n");
}

/**
 * @brief Free configuration resources
 *
 * @param[in,out] config  Configuration to free
 */
void config_free(struct seed_config *config)
{
    if (config) {
        /* Currently no dynamic allocations to free */
        memset(config, 0, sizeof(struct seed_config));
    }
}