/**
 * @file config.h
 * @brief Configuration management for Seed reverse proxy
 * @author Seed Development Team
 * @date 2025
 */

#ifndef CONFIG_H
#define CONFIG_H

#include "common.h"
#include "log.h"

/** Maximum number of proxy instances */
#define MAX_PROXY_INSTANCES 100

/** Seed working mode */
enum seed_mode {
    MODE_UNKNOWN = 0, /** Unknown mode */
    MODE_SERVER,      /** Server mode */
    MODE_CLIENT       /** Client mode */
};

/** Proxy type */
enum proxy_type {
    PROXY_TYPE_TCP = 0, /** TCP proxy */
    PROXY_TYPE_UDP      /** UDP proxy */
};

/** Encryption implementation */
enum encrypt_impl {
    ENCRYPT_NONE = 0,  /** No encryption */
    ENCRYPT_TLS,       /** TLS encryption */
    ENCRYPT_SSH,       /** SSH encryption */
    ENCRYPT_TABLE      /** Table encryption (UDP only) */
};

/** Proxy instance configuration */
struct proxy_config {
    char name[64];              /** Instance name */
    enum proxy_type type;       /** Proxy type */
    char local_addr[16];        /** Local address */
    int local_port;             /** Local port */
    int remote_port;            /** Remote port */
    bool encrypt;               /** Use encryption */
    enum encrypt_impl encrypt_impl; /** Encryption implementation */
};

/** Server configuration */
struct server_config {
    char bind_addr[16];         /** Bind address */
    int bind_port;              /** Bind port */
    char auth_file[MAX_PATH_LENGTH]; /** Authentication file path */
};

/** Main configuration structure */
struct seed_config {
    /* Global settings */
    enum seed_mode mode;        /** Working mode */
    enum log_level log_level;   /** Log level */
    
    /* Server settings (only used in server mode) */
    struct server_config server;
    
    /* Client settings (only used in client mode) */
    char server_addr[16];       /** Server address */
    int server_port;            /** Server port */
    char username[64];          /** Username for authentication */
    char password[128];         /** Password for authentication */
    
    /* Proxy instances */
    struct proxy_config proxies[MAX_PROXY_INSTANCES]; /** Proxy configurations */
    int proxy_count;            /** Number of configured proxies */
};

/**
 * @brief Initialize configuration with defaults
 *
 * @param[out] config  Configuration structure to initialize
 */
void config_init(struct seed_config *config);

/**
 * @brief Load configuration from file
 *
 * @param[in]  filename  Configuration file path
 * @param[out] config    Configuration structure to fill
 *
 * @return 0 on success, negative error code on failure
 */
int config_load(const char *filename, struct seed_config *config);

/**
 * @brief Validate configuration
 *
 * @param[in] config  Configuration to validate
 *
 * @return 0 if valid, negative error code if invalid
 */
int config_validate(const struct seed_config *config);

/**
 * @brief Print configuration for debugging
 *
 * @param[in] config  Configuration to print
 */
void config_print(const struct seed_config *config);

/**
 * @brief Free configuration resources
 *
 * @param[in,out] config  Configuration to free
 */
void config_free(struct seed_config *config);

#endif /* CONFIG_H */