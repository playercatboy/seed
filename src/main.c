/**
 * @file main.c
 * @brief Main entry point for Seed reverse proxy
 * @author Seed Development Team
 * @date 2025
 */

#include "common.h"
#include "log.h"
#include "cmdline.h"
#include "config.h"
#include "jwt.h"
#include "auth.h"
#include "server.h"

/**
 * @brief Handle password hashing mode
 *
 * @param[in] password  Password to hash
 *
 * @return Exit code
 */
static int handle_hash_password(const char *password)
{
    char token[MAX_JWT_LENGTH];
    
    if (jwt_generate(password, token, sizeof(token)) != SEED_OK) {
        fprintf(stderr, "Failed to generate JWT token\n");
        return EXIT_FAILURE;
    }
    
    printf("JWT Token:\n%s\n", token);
    printf("\nAdd this to your seed.auth file as:\n");
    printf("username: %s\n", token);
    
    return EXIT_SUCCESS;
}

/**
 * @brief Main entry point
 *
 * @param[in] argc  Argument count
 * @param[in] argv  Argument vector
 *
 * @return Exit code
 */
int main(int argc, char *argv[])
{
    struct cmdline_options options;
    struct seed_config config;
    int result;
    
    /* Parse command line arguments */
    result = cmdline_parse(argc, argv, &options);
    if (result != SEED_OK) {
        fprintf(stderr, "Error: Invalid command line arguments\n");
        cmdline_print_help(argv[0]);
        return EXIT_FAILURE;
    }
    
    /* Handle help */
    if (options.show_help) {
        cmdline_print_help(argv[0]);
        cmdline_free(&options);
        return EXIT_SUCCESS;
    }
    
    /* Handle version */
    if (options.show_version) {
        cmdline_print_version();
        cmdline_free(&options);
        return EXIT_SUCCESS;
    }
    
    /* Handle password hashing */
    if (options.hash_password) {
        int ret = handle_hash_password(options.password);
        cmdline_free(&options);
        return ret;
    }
    
    /* Load configuration */
    result = config_load(options.config_file, &config);
    if (result != SEED_OK) {
        fprintf(stderr, "Error: Failed to load configuration from %s\n", 
                options.config_file);
        cmdline_free(&options);
        return EXIT_FAILURE;
    }
    
    /* Initialize logging */
    log_init(config.log_level);
    
    /* Validate configuration */
    result = config_validate(&config);
    if (result != SEED_OK) {
        log_error("Configuration validation failed");
        config_free(&config);
        cmdline_free(&options);
        return EXIT_FAILURE;
    }
    
    /* Print configuration in debug mode */
    if (config.log_level == LOG_DEBUG) {
        config_print(&config);
    }
    
    log_info("Seed v%s starting in %s mode", 
             SEED_VERSION_STRING, 
             config.mode == MODE_SERVER ? "server" : "client");
    
    /* Server mode */
    if (config.mode == MODE_SERVER) {
        struct server_context server_ctx;
        int server_result;
        
        log_info("Starting server on %s:%d", 
                 config.server.bind_addr, 
                 config.server.bind_port);
        
        /* Initialize server */
        server_result = server_init(&server_ctx, &config);
        if (server_result != SEED_OK) {
            log_error("Failed to initialize server");
            config_free(&config);
            cmdline_free(&options);
            log_cleanup();
            return EXIT_FAILURE;
        }
        
        /* Start server */
        server_result = server_start(&server_ctx);
        if (server_result != SEED_OK) {
            log_error("Failed to start server");
            server_cleanup(&server_ctx);
            config_free(&config);
            cmdline_free(&options);
            log_cleanup();
            return EXIT_FAILURE;
        }
        
        /* Run server main loop */
        server_result = server_run(&server_ctx);
        
        /* Cleanup */
        server_cleanup(&server_ctx);
        config_free(&config);
        cmdline_free(&options);
        log_cleanup();
        
        log_info("Server shutdown completed");
        
        return server_result;
    }
    /* Client mode */
    else if (config.mode == MODE_CLIENT) {
        log_info("Starting client with %d proxy instances", config.proxy_count);
        
        /* TODO: Implement client mode */
        log_error("Client mode not yet implemented");
        
        config_free(&config);
        cmdline_free(&options);
        log_cleanup();
        
        return EXIT_FAILURE;
    }
    
    /* Cleanup */
    config_free(&config);
    cmdline_free(&options);
    log_cleanup();
    
    return EXIT_SUCCESS;
}