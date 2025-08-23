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
#include "client.h"
#include "network.h"

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
        struct network_context network_ctx;
        struct client_session client;
        int client_result;
        
        log_info("Starting client with %d proxy instances", config.proxy_count);
        
        /* Initialize network context */
        client_result = network_init(&network_ctx, NULL);
        if (client_result != SEED_OK) {
            log_error("Failed to initialize network context");
            config_free(&config);
            cmdline_free(&options);
            log_cleanup();
            return EXIT_FAILURE;
        }
        
        /* Initialize client */
        client_result = client_init(&client, &network_ctx, &config);
        if (client_result != SEED_OK) {
            log_error("Failed to initialize client");
            network_cleanup(&network_ctx);
            config_free(&config);
            cmdline_free(&options);
            log_cleanup();
            return EXIT_FAILURE;
        }
        
        /* Add proxy instances from configuration */
        for (int i = 0; i < config.proxy_count; i++) {
            const struct proxy_config *proxy = &config.proxies[i];
            client_result = client_add_proxy(&client, proxy->name, proxy->type,
                                           proxy->local_addr, proxy->local_port,
                                           proxy->remote_port, proxy->encrypt,
                                           proxy->encrypt_impl);
            if (client_result != SEED_OK) {
                log_error("Failed to add proxy instance '%s'", proxy->name);
            }
        }
        
        /* Connect to server - for now use hardcoded values */
        /* TODO: Add server address/port to client configuration */
        const char *server_addr = "127.0.0.1";
        uint16_t server_port = 7000;
        
        client_result = client_connect(&client, server_addr, server_port);
        if (client_result != SEED_OK) {
            log_error("Failed to connect to server");
            client_cleanup(&client);
            network_cleanup(&network_ctx);
            config_free(&config);
            cmdline_free(&options);
            log_cleanup();
            return EXIT_FAILURE;
        }
        
        /* Run client event loop */
        log_info("Client started, running event loop...");
        client_result = uv_run(network_ctx.loop, UV_RUN_DEFAULT);
        
        log_info("Client event loop finished");
        
        /* Cleanup */
        client_cleanup(&client);
        network_cleanup(&network_ctx);
        config_free(&config);
        cmdline_free(&options);
        log_cleanup();
        
        return client_result == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    
    /* Cleanup */
    config_free(&config);
    cmdline_free(&options);
    log_cleanup();
    
    return EXIT_SUCCESS;
}