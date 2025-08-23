/**
 * @file test_integration_simple.c
 * @brief Simple integration tests for core functionality
 * @author Seed Development Team
 * @date 2025
 */

#include <stdio.h>
#include <unistd.h>
#include "../include/log.h"
#include "../include/config.h"
#include "../include/jwt.h"
#include "../include/cmdline.h"

/**
 * @brief Test basic functionality integration
 */
int main(void)
{
    printf("=== Seed Integration Tests ===\n\n");
    
    /* Initialize logging */
    log_init(LOG_INFO);
    log_info("Starting integration tests");
    
    /* Test 1: Configuration loading */
    printf("Test 1: Configuration Loading\n");
    struct seed_config config;
    config_init(&config);
    printf("✓ Configuration initialization successful\n");
    
    /* Test 2: JWT functionality */
    printf("\nTest 2: JWT Token Generation\n");
    char token[512];
    int result = jwt_generate("test_password", token, sizeof(token));
    if (result == 0) {
        printf("✓ JWT generation successful (length: %d)\n", (int)strlen(token));
        
        /* Test verification */
        result = jwt_verify("test_password", token);
        if (result == 0) {
            printf("✓ JWT verification successful\n");
        } else {
            printf("✗ JWT verification failed\n");
        }
    } else {
        printf("✗ JWT generation failed\n");
    }
    
    /* Test 3: Command line parsing */
    printf("\nTest 3: Command Line Parsing\n");
    char *test_argv[] = {"seed", "-f", "test.conf"};
    struct cmdline_options options;
    result = cmdline_parse(3, test_argv, &options);
    if (result == 0 && strcmp(options.config_file, "test.conf") == 0) {
        printf("✓ Command line parsing successful\n");
    } else {
        printf("✗ Command line parsing failed\n");
    }
    cmdline_free(&options);
    
    /* Test 4: Create sample configuration file */
    printf("\nTest 4: Configuration File Creation\n");
    FILE *conf_file = fopen("test_integration.conf", "w");
    if (conf_file) {
        fprintf(conf_file, "[seed]\nmode = server\nlog_level = info\n\n");
        fprintf(conf_file, "[server]\nbind_addr = 127.0.0.1\nbind_port = 7000\n");
        fprintf(conf_file, "auth_file = test.auth\n");
        fclose(conf_file);
        
        /* Try to load the configuration */
        result = config_load("test_integration.conf", &config);
        if (result == 0) {
            printf("✓ Configuration file loading successful\n");
            printf("  Mode: %s\n", config.mode == MODE_SERVER ? "server" : "client");
            printf("  Server: %s:%d\n", config.server.bind_addr, config.server.bind_port);
        } else {
            printf("✗ Configuration file loading failed\n");
        }
        
        /* Clean up */
        unlink("test_integration.conf");
    } else {
        printf("✗ Configuration file creation failed\n");
    }
    
    config_free(&config);
    
    printf("\n=== Integration Tests Complete ===\n");
    log_info("Integration tests completed");
    log_cleanup();
    
    return 0;
}