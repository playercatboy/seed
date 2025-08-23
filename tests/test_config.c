/**
 * @file test_config.c
 * @brief Unit tests for configuration module
 * @author Seed Development Team
 * @date 2025
 */

#include "test_framework.h"
#include "../include/config.h"
#include "../include/log.h"
#include <unistd.h>

/** Test INI file content */
static const char *test_server_ini = 
    "[seed]\n"
    "mode = server\n"
    "log_level = info\n"
    "\n"
    "[server]\n"
    "bind_addr = 127.0.0.1\n"
    "bind_port = 7000\n"
    "auth_file = test.auth\n";

static const char *test_client_ini = 
    "[seed]\n"
    "mode = client\n"
    "log_level = debug\n"
    "\n"
    "[http-proxy]\n"
    "type = tcp\n"
    "local_addr = 127.0.0.1\n"
    "local_port = 8080\n"
    "remote_port = 8080\n"
    "encrypt = true\n"
    "encrypt_impl = tls\n"
    "\n"
    "[udp-test]\n"
    "type = udp\n"
    "local_addr = 192.168.1.1\n"
    "local_port = 9999\n"
    "remote_port = 9999\n"
    "encrypt = false\n";

/**
 * @brief Create temporary test file
 */
static int create_test_file(const char *filename, const char *content)
{
    FILE *file = fopen(filename, "w");
    if (!file) {
        return -1;
    }
    
    fputs(content, file);
    fclose(file);
    return 0;
}

/**
 * @brief Test configuration initialization
 */
static void test_config_init(void)
{
    TEST_CASE("config_init");
    
    struct seed_config config;
    
    config_init(&config);
    
    ASSERT_EQUAL(MODE_UNKNOWN, config.mode, "Default mode should be unknown");
    ASSERT_EQUAL(LOG_ERROR, config.log_level, "Default log level should be error");
    ASSERT_EQUAL(DEFAULT_SERVER_PORT, config.server.bind_port, "Default server port");
    ASSERT_STR_EQUAL("0.0.0.0", config.server.bind_addr, "Default bind address");
    ASSERT_EQUAL(0, config.proxy_count, "Default proxy count should be 0");
}

/**
 * @brief Test server configuration loading
 */
static void test_server_config_load(void)
{
    TEST_CASE("server_config_load");
    
    const char *test_file = "test_server.conf";
    struct seed_config config;
    int result;
    
    /* Create test file */
    result = create_test_file(test_file, test_server_ini);
    ASSERT_EQUAL(0, result, "Test file creation should succeed");
    
    /* Load configuration */
    result = config_load(test_file, &config);
    ASSERT_EQUAL(SEED_OK, result, "Configuration load should succeed");
    
    /* Validate server configuration */
    ASSERT_EQUAL(MODE_SERVER, config.mode, "Mode should be server");
    ASSERT_EQUAL(LOG_INFO, config.log_level, "Log level should be info");
    ASSERT_STR_EQUAL("127.0.0.1", config.server.bind_addr, "Bind address should match");
    ASSERT_EQUAL(7000, config.server.bind_port, "Bind port should match");
    ASSERT_STR_EQUAL("test.auth", config.server.auth_file, "Auth file should match");
    
    /* Validate configuration */
    result = config_validate(&config);
    ASSERT_EQUAL(SEED_OK, result, "Server configuration should be valid");
    
    /* Cleanup */
    config_free(&config);
    unlink(test_file);
}

/**
 * @brief Test client configuration loading
 */
static void test_client_config_load(void)
{
    TEST_CASE("client_config_load");
    
    const char *test_file = "test_client.conf";
    struct seed_config config;
    int result;
    
    /* Create test file */
    result = create_test_file(test_file, test_client_ini);
    ASSERT_EQUAL(0, result, "Test file creation should succeed");
    
    /* Load configuration */
    result = config_load(test_file, &config);
    ASSERT_EQUAL(SEED_OK, result, "Configuration load should succeed");
    
    /* Validate client configuration */
    ASSERT_EQUAL(MODE_CLIENT, config.mode, "Mode should be client");
    ASSERT_EQUAL(LOG_DEBUG, config.log_level, "Log level should be debug");
    ASSERT_EQUAL(2, config.proxy_count, "Should have 2 proxy instances");
    
    /* Validate first proxy */
    ASSERT_STR_EQUAL("http-proxy", config.proxies[0].name, "First proxy name");
    ASSERT_EQUAL(PROXY_TYPE_TCP, config.proxies[0].type, "First proxy type should be TCP");
    ASSERT_STR_EQUAL("127.0.0.1", config.proxies[0].local_addr, "First proxy local addr");
    ASSERT_EQUAL(8080, config.proxies[0].local_port, "First proxy local port");
    ASSERT_EQUAL(8080, config.proxies[0].remote_port, "First proxy remote port");
    ASSERT_TRUE(config.proxies[0].encrypt, "First proxy should have encryption enabled");
    ASSERT_EQUAL(ENCRYPT_TLS, config.proxies[0].encrypt_impl, "First proxy should use TLS");
    
    /* Validate second proxy */
    ASSERT_STR_EQUAL("udp-test", config.proxies[1].name, "Second proxy name");
    ASSERT_EQUAL(PROXY_TYPE_UDP, config.proxies[1].type, "Second proxy type should be UDP");
    ASSERT_STR_EQUAL("192.168.1.1", config.proxies[1].local_addr, "Second proxy local addr");
    ASSERT_EQUAL(9999, config.proxies[1].local_port, "Second proxy local port");
    ASSERT_EQUAL(9999, config.proxies[1].remote_port, "Second proxy remote port");
    ASSERT_FALSE(config.proxies[1].encrypt, "Second proxy should have encryption disabled");
    
    /* Validate configuration */
    result = config_validate(&config);
    ASSERT_EQUAL(SEED_OK, result, "Client configuration should be valid");
    
    /* Cleanup */
    config_free(&config);
    unlink(test_file);
}

/**
 * @brief Test invalid configuration
 */
static void test_invalid_config(void)
{
    TEST_CASE("invalid_config");
    
    const char *invalid_ini = "[seed]\nmode = invalid\n";
    const char *test_file = "test_invalid.conf";
    struct seed_config config;
    int result;
    
    /* Create invalid test file */
    result = create_test_file(test_file, invalid_ini);
    ASSERT_EQUAL(0, result, "Invalid test file creation should succeed");
    
    /* Load configuration */
    result = config_load(test_file, &config);
    ASSERT_EQUAL(SEED_OK, result, "Configuration load should succeed even with invalid mode");
    
    /* Validate configuration should fail */
    result = config_validate(&config);
    ASSERT_NOT_EQUAL(SEED_OK, result, "Invalid configuration should not validate");
    
    /* Cleanup */
    config_free(&config);
    unlink(test_file);
}

/**
 * @brief Test missing file
 */
static void test_missing_file(void)
{
    TEST_CASE("missing_file");
    
    struct seed_config config;
    int result;
    
    /* Try to load non-existent file */
    result = config_load("non_existent_file.conf", &config);
    ASSERT_NOT_EQUAL(SEED_OK, result, "Loading non-existent file should fail");
}

/**
 * @brief Main test function
 */
int test_config_main(void)
{
    test_init();
    
    /* Suppress logging during tests */
    log_init(LOG_ERROR);
    
    TEST_SUITE("Configuration Module Tests");
    
    test_config_init();
    test_server_config_load();
    test_client_config_load();
    test_invalid_config();
    test_missing_file();
    
    TEST_SUMMARY();
    
    return test_exit_code();
}