/**
 * @file test_ssh_encrypt.c
 * @brief SSH encryption module unit tests
 * @author Seed Development Team
 * @date 2025
 */

#include "../src/ssh_encrypt.c"
#include "test_framework.h"
#include <string.h>
#include <stdlib.h>

/* Test assertion wrapper */
#define test_assert(condition, message) ASSERT_TRUE(condition, message)

/* Test data */
static const char *TEST_HOST = "localhost";
static const int TEST_PORT = 2222;
static const char *TEST_USERNAME = "testuser";
static const char *TEST_PASSWORD = "testpass123";
static const char *TEST_REMOTE_HOST = "127.0.0.1";
static const int TEST_REMOTE_PORT = 8080;

/* Helper function to create test configuration */
static void create_test_config(struct ssh_config *config, bool server_mode)
{
    memset(config, 0, sizeof(struct ssh_config));
    
    strncpy(config->host, TEST_HOST, sizeof(config->host) - 1);
    config->port = TEST_PORT;
    strncpy(config->username, TEST_USERNAME, sizeof(config->username) - 1);
    strncpy(config->password, TEST_PASSWORD, sizeof(config->password) - 1);
    strncpy(config->remote_host, TEST_REMOTE_HOST, sizeof(config->remote_host) - 1);
    config->remote_port = TEST_REMOTE_PORT;
    config->server_mode = server_mode;
}

/* Test SSH module initialization */
void test_ssh_init_cleanup(void)
{
    printf("Testing SSH module initialization...\n");
    
    /* Test initialization */
    int result = ssh_encrypt_init();
    test_assert(result == 0, "SSH initialization should succeed");
    
    /* Test double initialization (should be safe) */
    result = ssh_encrypt_init();
    test_assert(result == 0, "Double SSH initialization should be safe");
    
    /* Test cleanup */
    ssh_encrypt_cleanup();
    
    /* Test double cleanup (should be safe) */
    ssh_encrypt_cleanup();
    
    printf("✓ SSH module initialization tests passed\n");
}

/* Test SSH context creation and destruction */
void test_ssh_context_lifecycle(void)
{
    printf("Testing SSH context lifecycle...\n");
    
    /* Initialize SSH module */
    int result = ssh_encrypt_init();
    test_assert(result == 0, "SSH initialization required");
    
    struct ssh_config config;
    struct ssh_context *ctx = NULL;
    
    /* Test invalid arguments */
    result = ssh_context_create(NULL, &ctx);
    test_assert(result == SEED_ERROR_INVALID_ARGS, "Should reject NULL config");
    
    result = ssh_context_create(&config, NULL);
    test_assert(result == SEED_ERROR_INVALID_ARGS, "Should reject NULL context pointer");
    
    /* Test client mode context creation */
    create_test_config(&config, false);
    result = ssh_context_create(&config, &ctx);
    
#ifdef ENABLE_SSH_ENCRYPTION
    test_assert(result == 0, "SSH client context creation should succeed");
    test_assert(ctx != NULL, "Context should be allocated");
    test_assert(!ctx->connected, "Context should start disconnected");
    test_assert(!ctx->channel_ready, "Channel should start not ready");
    
    /* Test context destruction */
    ssh_context_destroy(ctx);
#else
    test_assert(result == SEED_ERROR_NOT_IMPLEMENTED, "Should return not implemented without libssh");
#endif
    
    /* Test server mode context creation */
    create_test_config(&config, true);
    ctx = NULL;
    result = ssh_context_create(&config, &ctx);
    
#ifdef ENABLE_SSH_ENCRYPTION
    test_assert(result == 0, "SSH server context creation should succeed");
    test_assert(ctx != NULL, "Context should be allocated");
    ssh_context_destroy(ctx);
#else
    test_assert(result == SEED_ERROR_NOT_IMPLEMENTED, "Should return not implemented without libssh");
#endif
    
    /* Test destroying NULL context (should be safe) */
    ssh_context_destroy(NULL);
    
    ssh_encrypt_cleanup();
    printf("✓ SSH context lifecycle tests passed\n");
}

/* Test SSH connection functions */
void test_ssh_connection_functions(void)
{
    printf("Testing SSH connection functions...\n");
    
    int result = ssh_encrypt_init();
    test_assert(result == 0, "SSH initialization required");
    
    struct ssh_config config;
    struct ssh_context *ctx = NULL;
    
    /* Create test context */
    create_test_config(&config, false);
    result = ssh_context_create(&config, &ctx);
    
#ifdef ENABLE_SSH_ENCRYPTION
    test_assert(result == 0, "Context creation required for connection tests");
    
    /* Test ssh_connect with invalid arguments */
    result = ssh_connect(NULL);
    test_assert(result == SEED_ERROR_INVALID_ARGS, "Should reject NULL context");
    
    /* Test ssh_connect (will likely fail without real SSH server) */
    result = ssh_connect(ctx);
    /* Don't assert success since we don't have a real SSH server running */
    /* Just ensure it doesn't crash and returns appropriate error */
    test_assert(result != 0, "Connection should fail without SSH server");
    
    /* Test ssh_is_ready */
    bool ready = ssh_is_ready(NULL);
    test_assert(!ready, "NULL context should not be ready");
    
    ready = ssh_is_ready(ctx);
    test_assert(!ready, "Unconnected context should not be ready");
    
    /* Test ssh_disconnect */
    ssh_disconnect(NULL); /* Should not crash */
    ssh_disconnect(ctx);  /* Should not crash */
    
    ssh_context_destroy(ctx);
#else
    test_assert(result == SEED_ERROR_NOT_IMPLEMENTED, "Should return not implemented without libssh");
    
    /* Test functions without libssh support */
    result = ssh_connect(NULL);
    test_assert(result == SEED_ERROR_NOT_IMPLEMENTED, "Should return not implemented");
    
    bool ready = ssh_is_ready(NULL);
    test_assert(!ready, "Should return false without libssh");
#endif
    
    ssh_encrypt_cleanup();
    printf("✓ SSH connection function tests passed\n");
}

/* Test SSH authentication functions */
void test_ssh_authentication(void)
{
    printf("Testing SSH authentication functions...\n");
    
    int result = ssh_encrypt_init();
    test_assert(result == 0, "SSH initialization required");
    
    struct ssh_config config;
    struct ssh_context *ctx = NULL;
    
    create_test_config(&config, false);
    result = ssh_context_create(&config, &ctx);
    
#ifdef ENABLE_SSH_ENCRYPTION
    test_assert(result == 0, "Context creation required");
    
    /* Test password authentication with invalid arguments */
    result = ssh_authenticate_password(NULL, TEST_PASSWORD);
    test_assert(result == SEED_ERROR_INVALID_ARGS, "Should reject NULL context");
    
    result = ssh_authenticate_password(ctx, NULL);
    test_assert(result == SEED_ERROR_INVALID_ARGS, "Should reject NULL password");
    
    /* Test key authentication with invalid arguments */
    result = ssh_authenticate_key(NULL, "/tmp/test_key", NULL);
    test_assert(result == SEED_ERROR_INVALID_ARGS, "Should reject NULL context");
    
    result = ssh_authenticate_key(ctx, NULL, NULL);
    test_assert(result == SEED_ERROR_INVALID_ARGS, "Should reject NULL key path");
    
    /* Test authentication on disconnected context */
    result = ssh_authenticate_password(ctx, TEST_PASSWORD);
    test_assert(result == SEED_ERROR, "Should fail on disconnected context");
    
    result = ssh_authenticate_key(ctx, "/tmp/nonexistent_key", NULL);
    test_assert(result == SEED_ERROR, "Should fail on disconnected context");
    
    ssh_context_destroy(ctx);
#else
    test_assert(result == SEED_ERROR_NOT_IMPLEMENTED, "Should return not implemented without libssh");
    
    /* Test functions without libssh support */
    result = ssh_authenticate_password(NULL, TEST_PASSWORD);
    test_assert(result == SEED_ERROR_NOT_IMPLEMENTED, "Should return not implemented");
    
    result = ssh_authenticate_key(NULL, "/tmp/test_key", NULL);
    test_assert(result == SEED_ERROR_NOT_IMPLEMENTED, "Should return not implemented");
#endif
    
    ssh_encrypt_cleanup();
    printf("✓ SSH authentication tests passed\n");
}

/* Test SSH data transfer functions */
void test_ssh_data_transfer(void)
{
    printf("Testing SSH data transfer functions...\n");
    
    int result = ssh_encrypt_init();
    test_assert(result == 0, "SSH initialization required");
    
    struct ssh_config config;
    struct ssh_context *ctx = NULL;
    
    create_test_config(&config, false);
    result = ssh_context_create(&config, &ctx);
    
#ifdef ENABLE_SSH_ENCRYPTION
    test_assert(result == 0, "Context creation required");
    
    const char *test_data = "Hello SSH tunnel!";
    char buffer[256];
    size_t received = 0;
    
    /* Test send with invalid arguments */
    result = ssh_send_data(NULL, test_data, strlen(test_data));
    test_assert(result == SEED_ERROR_INVALID_ARGS, "Should reject NULL context");
    
    result = ssh_send_data(ctx, NULL, 10);
    test_assert(result == SEED_ERROR_INVALID_ARGS, "Should reject NULL data");
    
    /* Test receive with invalid arguments */
    result = ssh_receive_data(NULL, buffer, sizeof(buffer), &received);
    test_assert(result == SEED_ERROR_INVALID_ARGS, "Should reject NULL context");
    
    result = ssh_receive_data(ctx, NULL, sizeof(buffer), &received);
    test_assert(result == SEED_ERROR_INVALID_ARGS, "Should reject NULL buffer");
    
    result = ssh_receive_data(ctx, buffer, sizeof(buffer), NULL);
    test_assert(result == SEED_ERROR_INVALID_ARGS, "Should reject NULL received pointer");
    
    /* Test operations on channel that's not ready */
    result = ssh_send_data(ctx, test_data, strlen(test_data));
    test_assert(result == SEED_ERROR, "Should fail on unready channel");
    
    result = ssh_receive_data(ctx, buffer, sizeof(buffer), &received);
    test_assert(result == SEED_ERROR, "Should fail on unready channel");
    
    /* Test tunnel creation */
    result = ssh_create_tunnel(NULL, TEST_REMOTE_HOST, TEST_REMOTE_PORT);
    test_assert(result == SEED_ERROR_INVALID_ARGS, "Should reject NULL context");
    
    result = ssh_create_tunnel(ctx, NULL, TEST_REMOTE_PORT);
    test_assert(result == SEED_ERROR_INVALID_ARGS, "Should reject NULL remote host");
    
    result = ssh_create_tunnel(ctx, TEST_REMOTE_HOST, TEST_REMOTE_PORT);
    test_assert(result == SEED_ERROR, "Should fail on disconnected context");
    
    ssh_context_destroy(ctx);
#else
    test_assert(result == SEED_ERROR_NOT_IMPLEMENTED, "Should return not implemented without libssh");
    
    /* Test functions without libssh support */
    result = ssh_send_data(NULL, "test", 4);
    test_assert(result == SEED_ERROR_NOT_IMPLEMENTED, "Should return not implemented");
    
    char buffer[64];
    size_t received = 0;
    result = ssh_receive_data(NULL, buffer, sizeof(buffer), &received);
    test_assert(result == SEED_ERROR_NOT_IMPLEMENTED, "Should return not implemented");
    
    result = ssh_create_tunnel(NULL, TEST_REMOTE_HOST, TEST_REMOTE_PORT);
    test_assert(result == SEED_ERROR_NOT_IMPLEMENTED, "Should return not implemented");
#endif
    
    ssh_encrypt_cleanup();
    printf("✓ SSH data transfer tests passed\n");
}

/* Test SSH info function */
void test_ssh_get_info(void)
{
    printf("Testing SSH info function...\n");
    
    int result = ssh_encrypt_init();
    test_assert(result == 0, "SSH initialization required");
    
    struct ssh_config config;
    struct ssh_context *ctx = NULL;
    char info[256];
    
    /* Test with invalid arguments */
    result = ssh_get_info(NULL, info, sizeof(info));
    test_assert(result == SEED_ERROR_INVALID_ARGS, "Should reject NULL context");
    
    result = ssh_get_info(ctx, NULL, sizeof(info));
    test_assert(result == SEED_ERROR_INVALID_ARGS, "Should reject NULL info buffer");
    
    create_test_config(&config, false);
    result = ssh_context_create(&config, &ctx);
    
#ifdef ENABLE_SSH_ENCRYPTION
    test_assert(result == 0, "Context creation required");
    
    /* Test info on disconnected context */
    result = ssh_get_info(ctx, info, sizeof(info));
    test_assert(result == SEED_ERROR, "Should fail on disconnected context");
    test_assert(strstr(info, "not connected") != NULL, "Should indicate not connected");
    
    ssh_context_destroy(ctx);
#else
    test_assert(result == SEED_ERROR_NOT_IMPLEMENTED, "Should return not implemented without libssh");
    
    /* Test without libssh support */
    result = ssh_get_info(NULL, info, sizeof(info));
    test_assert(result == SEED_ERROR_NOT_IMPLEMENTED, "Should return not implemented");
    test_assert(strstr(info, "not available") != NULL, "Should indicate SSH not available");
#endif
    
    ssh_encrypt_cleanup();
    printf("✓ SSH info function tests passed\n");
}

/* Test SSH server mode functions */
void test_ssh_server_mode(void)
{
    printf("Testing SSH server mode functions...\n");
    
    int result = ssh_encrypt_init();
    test_assert(result == 0, "SSH initialization required");
    
    struct ssh_config config;
    struct ssh_context *ctx = NULL;
    
    create_test_config(&config, true);
    result = ssh_context_create(&config, &ctx);
    
#ifdef ENABLE_SSH_ENCRYPTION
    test_assert(result == 0, "Server context creation required");
    
    /* Test accept with invalid arguments */
    result = ssh_accept(NULL);
    test_assert(result == SEED_ERROR_INVALID_ARGS, "Should reject NULL context");
    
    /* Test accept (will likely fail without proper setup) */
    result = ssh_accept(ctx);
    /* Don't assert success since we don't have proper SSH server setup */
    /* Just ensure it doesn't crash */
    test_assert(result != 0, "Accept should fail without proper SSH setup");
    
    ssh_context_destroy(ctx);
#else
    test_assert(result == SEED_ERROR_NOT_IMPLEMENTED, "Should return not implemented without libssh");
    
    /* Test without libssh support */
    result = ssh_accept(NULL);
    test_assert(result == SEED_ERROR_NOT_IMPLEMENTED, "Should return not implemented");
#endif
    
    ssh_encrypt_cleanup();
    printf("✓ SSH server mode tests passed\n");
}

/* Test runner main function for integration */
int test_ssh_encrypt_main(void)
{
    printf("Starting SSH encryption module tests...\n\n");
    
    test_ssh_init_cleanup();
    test_ssh_context_lifecycle();
    test_ssh_connection_functions();
    test_ssh_authentication();
    test_ssh_data_transfer();
    test_ssh_get_info();
    test_ssh_server_mode();
    
    printf("\n✅ All SSH encryption tests passed!\n");
    return 0;
}

/* Main test function for standalone execution */
int main(void)
{
    return test_ssh_encrypt_main();
}