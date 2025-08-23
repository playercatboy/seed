/**
 * @file test_client.c
 * @brief Client mode unit tests
 * @author Seed Development Team  
 * @date 2025
 */

#include "test_framework.h"
#include "client.h"
#include "config.h"
#include "log.h"

/**
 * @brief Mock network context for testing
 */
static struct network_context mock_network = { NULL };

/**
 * @brief Test client initialization
 */
TEST_CASE(test_client_init)
{
    struct client_session session;
    struct seed_config config;
    
    /* Initialize minimal config */
    memset(&config, 0, sizeof(config));
    config.mode = MODE_CLIENT;
    
    /* Test null arguments */
    ASSERT_EQUAL(client_init(NULL, &mock_network, &config), SEED_ERROR_INVALID_ARGS);
    ASSERT_EQUAL(client_init(&session, NULL, &config), SEED_ERROR_INVALID_ARGS);
    ASSERT_EQUAL(client_init(&session, &mock_network, NULL), SEED_ERROR_INVALID_ARGS);
    
    printf("✓ Client init parameter validation\n");
}

/**
 * @brief Test proxy instance management
 */
TEST_CASE(test_client_proxy_management)
{
    struct client_session session;
    
    /* Initialize session structure */
    memset(&session, 0, sizeof(session));
    session.proxy_count = 0;
    
    /* Test adding proxy instances */
    int ret = client_add_proxy(&session, "test-proxy", PROXY_TYPE_TCP,
                              "127.0.0.1", 8080, 8080, true, ENCRYPT_IMPL_TLS);
    ASSERT_EQUAL(ret, SEED_OK);
    ASSERT_EQUAL(session.proxy_count, 1);
    
    /* Verify proxy configuration */
    struct proxy_instance *proxy = &session.proxies[0];
    ASSERT_STR_EQUAL(proxy->name, "test-proxy");
    ASSERT_EQUAL(proxy->type, PROXY_TYPE_TCP);
    ASSERT_STR_EQUAL(proxy->local_addr, "127.0.0.1");
    ASSERT_EQUAL(proxy->local_port, 8080);
    ASSERT_EQUAL(proxy->remote_port, 8080);
    ASSERT_TRUE(proxy->encrypt);
    ASSERT_EQUAL(proxy->encrypt_impl, ENCRYPT_IMPL_TLS);
    ASSERT_FALSE(proxy->active);
    
    printf("✓ Proxy instance management\n");
    
    /* Test adding multiple proxies */
    ret = client_add_proxy(&session, "udp-proxy", PROXY_TYPE_UDP,
                          "127.0.0.1", 9090, 9090, false, ENCRYPT_IMPL_NONE);
    ASSERT_EQUAL(ret, SEED_OK);
    ASSERT_EQUAL(session.proxy_count, 2);
    
    printf("✓ Multiple proxy instances\n");
    
    /* Test parameter validation */
    ret = client_add_proxy(NULL, "test", PROXY_TYPE_TCP, "127.0.0.1", 80, 80, false, ENCRYPT_IMPL_NONE);
    ASSERT_EQUAL(ret, SEED_ERROR_INVALID_ARGS);
    
    ret = client_add_proxy(&session, NULL, PROXY_TYPE_TCP, "127.0.0.1", 80, 80, false, ENCRYPT_IMPL_NONE);
    ASSERT_EQUAL(ret, SEED_ERROR_INVALID_ARGS);
    
    ret = client_add_proxy(&session, "test", PROXY_TYPE_TCP, NULL, 80, 80, false, ENCRYPT_IMPL_NONE);
    ASSERT_EQUAL(ret, SEED_ERROR_INVALID_ARGS);
    
    printf("✓ Proxy parameter validation\n");
}

/**
 * @brief Test client state management
 */
TEST_CASE(test_client_state_management)
{
    struct client_session session;
    
    /* Initialize session */
    memset(&session, 0, sizeof(session));
    session.state = CLIENT_STATE_DISCONNECTED;
    session.proxy_count = 2;
    
    /* Initialize proxy instances */
    session.proxies[0].active = false;
    session.proxies[1].active = false;
    strncpy(session.proxies[0].name, "proxy1", sizeof(session.proxies[0].name));
    strncpy(session.proxies[1].name, "proxy2", sizeof(session.proxies[1].name));
    
    /* Test parameter validation for proxy operations */
    ASSERT_EQUAL(client_start_proxies(NULL), SEED_ERROR_INVALID_ARGS);
    ASSERT_EQUAL(client_stop_proxies(NULL), SEED_ERROR_INVALID_ARGS);
    
    /* Test starting proxies with wrong state */
    session.state = CLIENT_STATE_DISCONNECTED;
    ASSERT_EQUAL(client_start_proxies(&session), SEED_ERROR);
    
    /* Test with authenticated state */
    session.state = CLIENT_STATE_AUTHENTICATED;
    ASSERT_EQUAL(client_start_proxies(&session), SEED_OK);
    ASSERT_TRUE(session.proxies[0].active);
    ASSERT_TRUE(session.proxies[1].active);
    
    printf("✓ Proxy state management\n");
    
    /* Test stopping proxies */
    ASSERT_EQUAL(client_stop_proxies(&session), SEED_OK);
    ASSERT_FALSE(session.proxies[0].active);
    ASSERT_FALSE(session.proxies[1].active);
    
    printf("✓ Client state management\n");
}

/**
 * @brief Test client message handling  
 */
TEST_CASE(test_client_message_handling)
{
    struct client_session session;
    struct protocol_message msg;
    
    /* Initialize session */
    memset(&session, 0, sizeof(session));
    session.state = CLIENT_STATE_CONNECTING;
    
    /* Test parameter validation */
    ASSERT_EQUAL(client_handle_message(NULL, &msg), SEED_ERROR_INVALID_ARGS);
    ASSERT_EQUAL(client_handle_message(&session, NULL), SEED_ERROR_INVALID_ARGS);
    
    /* Test HELLO response */
    memset(&msg, 0, sizeof(msg));
    msg.header.type = PROTOCOL_TYPE_HELLO_RESPONSE;
    
    ASSERT_EQUAL(client_handle_message(&session, &msg), SEED_OK);
    ASSERT_EQUAL(session.state, CLIENT_STATE_AUTHENTICATED);
    
    printf("✓ HELLO response handling\n");
    
    /* Test authentication response - success */
    msg.header.type = PROTOCOL_TYPE_AUTH_RESPONSE;
    msg.header.flags = 0;  /* Success */
    session.state = CLIENT_STATE_AUTHENTICATING;
    
    ASSERT_EQUAL(client_handle_message(&session, &msg), SEED_OK);
    ASSERT_EQUAL(session.state, CLIENT_STATE_AUTHENTICATED);
    
    printf("✓ Authentication success handling\n");
    
    /* Test authentication response - failure */
    msg.header.flags = 1;  /* Failure */
    session.state = CLIENT_STATE_AUTHENTICATING;
    
    ASSERT_EQUAL(client_handle_message(&session, &msg), SEED_OK);
    ASSERT_EQUAL(session.state, CLIENT_STATE_ERROR);
    
    printf("✓ Authentication failure handling\n");
    
    /* Test error message */
    msg.header.type = PROTOCOL_TYPE_ERROR;
    session.state = CLIENT_STATE_AUTHENTICATED;
    
    ASSERT_EQUAL(client_handle_message(&session, &msg), SEED_OK);
    ASSERT_EQUAL(session.state, CLIENT_STATE_ERROR);
    
    printf("✓ Error message handling\n");
}

/**
 * @brief Test client cleanup
 */
TEST_CASE(test_client_cleanup)
{
    struct client_session session;
    
    /* Initialize session with sensitive data */
    memset(&session, 0, sizeof(session));
    strcpy(session.password, "sensitive_password");
    session.state = CLIENT_STATE_AUTHENTICATED;
    
    /* Test cleanup with null pointer */
    client_cleanup(NULL);  /* Should not crash */
    
    /* Test normal cleanup */
    client_cleanup(&session);
    
    /* Verify password is cleared */
    for (size_t i = 0; i < sizeof(session.password); i++) {
        ASSERT_EQUAL(session.password[i], 0);
    }
    
    printf("✓ Client cleanup and security\n");
}

/**
 * @brief Main test suite for client functionality
 */
TEST_SUITE(client_tests)
{
    log_init(LOG_ERROR);  /* Suppress log output during tests */
    
    printf("=== Client Module Tests ===\n");
    
    test_client_init();
    test_client_proxy_management();
    test_client_state_management(); 
    test_client_message_handling();
    test_client_cleanup();
    
    printf("=== Client Tests Complete ===\n\n");
}

#ifndef STANDALONE_TEST
int main(void)
{
    client_tests();
    return 0;
}
#endif