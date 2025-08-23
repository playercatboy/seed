/**
 * @file test_protocol.c
 * @brief Unit tests for protocol module
 * @author Seed Development Team
 * @date 2025
 */

#include "test_framework.h"
#include "../include/protocol.h"
#include "../include/log.h"

/**
 * @brief Test protocol message initialization
 */
static void test_message_init(void)
{
    TEST_CASE("message_init");
    
    struct protocol_message msg;
    
    /* Test hello message initialization */
    protocol_init_message(&msg, MSG_TYPE_HELLO);
    
    ASSERT_EQUAL(PROTOCOL_MAGIC, msg.header.magic, "Magic number should be set");
    ASSERT_EQUAL(PROTOCOL_VERSION, msg.header.version, "Version should be set");
    ASSERT_EQUAL(MSG_TYPE_HELLO, msg.header.type, "Message type should be set");
    ASSERT_EQUAL(MSG_FLAG_NONE, msg.header.flags, "Flags should be none");
    ASSERT_TRUE(msg.header.sequence > 0, "Sequence should be non-zero");
    ASSERT_EQUAL(0, msg.header.length, "Length should be zero initially");
    
    /* Test that sequence numbers increment */
    struct protocol_message msg2;
    protocol_init_message(&msg2, MSG_TYPE_AUTH_REQUEST);
    ASSERT_TRUE(msg2.header.sequence > msg.header.sequence, "Sequence should increment");
}

/**
 * @brief Test protocol checksum calculation
 */
static void test_checksum(void)
{
    TEST_CASE("checksum");
    
    struct protocol_message msg;
    uint32_t checksum1, checksum2;
    
    protocol_init_message(&msg, MSG_TYPE_HELLO);
    
    /* Calculate checksum */
    checksum1 = protocol_checksum(&msg.header);
    ASSERT_TRUE(checksum1 != 0, "Checksum should be non-zero");
    
    /* Same header should produce same checksum */
    checksum2 = protocol_checksum(&msg.header);
    ASSERT_EQUAL(checksum1, checksum2, "Same header should produce same checksum");
    
    /* Modify header and check different checksum */
    msg.header.type = MSG_TYPE_AUTH_REQUEST;
    checksum2 = protocol_checksum(&msg.header);
    ASSERT_NOT_EQUAL(checksum1, checksum2, "Modified header should produce different checksum");
}

/**
 * @brief Test message serialization and deserialization
 */
static void test_serialization(void)
{
    TEST_CASE("serialization");
    
    struct protocol_message msg, decoded_msg;
    uint8_t buffer[1024];
    int serialized_len, deserialized_len;
    
    /* Create hello message */
    protocol_init_message(&msg, MSG_TYPE_HELLO);
    msg.payload.hello.protocol_version = PROTOCOL_VERSION;
    strcpy(msg.payload.hello.client_id, "test_client_123");
    msg.payload.hello.capabilities = 0x12345678;
    
    /* Serialize message */
    serialized_len = protocol_serialize(&msg, buffer, sizeof(buffer));
    ASSERT_TRUE(serialized_len > 0, "Serialization should succeed");
    ASSERT_TRUE(serialized_len <= sizeof(buffer), "Serialized data should fit in buffer");
    
    /* Deserialize message */
    deserialized_len = protocol_deserialize(&decoded_msg, buffer, serialized_len);
    ASSERT_EQUAL(serialized_len, deserialized_len, "Deserialized length should match");
    
    /* Verify header */
    ASSERT_EQUAL(msg.header.magic, decoded_msg.header.magic, "Magic should match");
    ASSERT_EQUAL(msg.header.version, decoded_msg.header.version, "Version should match");
    ASSERT_EQUAL(msg.header.type, decoded_msg.header.type, "Type should match");
    ASSERT_EQUAL(msg.header.sequence, decoded_msg.header.sequence, "Sequence should match");
    
    /* Verify payload */
    ASSERT_EQUAL(msg.payload.hello.protocol_version, decoded_msg.payload.hello.protocol_version, "Protocol version should match");
    ASSERT_STR_EQUAL(msg.payload.hello.client_id, decoded_msg.payload.hello.client_id, "Client ID should match");
    ASSERT_EQUAL(msg.payload.hello.capabilities, decoded_msg.payload.hello.capabilities, "Capabilities should match");
}

/**
 * @brief Test different message types
 */
static void test_message_types(void)
{
    TEST_CASE("message_types");
    
    struct protocol_message msg;
    uint8_t buffer[1024];
    int result;
    
    /* Test auth request */
    protocol_init_message(&msg, MSG_TYPE_AUTH_REQUEST);
    strcpy(msg.payload.auth_req.username, "testuser");
    strcpy(msg.payload.auth_req.password, "testpass");
    
    result = protocol_serialize(&msg, buffer, sizeof(buffer));
    ASSERT_TRUE(result > 0, "Auth request serialization should succeed");
    
    /* Test proxy request */
    protocol_init_message(&msg, MSG_TYPE_PROXY_REQUEST);
    strcpy(msg.payload.proxy_req.proxy_name, "http-proxy");
    msg.payload.proxy_req.proxy_type = PROXY_TYPE_TCP;
    msg.payload.proxy_req.local_port = 8080;
    msg.payload.proxy_req.remote_port = 8080;
    strcpy(msg.payload.proxy_req.local_addr, "127.0.0.1");
    
    result = protocol_serialize(&msg, buffer, sizeof(buffer));
    ASSERT_TRUE(result > 0, "Proxy request serialization should succeed");
    
    /* Test keepalive (no payload) */
    protocol_init_message(&msg, MSG_TYPE_KEEPALIVE);
    result = protocol_serialize(&msg, buffer, sizeof(buffer));
    ASSERT_TRUE(result > 0, "Keepalive serialization should succeed");
}

/**
 * @brief Test message validation
 */
static void test_message_validation(void)
{
    TEST_CASE("message_validation");
    
    struct protocol_message msg;
    int result;
    
    /* Test valid message */
    protocol_init_message(&msg, MSG_TYPE_HELLO);
    msg.header.checksum = protocol_checksum(&msg.header);
    
    result = protocol_validate_message(&msg);
    ASSERT_EQUAL(SEED_OK, result, "Valid message should pass validation");
    
    /* Test invalid magic */
    msg.header.magic = 0x12345678;
    result = protocol_validate_message(&msg);
    ASSERT_NOT_EQUAL(SEED_OK, result, "Invalid magic should fail validation");
    
    /* Reset and test invalid version */
    protocol_init_message(&msg, MSG_TYPE_HELLO);
    msg.header.version = 999;
    msg.header.checksum = protocol_checksum(&msg.header);
    result = protocol_validate_message(&msg);
    ASSERT_NOT_EQUAL(SEED_OK, result, "Invalid version should fail validation");
    
    /* Reset and test invalid message type */
    protocol_init_message(&msg, MSG_TYPE_HELLO);
    msg.header.type = MSG_TYPE_MAX + 1;
    msg.header.checksum = protocol_checksum(&msg.header);
    result = protocol_validate_message(&msg);
    ASSERT_NOT_EQUAL(SEED_OK, result, "Invalid message type should fail validation");
    
    /* Reset and test invalid checksum */
    protocol_init_message(&msg, MSG_TYPE_HELLO);
    msg.header.checksum = 0x12345678; /* Wrong checksum */
    result = protocol_validate_message(&msg);
    ASSERT_NOT_EQUAL(SEED_OK, result, "Invalid checksum should fail validation");
}

/**
 * @brief Test buffer overflow protection
 */
static void test_buffer_overflow(void)
{
    TEST_CASE("buffer_overflow");
    
    struct protocol_message msg;
    uint8_t small_buffer[10];
    int result;
    
    protocol_init_message(&msg, MSG_TYPE_HELLO);
    strcpy(msg.payload.hello.client_id, "test_client");
    
    /* Test serialization with too small buffer */
    result = protocol_serialize(&msg, small_buffer, sizeof(small_buffer));
    ASSERT_TRUE(result < 0, "Serialization to small buffer should fail");
    
    /* Test deserialization with insufficient data */
    uint8_t partial_buffer[sizeof(struct protocol_header) - 1];
    memset(partial_buffer, 0, sizeof(partial_buffer));
    
    result = protocol_deserialize(&msg, partial_buffer, sizeof(partial_buffer));
    ASSERT_TRUE(result < 0, "Deserialization of partial header should fail");
}

/**
 * @brief Test message type names
 */
static void test_type_names(void)
{
    TEST_CASE("type_names");
    
    const char *name;
    
    name = protocol_type_name(MSG_TYPE_HELLO);
    ASSERT_STR_EQUAL("HELLO", name, "Hello message name should be correct");
    
    name = protocol_type_name(MSG_TYPE_AUTH_REQUEST);
    ASSERT_STR_EQUAL("AUTH_REQUEST", name, "Auth request name should be correct");
    
    name = protocol_type_name(MSG_TYPE_ERROR);
    ASSERT_STR_EQUAL("ERROR", name, "Error message name should be correct");
    
    name = protocol_type_name(MSG_TYPE_MAX + 1);
    ASSERT_STR_EQUAL("INVALID", name, "Invalid message type should return INVALID");
}

/**
 * @brief Test NULL pointer handling
 */
static void test_null_pointers(void)
{
    TEST_CASE("null_pointers");
    
    struct protocol_message msg;
    uint8_t buffer[1024];
    int result;
    uint32_t checksum;
    
    /* Test NULL message initialization */
    protocol_init_message(NULL, MSG_TYPE_HELLO);
    /* Should not crash */
    
    /* Test NULL checksum calculation */
    checksum = protocol_checksum(NULL);
    ASSERT_EQUAL(0, checksum, "NULL checksum should return 0");
    
    /* Test NULL validation */
    result = protocol_validate_message(NULL);
    ASSERT_NOT_EQUAL(SEED_OK, result, "NULL message validation should fail");
    
    /* Test NULL serialization */
    protocol_init_message(&msg, MSG_TYPE_HELLO);
    result = protocol_serialize(NULL, buffer, sizeof(buffer));
    ASSERT_TRUE(result < 0, "NULL message serialization should fail");
    
    result = protocol_serialize(&msg, NULL, sizeof(buffer));
    ASSERT_TRUE(result < 0, "NULL buffer serialization should fail");
    
    /* Test NULL deserialization */
    result = protocol_deserialize(NULL, buffer, sizeof(buffer));
    ASSERT_TRUE(result < 0, "NULL message deserialization should fail");
    
    result = protocol_deserialize(&msg, NULL, sizeof(buffer));
    ASSERT_TRUE(result < 0, "NULL buffer deserialization should fail");
}

/**
 * @brief Main test function
 */
int test_protocol_main(void)
{
    test_init();
    
    /* Suppress logging during tests */
    log_init(LOG_ERROR);
    
    TEST_SUITE("Protocol Module Tests");
    
    test_message_init();
    test_checksum();
    test_serialization();
    test_message_types();
    test_message_validation();
    test_buffer_overflow();
    test_type_names();
    test_null_pointers();
    
    TEST_SUMMARY();
    
    return test_exit_code();
}