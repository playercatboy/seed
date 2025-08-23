/**
 * @file test_jwt.c
 * @brief Unit tests for JWT module
 * @author Seed Development Team
 * @date 2025
 */

#include "test_framework.h"
#include "../include/jwt.h"
#include "../include/log.h"

/**
 * @brief Test password hashing
 */
static void test_password_hashing(void)
{
    TEST_CASE("password_hashing");
    
    unsigned char hash1[32];
    unsigned char hash2[32];
    char hash_hex1[65];
    char hash_hex2[65];
    int result;
    
    /* Test basic password hashing */
    result = jwt_hash_password("testpassword", hash1, hash_hex1);
    ASSERT_EQUAL(SEED_OK, result, "Password hashing should succeed");
    ASSERT_EQUAL(64, strlen(hash_hex1), "Hash hex should be 64 characters");
    
    /* Test same password produces same hash */
    result = jwt_hash_password("testpassword", hash2, hash_hex2);
    ASSERT_EQUAL(SEED_OK, result, "Second password hashing should succeed");
    ASSERT_STR_EQUAL(hash_hex1, hash_hex2, "Same password should produce same hash");
    ASSERT_TRUE(memcmp(hash1, hash2, 32) == 0, "Binary hashes should be identical");
    
    /* Test different password produces different hash */
    result = jwt_hash_password("differentpassword", hash2, hash_hex2);
    ASSERT_EQUAL(SEED_OK, result, "Different password hashing should succeed");
    ASSERT_STR_NOT_EQUAL(hash_hex1, hash_hex2, "Different passwords should produce different hashes");
    ASSERT_FALSE(memcmp(hash1, hash2, 32) == 0, "Binary hashes should be different");
}

/**
 * @brief Test JWT token generation
 */
static void test_jwt_generation(void)
{
    TEST_CASE("jwt_generation");
    
    char token1[MAX_JWT_LENGTH];
    char token2[MAX_JWT_LENGTH];
    int result;
    
    /* Test basic JWT generation */
    result = jwt_generate("password123", token1, sizeof(token1));
    ASSERT_EQUAL(SEED_OK, result, "JWT generation should succeed");
    ASSERT_TRUE(strlen(token1) > 0, "JWT token should not be empty");
    ASSERT_TRUE(strlen(token1) < MAX_JWT_LENGTH, "JWT token should fit in buffer");
    
    /* Test same password produces same token structure (but different timestamps) */
    result = jwt_generate("password123", token2, sizeof(token2));
    ASSERT_EQUAL(SEED_OK, result, "Second JWT generation should succeed");
    ASSERT_TRUE(strlen(token2) > 0, "Second JWT token should not be empty");
    
    /* Tokens should have JWT structure (header.payload.signature) */
    char *dot1 = strchr(token1, '.');
    ASSERT_TRUE(dot1 != NULL, "JWT should have first dot separator");
    if (dot1) {
        char *dot2 = strchr(dot1 + 1, '.');
        ASSERT_TRUE(dot2 != NULL, "JWT should have second dot separator");
    }
    
    /* Test different password produces different token */
    result = jwt_generate("differentpassword", token2, sizeof(token2));
    ASSERT_EQUAL(SEED_OK, result, "Different password JWT generation should succeed");
    ASSERT_STR_NOT_EQUAL(token1, token2, "Different passwords should produce different tokens");
}

/**
 * @brief Test JWT token verification
 */
static void test_jwt_verification(void)
{
    TEST_CASE("jwt_verification");
    
    char token[MAX_JWT_LENGTH];
    int result;
    
    /* Generate a token */
    result = jwt_generate("testpassword", token, sizeof(token));
    ASSERT_EQUAL(SEED_OK, result, "JWT generation should succeed");
    
    /* Verify correct password */
    result = jwt_verify("testpassword", token);
    ASSERT_EQUAL(SEED_OK, result, "Correct password verification should succeed");
    
    /* Verify incorrect password */
    result = jwt_verify("wrongpassword", token);
    ASSERT_NOT_EQUAL(SEED_OK, result, "Wrong password verification should fail");
    
    /* Test edge cases */
    result = jwt_verify("", token);
    ASSERT_NOT_EQUAL(SEED_OK, result, "Empty password verification should fail");
    
    result = jwt_verify("testpassword", "");
    ASSERT_NOT_EQUAL(SEED_OK, result, "Empty token verification should fail");
    
    result = jwt_verify("testpassword", "invalid.jwt.token");
    ASSERT_NOT_EQUAL(SEED_OK, result, "Invalid token verification should fail");
}

/**
 * @brief Test empty and null inputs
 */
static void test_null_inputs(void)
{
    TEST_CASE("null_inputs");
    
    char token[MAX_JWT_LENGTH];
    unsigned char hash[32];
    char hash_hex[65];
    int result;
    
    /* Test NULL password hashing */
    result = jwt_hash_password(NULL, hash, hash_hex);
    ASSERT_NOT_EQUAL(SEED_OK, result, "NULL password hashing should fail");
    
    result = jwt_hash_password("test", NULL, hash_hex);
    ASSERT_NOT_EQUAL(SEED_OK, result, "NULL hash buffer hashing should fail");
    
    result = jwt_hash_password("test", hash, NULL);
    ASSERT_NOT_EQUAL(SEED_OK, result, "NULL hex buffer hashing should fail");
    
    /* Test NULL JWT generation */
    result = jwt_generate(NULL, token, sizeof(token));
    ASSERT_NOT_EQUAL(SEED_OK, result, "NULL password JWT generation should fail");
    
    result = jwt_generate("test", NULL, sizeof(token));
    ASSERT_NOT_EQUAL(SEED_OK, result, "NULL token buffer JWT generation should fail");
    
    /* Test NULL JWT verification */
    result = jwt_verify(NULL, "token");
    ASSERT_NOT_EQUAL(SEED_OK, result, "NULL password JWT verification should fail");
    
    result = jwt_verify("password", NULL);
    ASSERT_NOT_EQUAL(SEED_OK, result, "NULL token JWT verification should fail");
}

/**
 * @brief Test buffer size limits
 */
static void test_buffer_limits(void)
{
    TEST_CASE("buffer_limits");
    
    char small_token[10];  /* Too small for JWT */
    int result;
    
    /* Test small token buffer */
    result = jwt_generate("password", small_token, sizeof(small_token));
    ASSERT_NOT_EQUAL(SEED_OK, result, "Small token buffer should fail");
    
    /* Test minimum required size */
    char min_token[MAX_JWT_LENGTH];
    result = jwt_generate("password", min_token, MAX_JWT_LENGTH);
    ASSERT_EQUAL(SEED_OK, result, "Minimum size buffer should succeed");
}

/**
 * @brief Test special characters in passwords
 */
static void test_special_characters(void)
{
    TEST_CASE("special_characters");
    
    char token[MAX_JWT_LENGTH];
    int result;
    
    /* Test password with special characters */
    result = jwt_generate("!@#$%^&*()_+-=[]{}|;':\",./<>?", token, sizeof(token));
    ASSERT_EQUAL(SEED_OK, result, "Special characters password should work");
    
    /* Verify it */
    result = jwt_verify("!@#$%^&*()_+-=[]{}|;':\",./<>?", token);
    ASSERT_EQUAL(SEED_OK, result, "Special characters verification should work");
    
    /* Test unicode characters (if supported) */
    result = jwt_generate("测试密码", token, sizeof(token));
    ASSERT_EQUAL(SEED_OK, result, "Unicode password should work");
    
    result = jwt_verify("测试密码", token);
    ASSERT_EQUAL(SEED_OK, result, "Unicode verification should work");
}

/**
 * @brief Main test function
 */
int test_jwt_main(void)
{
    test_init();
    
    /* Suppress logging during tests */
    log_init(LOG_ERROR);
    
    TEST_SUITE("JWT Module Tests");
    
    test_password_hashing();
    test_jwt_generation();
    test_jwt_verification();
    test_null_inputs();
    test_buffer_limits();
    test_special_characters();
    
    TEST_SUMMARY();
    
    return test_exit_code();
}