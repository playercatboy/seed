/**
 * @file test_encrypt_core_simple.c
 * @brief Simple tests for core encryption functionality without dependencies
 * @author Seed Development Team
 * @date 2025
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* Include only the table encryption header directly */
#include "../include/table_encrypt.h"

/* Simple logging for tests */
void log_init() { /* stub */ }
void log_set_level(int level) { /* stub */ }
int log_get_level() { return 0; }
void log_write(int level, const char *file, int line, const char *fmt, ...) { /* stub */ }
void log_cleanup() { /* stub */ }
void log_info(const char *fmt, ...) { /* stub */ }
void log_error(const char *fmt, ...) { /* stub */ }
void log_debug(const char *fmt, ...) { /* stub */ }
void log_warning(const char *fmt, ...) { /* stub */ }

/* Mock config structures for testing */
enum proxy_type {
    PROXY_TYPE_TCP = 0,
    PROXY_TYPE_UDP
};

enum encrypt_impl {
    ENCRYPT_NONE = 0,
    ENCRYPT_TLS,
    ENCRYPT_SSH,
    ENCRYPT_TABLE
};

struct proxy_config {
    char name[64];
    enum proxy_type type;
    bool encrypt;
    enum encrypt_impl encrypt_impl;
};

/* Test the core table encryption functionality */
int main(void)
{
    printf("=== Simple Core Encryption Tests ===\n");
    
    /* Test 1: Initialize table encryption module */
    printf("Testing table encryption initialization...\n");
    int ret = table_encrypt_init();
    assert(ret == 0);
    printf("✓ Table encryption initialization\n");
    
    /* Test 2: Create table encryption context */
    printf("Testing table encryption context creation...\n");
    struct table_encrypt_context *ctx = NULL;
    ret = table_context_create("encryption_test_password", &ctx);
    assert(ret == 0);
    assert(ctx != NULL);
    printf("✓ Table encryption context creation\n");
    
    /* Test 3: Test encryption/decryption with copy functions */
    printf("Testing table encryption copy functions...\n");
    const char *test_message = "This is a test message for encryption!";
    size_t msg_len = strlen(test_message);
    
    uint8_t encrypted_data[256];
    uint8_t decrypted_data[256];
    
    /* Encrypt */
    ret = table_encrypt_copy(ctx, (const uint8_t*)test_message, encrypted_data, msg_len);
    assert(ret == 0);
    assert(memcmp(test_message, encrypted_data, msg_len) != 0); /* Should be different */
    
    /* Decrypt */
    ret = table_decrypt_copy(ctx, encrypted_data, decrypted_data, msg_len);
    assert(ret == 0);
    assert(memcmp(test_message, decrypted_data, msg_len) == 0); /* Should be same */
    printf("✓ Table encryption copy functions\n");
    
    /* Test 4: Test in-place encryption/decryption */
    printf("Testing table encryption in-place functions...\n");
    uint8_t test_data[256];
    strcpy((char*)test_data, test_message);
    
    uint8_t original_data[256];
    memcpy(original_data, test_data, msg_len);
    
    /* Encrypt in-place */
    ret = table_encrypt_data(ctx, test_data, msg_len);
    assert(ret == 0);
    assert(memcmp(original_data, test_data, msg_len) != 0); /* Should be different */
    
    /* Decrypt in-place */
    ret = table_decrypt_data(ctx, test_data, msg_len);
    assert(ret == 0);
    assert(memcmp(original_data, test_data, msg_len) == 0); /* Should be same */
    printf("✓ Table encryption in-place functions\n");
    
    /* Test 5: Test large data encryption */
    printf("Testing large data encryption...\n");
    const size_t large_size = 32768;
    uint8_t *large_data = malloc(large_size);
    uint8_t *large_backup = malloc(large_size);
    
    if (large_data && large_backup) {
        /* Fill with pattern */
        for (size_t i = 0; i < large_size; i++) {
            large_data[i] = (uint8_t)(i % 256);
        }
        memcpy(large_backup, large_data, large_size);
        
        /* Encrypt and decrypt */
        ret = table_encrypt_data(ctx, large_data, large_size);
        assert(ret == 0);
        assert(memcmp(large_backup, large_data, large_size) != 0);
        
        ret = table_decrypt_data(ctx, large_data, large_size);
        assert(ret == 0);
        assert(memcmp(large_backup, large_data, large_size) == 0);
        
        free(large_data);
        free(large_backup);
        printf("✓ Large data encryption\n");
    } else {
        printf("⚠ Skipped large data test (memory allocation failed)\n");
    }
    
    /* Test 6: Test multiple contexts with different passwords */
    printf("Testing multiple encryption contexts...\n");
    struct table_encrypt_context *ctx1 = NULL;
    struct table_encrypt_context *ctx2 = NULL;
    
    ret = table_context_create("password1", &ctx1);
    assert(ret == 0);
    
    ret = table_context_create("password2", &ctx2);
    assert(ret == 0);
    
    /* Test that different passwords produce different encryption */
    const char *multi_test = "Multi-context test data";
    size_t multi_len = strlen(multi_test);
    
    uint8_t encrypted1[256];
    uint8_t encrypted2[256];
    
    ret = table_encrypt_copy(ctx1, (const uint8_t*)multi_test, encrypted1, multi_len);
    assert(ret == 0);
    
    ret = table_encrypt_copy(ctx2, (const uint8_t*)multi_test, encrypted2, multi_len);
    assert(ret == 0);
    
    /* Different passwords should produce different results */
    assert(memcmp(encrypted1, encrypted2, multi_len) != 0);
    printf("✓ Multiple encryption contexts\n");
    
    /* Test 7: Test table export/import */
    printf("Testing table export/import...\n");
    char base64_table[400];
    ret = table_export_base64(ctx->encrypt_table, base64_table, sizeof(base64_table));
    assert(ret == 0);
    
    uint8_t imported_table[TABLE_KEY_SIZE];
    ret = table_import_base64(base64_table, imported_table);
    assert(ret == 0);
    
    /* Verify imported table matches */
    assert(memcmp(ctx->encrypt_table, imported_table, TABLE_KEY_SIZE) == 0);
    printf("✓ Table export/import\n");
    
    /* Cleanup */
    table_context_destroy(ctx);
    table_context_destroy(ctx1);
    table_context_destroy(ctx2);
    table_encrypt_cleanup();
    
    printf("\n=== All Core Encryption Tests Passed ===\n");
    return 0;
}