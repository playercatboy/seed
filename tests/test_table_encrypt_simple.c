/**
 * @file test_table_encrypt_simple.c
 * @brief Simple tests for table encryption functionality
 * @author Seed Development Team
 * @date 2025
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* Include our table encryption header */
#include "../include/table_encrypt.h"

/* Simple logging for tests */
void log_info(const char *fmt, ...) { /* stub */ }
void log_error(const char *fmt, ...) { /* stub */ }
void log_debug(const char *fmt, ...) { /* stub */ }

int main(void)
{
    printf("=== Simple Table Encryption Tests ===\n");
    
    /* Test 1: Initialize table encryption module */
    printf("Testing table encryption initialization...\n");
    int ret = table_encrypt_init();
    assert(ret == 0);
    printf("✓ Table encryption initialization\n");
    
    /* Test 2: Generate table from password */
    printf("Testing table generation from password...\n");
    uint8_t table[TABLE_KEY_SIZE];
    ret = table_generate_from_password("test_password123", table);
    assert(ret == 0);
    printf("✓ Table generation from password\n");
    
    /* Test 3: Validate generated table */
    printf("Testing table validation...\n");
    bool valid = table_validate(table);
    assert(valid == true);
    printf("✓ Table validation\n");
    
    /* Test 4: Create inverse table */
    printf("Testing inverse table creation...\n");
    uint8_t decrypt_table[TABLE_KEY_SIZE];
    ret = table_create_inverse(table, decrypt_table);
    assert(ret == 0);
    
    /* Validate inverse table */
    valid = table_validate(decrypt_table);
    assert(valid == true);
    printf("✓ Inverse table creation\n");
    
    /* Test 5: Create encryption context from password */
    printf("Testing context creation from password...\n");
    struct table_encrypt_context *ctx = NULL;
    ret = table_context_create("test_password123", &ctx);
    assert(ret == 0);
    assert(ctx != NULL);
    assert(ctx->initialized == true);
    printf("✓ Context creation from password\n");
    
    /* Test 6: Encrypt and decrypt data (in-place) */
    printf("Testing in-place encryption and decryption...\n");
    uint8_t test_data[] = "Hello, World! This is a test message for table encryption.";
    size_t data_len = strlen((char*)test_data);
    uint8_t original_data[sizeof(test_data)];
    memcpy(original_data, test_data, sizeof(test_data));
    
    /* Encrypt */
    ret = table_encrypt_data(ctx, test_data, data_len);
    assert(ret == 0);
    
    /* Verify data changed */
    assert(memcmp(original_data, test_data, data_len) != 0);
    
    /* Decrypt */
    ret = table_decrypt_data(ctx, test_data, data_len);
    assert(ret == 0);
    
    /* Verify data restored */
    assert(memcmp(original_data, test_data, data_len) == 0);
    printf("✓ In-place encryption and decryption\n");
    
    /* Test 7: Copy-based encryption and decryption */
    printf("Testing copy-based encryption and decryption...\n");
    uint8_t input_data[] = "Copy encryption test data";
    uint8_t encrypted_data[sizeof(input_data)];
    uint8_t decrypted_data[sizeof(input_data)];
    size_t copy_len = strlen((char*)input_data);
    
    /* Encrypt copy */
    ret = table_encrypt_copy(ctx, input_data, encrypted_data, copy_len);
    assert(ret == 0);
    
    /* Verify encryption changed data */
    assert(memcmp(input_data, encrypted_data, copy_len) != 0);
    
    /* Decrypt copy */
    ret = table_decrypt_copy(ctx, encrypted_data, decrypted_data, copy_len);
    assert(ret == 0);
    
    /* Verify decryption restored data */
    assert(memcmp(input_data, decrypted_data, copy_len) == 0);
    printf("✓ Copy-based encryption and decryption\n");
    
    /* Test 8: Base64 export/import */
    printf("Testing base64 export/import...\n");
    char base64_table[400];
    ret = table_export_base64(ctx->encrypt_table, base64_table, sizeof(base64_table));
    assert(ret == 0);
    
    uint8_t imported_table[TABLE_KEY_SIZE];
    ret = table_import_base64(base64_table, imported_table);
    assert(ret == 0);
    
    /* Verify imported table matches original */
    assert(memcmp(ctx->encrypt_table, imported_table, TABLE_KEY_SIZE) == 0);
    printf("✓ Base64 export/import\n");
    
    /* Test 9: Random table generation */
    printf("Testing random table generation...\n");
    uint8_t random_table[TABLE_KEY_SIZE];
    ret = table_generate_random(random_table);
    assert(ret == 0);
    
    valid = table_validate(random_table);
    assert(valid == true);
    printf("✓ Random table generation\n");
    
    /* Test 10: Context from raw key */
    printf("Testing context creation from raw key...\n");
    struct table_encrypt_context *ctx2 = NULL;
    ret = table_context_create_from_key(random_table, &ctx2);
    assert(ret == 0);
    assert(ctx2 != NULL);
    assert(ctx2->initialized == true);
    
    /* Verify table matches */
    assert(memcmp(ctx2->encrypt_table, random_table, TABLE_KEY_SIZE) == 0);
    printf("✓ Context creation from raw key\n");
    
    /* Cleanup */
    table_context_destroy(ctx);
    table_context_destroy(ctx2);
    table_encrypt_cleanup();
    
    printf("\n=== All Table Encryption Tests Passed ===\n");
    return 0;
}