/**
 * @file test_auth_encrypted_simple.c
 * @brief Simple tests for encrypted authentication file functionality
 * @author Seed Development Team
 * @date 2025
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* Include our auth header */
#include "../include/auth.h"

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

int main(void)
{
    printf("=== Simple Encrypted Auth File Tests ===\n");
    
    /* Test 1: Create test auth database */
    printf("Testing auth database creation...\n");
    struct auth_db db1, db2;
    auth_db_init(&db1);
    
    /* Add test users */
    int ret = auth_db_add_user(&db1, "alice", "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.alice_token");
    assert(ret == 0);
    
    ret = auth_db_add_user(&db1, "bob", "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.bob_token");
    assert(ret == 0);
    
    ret = auth_db_add_user(&db1, "charlie", "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.charlie_token");
    assert(ret == 0);
    
    assert(db1.user_count == 3);
    printf("✓ Auth database creation with 3 users\n");
    
    /* Test 2: Save to encrypted file */
    printf("Testing encrypted auth file save...\n");
    const char *test_file = "test_auth_encrypted.bin";
    const char *test_password = "secure_auth_password_123";
    
    ret = auth_db_save_encrypted(test_file, test_password, &db1);
    assert(ret == 0);
    printf("✓ Encrypted auth file save\n");
    
    /* Test 3: Load from encrypted file */
    printf("Testing encrypted auth file load...\n");
    auth_db_init(&db2);
    
    ret = auth_db_load_encrypted(test_file, test_password, &db2);
    assert(ret == 0);
    assert(db2.user_count == 3);
    
    /* Verify users were loaded correctly */
    struct user_credential user;
    ret = auth_db_find_user(&db2, "alice", &user);
    assert(ret == 0);
    assert(strcmp(user.username, "alice") == 0);
    assert(strcmp(user.token, "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.alice_token") == 0);
    
    ret = auth_db_find_user(&db2, "bob", &user);
    assert(ret == 0);
    assert(strcmp(user.username, "bob") == 0);
    
    ret = auth_db_find_user(&db2, "charlie", &user);
    assert(ret == 0);
    assert(strcmp(user.username, "charlie") == 0);
    
    printf("✓ Encrypted auth file load with correct data\n");
    
    /* Test 4: Test with wrong password */
    printf("Testing encrypted auth file with wrong password...\n");
    struct auth_db db3;
    auth_db_init(&db3);
    
    ret = auth_db_load_encrypted(test_file, "wrong_password", &db3);
    assert(ret != 0); /* Should fail */
    printf("✓ Wrong password correctly rejected\n");
    
    /* Test 5: Test empty database encryption */
    printf("Testing empty database encryption...\n");
    struct auth_db empty_db;
    auth_db_init(&empty_db);
    
    const char *empty_file = "test_empty_encrypted.bin";
    ret = auth_db_save_encrypted(empty_file, test_password, &empty_db);
    assert(ret == 0); /* Should succeed even with empty database */
    
    struct auth_db loaded_empty;
    ret = auth_db_load_encrypted(empty_file, test_password, &loaded_empty);
    assert(ret == 0);
    assert(loaded_empty.user_count == 0);
    printf("✓ Empty database encryption\n");
    
    /* Test 6: Test round-trip integrity */
    printf("Testing round-trip data integrity...\n");
    for (int i = 0; i < db1.user_count; i++) {
        /* Find corresponding user in loaded database */
        struct user_credential orig_user = db1.users[i];
        struct user_credential loaded_user;
        
        ret = auth_db_find_user(&db2, orig_user.username, &loaded_user);
        assert(ret == 0);
        assert(strcmp(orig_user.username, loaded_user.username) == 0);
        assert(strcmp(orig_user.token, loaded_user.token) == 0);
    }
    printf("✓ Round-trip data integrity\n");
    
    /* Test 7: Test different passwords produce different encrypted files */
    printf("Testing different passwords produce different encryption...\n");
    const char *test_file2 = "test_auth_encrypted2.bin";
    const char *test_password2 = "different_password_456";
    
    ret = auth_db_save_encrypted(test_file2, test_password2, &db1);
    assert(ret == 0);
    
    /* Read both files as binary and compare */
    FILE *f1 = fopen(test_file, "rb");
    FILE *f2 = fopen(test_file2, "rb");
    assert(f1 && f2);
    
    fseek(f1, 0, SEEK_END);
    fseek(f2, 0, SEEK_END);
    long size1 = ftell(f1);
    long size2 = ftell(f2);
    assert(size1 == size2); /* Same data should produce same size */
    
    fseek(f1, 0, SEEK_SET);
    fseek(f2, 0, SEEK_SET);
    
    char *data1 = malloc(size1);
    char *data2 = malloc(size2);
    fread(data1, 1, size1, f1);
    fread(data2, 1, size2, f2);
    fclose(f1);
    fclose(f2);
    
    /* Different passwords should produce different encrypted content */
    assert(memcmp(data1, data2, size1) != 0);
    free(data1);
    free(data2);
    printf("✓ Different passwords produce different encryption\n");
    
    /* Cleanup */
    auth_db_free(&db1);
    auth_db_free(&db2);
    auth_db_free(&db3);
    auth_db_free(&empty_db);
    auth_db_free(&loaded_empty);
    
    /* Remove test files */
    remove(test_file);
    remove(test_file2);
    remove(empty_file);
    
    printf("\n=== All Encrypted Auth File Tests Passed ===\n");
    return 0;
}