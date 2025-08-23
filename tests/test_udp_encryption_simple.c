/**
 * @file test_udp_encryption_simple.c
 * @brief Simple tests for UDP proxy encryption integration
 * @author Seed Development Team
 * @date 2025
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* Include our encryption header */
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

/* Test UDP proxy encryption integration without libuv dependencies */
int main(void)
{
    printf("=== Simple UDP Proxy Encryption Integration Tests ===\n");
    
    /* Test 1: Initialize table encryption module */
    printf("Testing table encryption initialization...\n");
    int ret = table_encrypt_init();
    assert(ret == 0);
    printf("✓ Table encryption initialization\n");
    
    /* Test 2: Create encryption context for UDP proxy */
    printf("Testing encryption context creation for UDP proxy...\n");
    struct table_encrypt_context *proxy_ctx = NULL;
    ret = table_context_create("udp_proxy_password123", &proxy_ctx);
    assert(ret == 0);
    assert(proxy_ctx != NULL);
    printf("✓ UDP proxy encryption context creation\n");
    
    /* Test 3: Simulate client-to-target packet flow (decrypt) */
    printf("Testing client-to-target packet processing...\n");
    uint8_t client_packet[] = "Hello from client to server!";
    size_t client_packet_len = strlen((char*)client_packet);
    uint8_t original_client_packet[sizeof(client_packet)];
    memcpy(original_client_packet, client_packet, sizeof(client_packet));
    
    /* First encrypt (simulate what client would do) */
    ret = table_encrypt_data(proxy_ctx, client_packet, client_packet_len);
    assert(ret == 0);
    assert(memcmp(original_client_packet, client_packet, client_packet_len) != 0);
    
    /* Then decrypt (simulate what UDP proxy would do) */
    ret = table_decrypt_data(proxy_ctx, client_packet, client_packet_len);
    assert(ret == 0);
    assert(memcmp(original_client_packet, client_packet, client_packet_len) == 0);
    printf("✓ Client-to-target packet processing\n");
    
    /* Test 4: Simulate target-to-client packet flow (encrypt) */
    printf("Testing target-to-client packet processing...\n");
    uint8_t target_packet[] = "Response from server to client!";
    size_t target_packet_len = strlen((char*)target_packet);
    uint8_t original_target_packet[sizeof(target_packet)];
    memcpy(original_target_packet, target_packet, sizeof(target_packet));
    
    /* Encrypt (simulate what UDP proxy would do before sending to client) */
    ret = table_encrypt_data(proxy_ctx, target_packet, target_packet_len);
    assert(ret == 0);
    assert(memcmp(original_target_packet, target_packet, target_packet_len) != 0);
    
    /* Decrypt (simulate what client would do) */
    ret = table_decrypt_data(proxy_ctx, target_packet, target_packet_len);
    assert(ret == 0);
    assert(memcmp(original_target_packet, target_packet, target_packet_len) == 0);
    printf("✓ Target-to-client packet processing\n");
    
    /* Test 5: Test multiple proxy instances with different passwords */
    printf("Testing multiple UDP proxy encryption contexts...\n");
    struct table_encrypt_context *proxy1_ctx = NULL;
    struct table_encrypt_context *proxy2_ctx = NULL;
    
    ret = table_context_create("proxy1_password", &proxy1_ctx);
    assert(ret == 0);
    
    ret = table_context_create("proxy2_password", &proxy2_ctx);
    assert(ret == 0);
    
    /* Test that different contexts produce different encryption */
    uint8_t test_data1[] = "Test data for proxy encryption";
    uint8_t test_data2[] = "Test data for proxy encryption";
    size_t test_len = strlen((char*)test_data1);
    
    ret = table_encrypt_data(proxy1_ctx, test_data1, test_len);
    assert(ret == 0);
    
    ret = table_encrypt_data(proxy2_ctx, test_data2, test_len);
    assert(ret == 0);
    
    /* Different passwords should produce different encrypted results */
    assert(memcmp(test_data1, test_data2, test_len) != 0);
    printf("✓ Multiple UDP proxy encryption contexts\n");
    
    /* Test 6: Test large packet encryption (simulating max UDP size) */
    printf("Testing large packet encryption...\n");
    uint8_t *large_packet = malloc(65507);  /* Max UDP payload size */
    if (large_packet) {
        /* Fill with pattern */
        for (int i = 0; i < 65507; i++) {
            large_packet[i] = (uint8_t)(i % 256);
        }
        
        /* Create backup */
        uint8_t *backup = malloc(65507);
        memcpy(backup, large_packet, 65507);
        
        /* Encrypt and decrypt */
        ret = table_encrypt_data(proxy_ctx, large_packet, 65507);
        assert(ret == 0);
        assert(memcmp(backup, large_packet, 65507) != 0);
        
        ret = table_decrypt_data(proxy_ctx, large_packet, 65507);
        assert(ret == 0);
        assert(memcmp(backup, large_packet, 65507) == 0);
        
        free(large_packet);
        free(backup);
        printf("✓ Large packet encryption\n");
    } else {
        printf("⚠ Skipped large packet test (memory allocation failed)\n");
    }
    
    /* Cleanup */
    table_context_destroy(proxy_ctx);
    table_context_destroy(proxy1_ctx);
    table_context_destroy(proxy2_ctx);
    table_encrypt_cleanup();
    
    printf("\n=== All UDP Proxy Encryption Integration Tests Passed ===\n");
    return 0;
}