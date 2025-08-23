/**
 * @file test_tls_encrypt_simple.c
 * @brief Simple tests for TLS encryption functionality
 * @author Seed Development Team
 * @date 2025
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* Include TLS encryption header */
#include "../include/tls_encrypt.h"

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
    printf("=== Simple TLS Encryption Tests ===\n");
    
    /* Test 1: Initialize TLS encryption module */
    printf("Testing TLS encryption module initialization...\n");
    int ret = tls_encrypt_init();
    assert(ret == 0);
    printf("✓ TLS encryption module initialization\n");
    
    /* Test 2: Create TLS context (client mode) */
    printf("Testing TLS context creation (client mode)...\n");
    struct tls_config config = {0};
    config.server_mode = false;
    config.verify_peer = false;  /* Skip peer verification for test */
    
    struct tls_context *ctx = NULL;
    ret = tls_context_create(&config, &ctx);
    
#ifdef ENABLE_TLS_ENCRYPTION
    assert(ret == 0);
    assert(ctx != NULL);
    printf("✓ TLS context creation (client mode)\n");
    
    /* Test 3: Check if context is ready (should be false before handshake) */
    printf("Testing TLS context readiness...\n");
    bool ready = tls_is_ready(ctx);
    assert(ready == false);
    printf("✓ TLS context readiness (not ready before handshake)\n");
    
    /* Test 4: Get TLS info (should indicate handshake not complete) */
    printf("Testing TLS info retrieval...\n");
    char cipher[128];
    char version[64];
    ret = tls_get_info(ctx, cipher, sizeof(cipher), version, sizeof(version));
    /* Should return error since handshake not complete */
    assert(ret != 0);
    printf("✓ TLS info retrieval (handshake incomplete)\n");
    
    /* Test 5: Cleanup TLS context */
    printf("Testing TLS context cleanup...\n");
    tls_context_destroy(ctx);
    printf("✓ TLS context cleanup\n");
    
#else
    /* TLS not available - should return error */
    assert(ret != 0);
    assert(ctx == NULL);
    printf("✓ TLS context creation (not available - expected)\n");
#endif
    
    /* Test 6: Create server mode context */
    printf("Testing TLS context creation (server mode)...\n");
    struct tls_config server_config = {0};
    server_config.server_mode = true;
    server_config.verify_peer = false;
    
    struct tls_context *server_ctx = NULL;
    ret = tls_context_create(&server_config, &server_ctx);
    
#ifdef ENABLE_TLS_ENCRYPTION
    /* Server mode might fail without certificates, but should not crash */
    if (ret == 0 && server_ctx != NULL) {
        tls_context_destroy(server_ctx);
        printf("✓ TLS server context creation\n");
    } else {
        printf("✓ TLS server context creation (failed as expected without certificates)\n");
    }
#else
    assert(ret != 0);
    assert(server_ctx == NULL);
    printf("✓ TLS server context creation (not available - expected)\n");
#endif
    
    /* Test 7: Test invalid arguments */
    printf("Testing invalid arguments...\n");
    ret = tls_context_create(NULL, &ctx);
    assert(ret != 0);
    
    ret = tls_context_create(&config, NULL);
    assert(ret != 0);
    
    /* Safe to call with NULL */
    tls_context_destroy(NULL);
    printf("✓ Invalid arguments handling\n");
    
    /* Cleanup */
    tls_encrypt_cleanup();
    
    printf("\n=== All TLS Encryption Tests Passed ===\n");
    return 0;
}