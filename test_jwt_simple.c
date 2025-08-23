#include <stdio.h>
#include "include/jwt.h"
#include "include/log.h"

int main() {
    printf("Testing JWT functionality...\n");
    
    log_init(LOG_INFO);
    
    char token[512];
    int result = jwt_generate("testpassword", token, sizeof(token));
    
    if (result == 0) {
        printf("✓ JWT generation successful\n");
        printf("Token length: %d\n", (int)strlen(token));
        printf("Token preview: %.50s...\n", token);
        
        // Test verification
        result = jwt_verify("testpassword", token);
        if (result == 0) {
            printf("✓ JWT verification successful\n");
        } else {
            printf("✗ JWT verification failed\n");
        }
        
        // Test wrong password
        result = jwt_verify("wrongpassword", token);
        if (result != 0) {
            printf("✓ JWT correctly rejected wrong password\n");
        } else {
            printf("✗ JWT incorrectly accepted wrong password\n");
        }
    } else {
        printf("✗ JWT generation failed: %d\n", result);
    }
    
    log_cleanup();
    
    printf("JWT tests completed!\n");
    return 0;
}