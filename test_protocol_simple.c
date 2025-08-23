#include <stdio.h>
#include "include/protocol.h"
#include "include/log.h"

int main() {
    printf("Testing Protocol functionality...\n");
    
    log_init(LOG_INFO);
    
    struct protocol_message msg, decoded_msg;
    uint8_t buffer[1024];
    int result;
    
    // Test hello message
    protocol_init_message(&msg, MSG_TYPE_HELLO);
    strcpy(msg.payload.hello.client_id, "test_client");
    msg.payload.hello.protocol_version = PROTOCOL_VERSION;
    msg.payload.hello.capabilities = 0x12345678;
    
    printf("✓ Message initialized: %s\n", protocol_type_name(MSG_TYPE_HELLO));
    
    // Test serialization
    result = protocol_serialize(&msg, buffer, sizeof(buffer));
    if (result > 0) {
        printf("✓ Serialization successful: %d bytes\n", result);
        
        // Test deserialization
        int consumed = protocol_deserialize(&decoded_msg, buffer, result);
        if (consumed == result) {
            printf("✓ Deserialization successful: %d bytes consumed\n", consumed);
            
            // Verify data
            if (decoded_msg.header.type == MSG_TYPE_HELLO &&
                strcmp(decoded_msg.payload.hello.client_id, "test_client") == 0 &&
                decoded_msg.payload.hello.capabilities == 0x12345678) {
                printf("✓ Data integrity verified\n");
            } else {
                printf("✗ Data integrity failed\n");
            }
        } else {
            printf("✗ Deserialization failed: %d\n", consumed);
        }
    } else {
        printf("✗ Serialization failed: %d\n", result);
    }
    
    // Test validation
    result = protocol_validate_message(&decoded_msg);
    if (result == 0) {
        printf("✓ Message validation successful\n");
    } else {
        printf("✗ Message validation failed: %d\n", result);
    }
    
    log_cleanup();
    
    printf("Protocol tests completed!\n");
    return 0;
}