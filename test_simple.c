#include <stdio.h>
#include "include/log.h"
#include "include/config.h"

int main() {
    printf("Testing basic compilation...\n");
    
    log_init(LOG_INFO);
    log_info("Logging test successful");
    
    struct seed_config config;
    config_init(&config);
    printf("Config initialization successful\n");
    
    log_cleanup();
    
    printf("Basic tests passed!\n");
    return 0;
}