#include <stdio.h>
#include "include/cmdline.h"
#include "include/log.h"

int main() {
    printf("Testing Command Line functionality...\n");
    
    log_init(LOG_INFO);
    
    struct cmdline_options options;
    int result;
    
    // Test help option
    char *argv1[] = {"seed", "-h"};
    result = cmdline_parse(2, argv1, &options);
    if (result == 0 && options.show_help) {
        printf("✓ Help option parsing successful\n");
    } else {
        printf("✗ Help option parsing failed\n");
    }
    cmdline_free(&options);
    
    // Test version option
    char *argv2[] = {"seed", "--version"};
    result = cmdline_parse(2, argv2, &options);
    if (result == 0 && options.show_version) {
        printf("✓ Version option parsing successful\n");
    } else {
        printf("✗ Version option parsing failed\n");
    }
    cmdline_free(&options);
    
    // Test config file option
    char *argv3[] = {"seed", "-f", "test.conf"};
    result = cmdline_parse(3, argv3, &options);
    if (result == 0 && strcmp(options.config_file, "test.conf") == 0) {
        printf("✓ Config file option parsing successful\n");
    } else {
        printf("✗ Config file option parsing failed\n");
    }
    cmdline_free(&options);
    
    // Test hash option
    char *argv4[] = {"seed", "-s", "password123"};
    result = cmdline_parse(3, argv4, &options);
    if (result == 0 && options.hash_password && 
        strcmp(options.password, "password123") == 0) {
        printf("✓ Hash option parsing successful\n");
    } else {
        printf("✗ Hash option parsing failed\n");
    }
    cmdline_free(&options);
    
    log_cleanup();
    
    printf("Command line tests completed!\n");
    return 0;
}