#include <stdio.h>
#include "include/cmdline.h"
#include "include/jwt.h"
#include "include/log.h"

int main(int argc, char *argv[])
{
    struct cmdline_options options;
    int result;
    
    printf("Testing Main Program Components...\n");
    log_init(LOG_INFO);
    
    /* Parse command line arguments */
    result = cmdline_parse(argc, argv, &options);
    if (result != 0) {
        printf("Error: Invalid command line arguments\n");
        return 1;
    }
    
    /* Handle help */
    if (options.show_help) {
        cmdline_print_help(argv[0]);
        cmdline_free(&options);
        return 0;
    }
    
    /* Handle version */
    if (options.show_version) {
        cmdline_print_version();
        cmdline_free(&options);
        return 0;
    }
    
    /* Handle password hashing */
    if (options.hash_password) {
        char token[512];
        
        if (jwt_generate(options.password, token, sizeof(token)) == 0) {
            printf("JWT Token:\n%s\n", token);
            printf("\nAdd this to your seed.auth file as:\n");
            printf("username: %s\n", token);
            cmdline_free(&options);
            return 0;
        } else {
            printf("Failed to generate JWT token\n");
            cmdline_free(&options);
            return 1;
        }
    }
    
    /* Normal operation */
    printf("Config file: %s\n", options.config_file);
    printf("Normal operation would continue here...\n");
    
    cmdline_free(&options);
    log_cleanup();
    return 0;
}