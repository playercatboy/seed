/**
 * @file test_cmdline_encrypted_simple.c
 * @brief Simple tests for encrypted auth command-line options
 * @author Seed Development Team
 * @date 2025
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* Include our command line header */
#include "../include/cmdline.h"

/* Simple logging for tests */
void log_info(const char *fmt, ...) { /* stub */ }
void log_error(const char *fmt, ...) { /* stub */ }
void log_debug(const char *fmt, ...) { /* stub */ }
void log_warning(const char *fmt, ...) { /* stub */ }

int main(void)
{
    printf("=== Simple Command Line Encrypted Auth Tests ===\n");
    
    /* Test 1: Basic encrypted auth flag */
    printf("Testing basic encrypted auth flag...\n");
    char *argv1[] = {"seed", "--encrypted-auth"};
    int argc1 = sizeof(argv1) / sizeof(argv1[0]);
    
    struct cmdline_options options1;
    int ret = cmdline_parse(argc1, argv1, &options1);
    assert(ret == 0);
    assert(options1.use_encrypted_auth == true);
    assert(options1.auth_password == NULL);
    cmdline_free(&options1);
    printf("✓ Basic encrypted auth flag\n");
    
    /* Test 2: Short form encrypted auth flag */
    printf("Testing short form encrypted auth flag...\n");
    char *argv2[] = {"seed", "-e"};
    int argc2 = sizeof(argv2) / sizeof(argv2[0]);
    
    /* Reset getopt state */
    extern int optind;
    optind = 1;
    
    struct cmdline_options options2;
    ret = cmdline_parse(argc2, argv2, &options2);
    assert(ret == 0);
    assert(options2.use_encrypted_auth == true);
    cmdline_free(&options2);
    printf("✓ Short form encrypted auth flag\n");
    
    /* Test 3: Auth password with long option */
    printf("Testing auth password with long option...\n");
    char *argv3[] = {"seed", "--auth-password", "test_password_123"};
    int argc3 = sizeof(argv3) / sizeof(argv3[0]);
    
    optind = 1;
    struct cmdline_options options3;
    ret = cmdline_parse(argc3, argv3, &options3);
    assert(ret == 0);
    assert(options3.auth_password != NULL);
    assert(strcmp(options3.auth_password, "test_password_123") == 0);
    cmdline_free(&options3);
    printf("✓ Auth password with long option\n");
    
    /* Test 4: Auth password with short option */
    printf("Testing auth password with short option...\n");
    char *argv4[] = {"seed", "-p", "short_password"};
    int argc4 = sizeof(argv4) / sizeof(argv4[0]);
    
    optind = 1;
    struct cmdline_options options4;
    ret = cmdline_parse(argc4, argv4, &options4);
    assert(ret == 0);
    assert(options4.auth_password != NULL);
    assert(strcmp(options4.auth_password, "short_password") == 0);
    cmdline_free(&options4);
    printf("✓ Auth password with short option\n");
    
    /* Test 5: Combined encrypted auth and password */
    printf("Testing combined encrypted auth and password...\n");
    char *argv5[] = {"seed", "-e", "-p", "combined_password"};
    int argc5 = sizeof(argv5) / sizeof(argv5[0]);
    
    optind = 1;
    struct cmdline_options options5;
    ret = cmdline_parse(argc5, argv5, &options5);
    assert(ret == 0);
    assert(options5.use_encrypted_auth == true);
    assert(options5.auth_password != NULL);
    assert(strcmp(options5.auth_password, "combined_password") == 0);
    cmdline_free(&options5);
    printf("✓ Combined encrypted auth and password\n");
    
    /* Test 6: Combined with config file */
    printf("Testing combined with config file...\n");
    char *argv6[] = {"seed", "-f", "custom.conf", "--encrypted-auth", "--auth-password", "file_password"};
    int argc6 = sizeof(argv6) / sizeof(argv6[0]);
    
    optind = 1;
    struct cmdline_options options6;
    ret = cmdline_parse(argc6, argv6, &options6);
    assert(ret == 0);
    assert(options6.config_file != NULL);
    assert(strcmp(options6.config_file, "custom.conf") == 0);
    assert(options6.use_encrypted_auth == true);
    assert(options6.auth_password != NULL);
    assert(strcmp(options6.auth_password, "file_password") == 0);
    cmdline_free(&options6);
    printf("✓ Combined with config file\n");
    
    /* Test 7: Default values when not specified */
    printf("Testing default values...\n");
    char *argv7[] = {"seed"};
    int argc7 = sizeof(argv7) / sizeof(argv7[0]);
    
    optind = 1;
    struct cmdline_options options7;
    ret = cmdline_parse(argc7, argv7, &options7);
    assert(ret == 0);
    assert(options7.use_encrypted_auth == false);
    assert(options7.auth_password == NULL);
    assert(options7.show_help == false);
    assert(options7.show_version == false);
    assert(options7.hash_password == false);
    cmdline_free(&options7);
    printf("✓ Default values\n");
    
    printf("\n=== All Command Line Encrypted Auth Tests Passed ===\n");
    return 0;
}