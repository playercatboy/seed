/**
 * @file test_cmdline.c
 * @brief Unit tests for command line module
 * @author Seed Development Team
 * @date 2025
 */

#include "test_framework.h"
#include "../include/cmdline.h"
#include "../include/log.h"

/**
 * @brief Test help option
 */
static void test_help_option(void)
{
    TEST_CASE("help_option");
    
    struct cmdline_options options;
    int result;
    
    /* Test short help option */
    char *argv1[] = {"seed", "-h"};
    int argc1 = sizeof(argv1) / sizeof(argv1[0]);
    
    result = cmdline_parse(argc1, argv1, &options);
    ASSERT_EQUAL(SEED_OK, result, "Help option parsing should succeed");
    ASSERT_TRUE(options.show_help, "Help flag should be set");
    ASSERT_FALSE(options.show_version, "Version flag should not be set");
    ASSERT_FALSE(options.hash_password, "Hash flag should not be set");
    
    cmdline_free(&options);
    
    /* Test long help option */
    char *argv2[] = {"seed", "--help"};
    int argc2 = sizeof(argv2) / sizeof(argv2[0]);
    
    result = cmdline_parse(argc2, argv2, &options);
    ASSERT_EQUAL(SEED_OK, result, "Long help option parsing should succeed");
    ASSERT_TRUE(options.show_help, "Help flag should be set");
    
    cmdline_free(&options);
}

/**
 * @brief Test version option
 */
static void test_version_option(void)
{
    TEST_CASE("version_option");
    
    struct cmdline_options options;
    int result;
    
    /* Test short version option */
    char *argv1[] = {"seed", "-v"};
    int argc1 = sizeof(argv1) / sizeof(argv1[0]);
    
    result = cmdline_parse(argc1, argv1, &options);
    ASSERT_EQUAL(SEED_OK, result, "Version option parsing should succeed");
    ASSERT_TRUE(options.show_version, "Version flag should be set");
    ASSERT_FALSE(options.show_help, "Help flag should not be set");
    ASSERT_FALSE(options.hash_password, "Hash flag should not be set");
    
    cmdline_free(&options);
    
    /* Test long version option */
    char *argv2[] = {"seed", "--version"};
    int argc2 = sizeof(argv2) / sizeof(argv2[0]);
    
    result = cmdline_parse(argc2, argv2, &options);
    ASSERT_EQUAL(SEED_OK, result, "Long version option parsing should succeed");
    ASSERT_TRUE(options.show_version, "Version flag should be set");
    
    cmdline_free(&options);
}

/**
 * @brief Test config file option
 */
static void test_config_file_option(void)
{
    TEST_CASE("config_file_option");
    
    struct cmdline_options options;
    int result;
    
    /* Test short config file option */
    char *argv1[] = {"seed", "-f", "custom.conf"};
    int argc1 = sizeof(argv1) / sizeof(argv1[0]);
    
    result = cmdline_parse(argc1, argv1, &options);
    ASSERT_EQUAL(SEED_OK, result, "Config file option parsing should succeed");
    ASSERT_FALSE(options.show_help, "Help flag should not be set");
    ASSERT_FALSE(options.show_version, "Version flag should not be set");
    ASSERT_FALSE(options.hash_password, "Hash flag should not be set");
    ASSERT_STR_EQUAL("custom.conf", options.config_file, "Config file should match");
    
    cmdline_free(&options);
    
    /* Test long config file option */
    char *argv2[] = {"seed", "--file", "another.conf"};
    int argc2 = sizeof(argv2) / sizeof(argv2[0]);
    
    result = cmdline_parse(argc2, argv2, &options);
    ASSERT_EQUAL(SEED_OK, result, "Long config file option parsing should succeed");
    ASSERT_STR_EQUAL("another.conf", options.config_file, "Config file should match");
    
    cmdline_free(&options);
}

/**
 * @brief Test hash password option
 */
static void test_hash_password_option(void)
{
    TEST_CASE("hash_password_option");
    
    struct cmdline_options options;
    int result;
    
    /* Test short hash option */
    char *argv1[] = {"seed", "-s", "mypassword"};
    int argc1 = sizeof(argv1) / sizeof(argv1[0]);
    
    result = cmdline_parse(argc1, argv1, &options);
    ASSERT_EQUAL(SEED_OK, result, "Hash password option parsing should succeed");
    ASSERT_TRUE(options.hash_password, "Hash flag should be set");
    ASSERT_FALSE(options.show_help, "Help flag should not be set");
    ASSERT_FALSE(options.show_version, "Version flag should not be set");
    ASSERT_STR_EQUAL("mypassword", options.password, "Password should match");
    
    cmdline_free(&options);
    
    /* Test long hash option */
    char *argv2[] = {"seed", "--hash", "anotherpassword"};
    int argc2 = sizeof(argv2) / sizeof(argv2[0]);
    
    result = cmdline_parse(argc2, argv2, &options);
    ASSERT_EQUAL(SEED_OK, result, "Long hash password option parsing should succeed");
    ASSERT_TRUE(options.hash_password, "Hash flag should be set");
    ASSERT_STR_EQUAL("anotherpassword", options.password, "Password should match");
    
    cmdline_free(&options);
}

/**
 * @brief Test default config file
 */
static void test_default_config_file(void)
{
    TEST_CASE("default_config_file");
    
    struct cmdline_options options;
    int result;
    
    /* Test no arguments */
    char *argv[] = {"seed"};
    int argc = sizeof(argv) / sizeof(argv[0]);
    
    result = cmdline_parse(argc, argv, &options);
    ASSERT_EQUAL(SEED_OK, result, "No arguments parsing should succeed");
    ASSERT_FALSE(options.show_help, "Help flag should not be set");
    ASSERT_FALSE(options.show_version, "Version flag should not be set");
    ASSERT_FALSE(options.hash_password, "Hash flag should not be set");
    ASSERT_STR_EQUAL(DEFAULT_CONFIG_FILE, options.config_file, "Should use default config file");
    
    cmdline_free(&options);
}

/**
 * @brief Test combined options
 */
static void test_combined_options(void)
{
    TEST_CASE("combined_options");
    
    struct cmdline_options options;
    int result;
    
    /* Test config file with different order */
    char *argv[] = {"seed", "--file", "test.conf"};
    int argc = sizeof(argv) / sizeof(argv[0]);
    
    result = cmdline_parse(argc, argv, &options);
    ASSERT_EQUAL(SEED_OK, result, "Combined options parsing should succeed");
    ASSERT_STR_EQUAL("test.conf", options.config_file, "Config file should be set");
    
    cmdline_free(&options);
}

/**
 * @brief Test invalid arguments
 */
static void test_invalid_arguments(void)
{
    TEST_CASE("invalid_arguments");
    
    struct cmdline_options options;
    int result;
    
    /* Test invalid option */
    char *argv1[] = {"seed", "-x"};
    int argc1 = sizeof(argv1) / sizeof(argv1[0]);
    
    result = cmdline_parse(argc1, argv1, &options);
    ASSERT_NOT_EQUAL(SEED_OK, result, "Invalid option should fail");
    
    /* Test missing argument for -f */
    char *argv2[] = {"seed", "-f"};
    int argc2 = sizeof(argv2) / sizeof(argv2[0]);
    
    result = cmdline_parse(argc2, argv2, &options);
    ASSERT_NOT_EQUAL(SEED_OK, result, "Missing file argument should fail");
    
    /* Test missing argument for -s */
    char *argv3[] = {"seed", "-s"};
    int argc3 = sizeof(argv3) / sizeof(argv3[0]);
    
    result = cmdline_parse(argc3, argv3, &options);
    ASSERT_NOT_EQUAL(SEED_OK, result, "Missing password argument should fail");
}

/**
 * @brief Test NULL arguments
 */
static void test_null_arguments(void)
{
    TEST_CASE("null_arguments");
    
    struct cmdline_options options;
    int result;
    char *argv[] = {"seed"};
    
    /* Test NULL options */
    result = cmdline_parse(1, argv, NULL);
    ASSERT_NOT_EQUAL(SEED_OK, result, "NULL options should fail");
    
    /* Test NULL argv */
    result = cmdline_parse(1, NULL, &options);
    ASSERT_NOT_EQUAL(SEED_OK, result, "NULL argv should fail");
}

/**
 * @brief Main test function
 */
int test_cmdline_main(void)
{
    test_init();
    
    /* Suppress logging during tests */
    log_init(LOG_ERROR);
    
    TEST_SUITE("Command Line Module Tests");
    
    test_help_option();
    test_version_option();
    test_config_file_option();
    test_hash_password_option();
    test_default_config_file();
    test_combined_options();
    test_invalid_arguments();
    test_null_arguments();
    
    TEST_SUMMARY();
    
    return test_exit_code();
}