/**
 * @file run_tests.c
 * @brief Test runner for all unit tests
 * @author Seed Development Team
 * @date 2025
 */

#include "test_framework.h"
#include "../include/log.h"
#include <time.h>

/* External test functions */
extern int test_config_main(void);
extern int test_cmdline_main(void);
extern int test_jwt_main(void);
extern int test_protocol_main(void);
extern int test_ssh_encrypt_main(void);

/**
 * @brief Run individual test and report results
 */
static int run_test(const char *test_name, int (*test_func)(void))
{
    int result;
    clock_t start_time, end_time;
    double elapsed;
    
    printf("\n" "=" "Running %s" "=", test_name);
    for (int i = strlen(test_name) + 9; i < 50; i++) printf("=");
    printf("\n");
    
    start_time = clock();
    result = test_func();
    end_time = clock();
    
    elapsed = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
    
    printf("\n%s completed in %.3f seconds (exit code: %d)\n", 
           test_name, elapsed, result);
    
    return result;
}

/**
 * @brief Main test runner
 */
int main(void)
{
    int total_failures = 0;
    int test_count = 0;
    clock_t total_start, total_end;
    double total_elapsed;
    
    /* Suppress all logging during tests */
    log_init(LOG_ERROR + 1); /* Higher than max level to disable all logs */
    
    printf("Seed Unit Test Runner\n");
    printf("====================\n");
    
    total_start = clock();
    
    /* Run all tests */
    total_failures += run_test("Configuration Tests", test_config_main);
    test_count++;
    
    total_failures += run_test("Command Line Tests", test_cmdline_main);
    test_count++;
    
    total_failures += run_test("JWT Tests", test_jwt_main);
    test_count++;
    
    total_failures += run_test("Protocol Tests", test_protocol_main);
    test_count++;
    
    total_failures += run_test("SSH Encryption Tests", test_ssh_encrypt_main);
    test_count++;
    
    total_end = clock();
    total_elapsed = ((double)(total_end - total_start)) / CLOCKS_PER_SEC;
    
    /* Print summary */
    printf("\n");
    printf("=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "\n");
    printf("Test Runner Summary\n");
    printf("=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "\n");
    printf("Test Suites: %d\n", test_count);
    printf("Failed Suites: %d\n", total_failures);
    printf("Total Time: %.3f seconds\n", total_elapsed);
    
    if (total_failures == 0) {
        printf("Result: ALL TESTS PASSED! ✓\n");
    } else {
        printf("Result: %d TEST SUITE(S) FAILED! ✗\n", total_failures);
    }
    printf("=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "\n");
    
    return (total_failures == 0) ? 0 : 1;
}