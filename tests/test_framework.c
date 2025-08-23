/**
 * @file test_framework.c
 * @brief Simple unit test framework implementation
 * @author Seed Development Team
 * @date 2025
 */

#include "test_framework.h"

/** Global test statistics */
struct test_stats g_test_stats = {0, 0, 0};

/**
 * @brief Initialize test framework
 */
void test_init(void)
{
    g_test_stats.total_tests = 0;
    g_test_stats.passed_tests = 0;
    g_test_stats.failed_tests = 0;
}

/**
 * @brief Get test exit code
 *
 * @return 0 if all tests passed, 1 if any failed
 */
int test_exit_code(void)
{
    return (g_test_stats.failed_tests == 0) ? 0 : 1;
}