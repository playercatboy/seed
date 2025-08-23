/**
 * @file test_framework.h
 * @brief Simple unit test framework for Seed
 * @author Seed Development Team
 * @date 2025
 */

#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** Test statistics */
struct test_stats {
    int total_tests;
    int passed_tests;
    int failed_tests;
};

/** Global test statistics */
extern struct test_stats g_test_stats;

/** Test assertion macros */
#define ASSERT_TRUE(condition, message) \
    do { \
        g_test_stats.total_tests++; \
        if (condition) { \
            printf("  ✓ %s\n", message); \
            g_test_stats.passed_tests++; \
        } else { \
            printf("  ✗ %s (line %d)\n", message, __LINE__); \
            g_test_stats.failed_tests++; \
        } \
    } while (0)

#define ASSERT_FALSE(condition, message) \
    ASSERT_TRUE(!(condition), message)

#define ASSERT_EQUAL(expected, actual, message) \
    ASSERT_TRUE((expected) == (actual), message)

#define ASSERT_NOT_EQUAL(expected, actual, message) \
    ASSERT_TRUE((expected) != (actual), message)

#define ASSERT_STR_EQUAL(expected, actual, message) \
    ASSERT_TRUE(strcmp(expected, actual) == 0, message)

#define ASSERT_STR_NOT_EQUAL(expected, actual, message) \
    ASSERT_TRUE(strcmp(expected, actual) != 0, message)

/** Test suite macros */
#define TEST_SUITE(name) \
    printf("\n=== Test Suite: %s ===\n", name)

#define TEST_CASE(name) \
    printf("\nRunning test: %s\n", name)

#define TEST_SUMMARY() \
    do { \
        printf("\n=== Test Summary ===\n"); \
        printf("Total tests: %d\n", g_test_stats.total_tests); \
        printf("Passed: %d\n", g_test_stats.passed_tests); \
        printf("Failed: %d\n", g_test_stats.failed_tests); \
        if (g_test_stats.failed_tests == 0) { \
            printf("All tests passed! ✓\n"); \
        } else { \
            printf("Some tests failed! ✗\n"); \
        } \
        printf("==================\n"); \
    } while (0)

/** Initialize test framework */
void test_init(void);

/** Get test exit code */
int test_exit_code(void);

#endif /* TEST_FRAMEWORK_H */