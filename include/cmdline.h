/**
 * @file cmdline.h
 * @brief Command line argument parsing for Seed reverse proxy
 * @author Seed Development Team
 * @date 2025
 */

#ifndef CMDLINE_H
#define CMDLINE_H

#include "common.h"

/** Command line options structure */
struct cmdline_options {
    bool show_help;         /** Show help and exit */
    bool show_version;      /** Show version and exit */
    bool hash_password;     /** Hash password mode */
    char *config_file;      /** Configuration file path */
    char *password;         /** Password to hash */
};

/**
 * @brief Parse command line arguments
 *
 * @param[in]  argc     Number of arguments
 * @param[in]  argv     Argument array
 * @param[out] options  Parsed options structure
 *
 * @return 0 on success, negative error code on failure
 */
int cmdline_parse(int argc, char *argv[], struct cmdline_options *options);

/**
 * @brief Print help message
 *
 * @param[in] program_name  Name of the program
 */
void cmdline_print_help(const char *program_name);

/**
 * @brief Print version information
 */
void cmdline_print_version(void);

/**
 * @brief Free command line options resources
 *
 * @param[in,out] options  Options structure to free
 */
void cmdline_free(struct cmdline_options *options);

#endif /* CMDLINE_H */