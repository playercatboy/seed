/**
 * @file cmdline.c
 * @brief Command line argument parsing implementation
 * @author Seed Development Team
 * @date 2025
 */

#include "cmdline.h"
#include <getopt.h>

/** Long options for getopt */
static struct option long_options[] = {
    {"help",    no_argument,       0, 'h'},
    {"version", no_argument,       0, 'v'},
    {"file",    required_argument, 0, 'f'},
    {"hash",    required_argument, 0, 's'},
    {0, 0, 0, 0}
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
int cmdline_parse(int argc, char *argv[], struct cmdline_options *options)
{
    int opt;
    int option_index = 0;
    
    if (!options || !argv) {
        return SEED_ERROR_INVALID_ARGS;
    }
    
    /* Initialize options */
    memset(options, 0, sizeof(struct cmdline_options));
    
    /* Parse arguments */
    while ((opt = getopt_long(argc, argv, "hvf:s:", long_options, &option_index)) != -1) {
        switch (opt) {
        case 'h':
            options->show_help = true;
            return SEED_OK;
            
        case 'v':
            options->show_version = true;
            return SEED_OK;
            
        case 'f':
            options->config_file = strdup(optarg);
            if (!options->config_file) {
                return SEED_ERROR_OUT_OF_MEMORY;
            }
            break;
            
        case 's':
            options->hash_password = true;
            options->password = strdup(optarg);
            if (!options->password) {
                cmdline_free(options);
                return SEED_ERROR_OUT_OF_MEMORY;
            }
            return SEED_OK;
            
        case '?':
            /* Invalid option */
            return SEED_ERROR_INVALID_ARGS;
            
        default:
            break;
        }
    }
    
    /* Set default config file if not specified */
    if (!options->config_file) {
        options->config_file = strdup(DEFAULT_CONFIG_FILE);
        if (!options->config_file) {
            return SEED_ERROR_OUT_OF_MEMORY;
        }
    }
    
    return SEED_OK;
}

/**
 * @brief Print help message
 *
 * @param[in] program_name  Name of the program
 */
void cmdline_print_help(const char *program_name)
{
    printf("Usage: %s [options]\n", program_name);
    printf("\nSeed - A reverse proxy software for accessing services behind NAT/firewall\n");
    printf("\nOptions:\n");
    printf("  -h, --help              Print this help message and exit\n");
    printf("  -v, --version           Print version information and exit\n");
    printf("  -f, --file <path>       Specify configuration file (default: %s)\n", DEFAULT_CONFIG_FILE);
    printf("  -s, --hash <password>   Hash a password to JWT token and exit\n");
    printf("\nExamples:\n");
    printf("  %s                      Start with default configuration\n", program_name);
    printf("  %s -f /etc/seed.conf    Start with custom configuration file\n", program_name);
    printf("  %s -s mypassword        Generate JWT token for password\n", program_name);
    printf("\nFor more information, see the documentation at:\n");
    printf("  https://github.com/yourusername/seed\n");
}

/**
 * @brief Print version information
 */
void cmdline_print_version(void)
{
    printf("Seed version %s\n", SEED_VERSION_STRING);
    printf("Copyright (C) 2025 Seed Development Team\n");
    printf("This is free software; see the source for copying conditions.\n");
    printf("There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A\n");
    printf("PARTICULAR PURPOSE.\n");
}

/**
 * @brief Free command line options resources
 *
 * @param[in,out] options  Options structure to free
 */
void cmdline_free(struct cmdline_options *options)
{
    if (options) {
        SAFE_FREE(options->config_file);
        SAFE_FREE(options->password);
        memset(options, 0, sizeof(struct cmdline_options));
    }
}