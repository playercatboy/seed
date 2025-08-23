/**
 * @file log.h
 * @brief Logging module for Seed reverse proxy
 * @author Seed Development Team
 * @date 2025
 */

#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdarg.h>

/** Log level enumeration */
enum log_level {
    LOG_ERROR = 0, /** Error level */
    LOG_WARNING,   /** Warning level */
    LOG_INFO,      /** Information level */
    LOG_DEBUG      /** Debug level */
};

/**
 * @brief Initialize the logging system
 *
 * @param[in] level The minimum log level to display
 *
 * @return 0 on success, negative error code on failure
 */
int log_init(enum log_level level);

/**
 * @brief Set the current log level
 *
 * @param[in] level The new log level
 */
void log_set_level(enum log_level level);

/**
 * @brief Get the current log level
 *
 * @return The current log level
 */
enum log_level log_get_level(void);

/**
 * @brief Log a message with specified level
 *
 * @param[in] level    The log level
 * @param[in] file     Source file name
 * @param[in] line     Source line number
 * @param[in] format   Printf-style format string
 * @param[in] ...      Variable arguments
 */
void log_write(enum log_level level, const char *file, int line, const char *format, ...);

/**
 * @brief Cleanup logging resources
 */
void log_cleanup(void);

/** Convenience macros for logging */
#define log_error(...)   log_write(LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define log_warning(...) log_write(LOG_WARNING, __FILE__, __LINE__, __VA_ARGS__)
#define log_info(...)    log_write(LOG_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define log_debug(...)   log_write(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)

#endif /* LOG_H */