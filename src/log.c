/**
 * @file log.c
 * @brief Logging module implementation for Seed reverse proxy
 * @author Seed Development Team
 * @date 2025
 */

#include "log.h"
#include <time.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#define isatty _isatty
#define fileno _fileno
#else
#include <unistd.h>
#endif

/** Current log level */
static enum log_level current_log_level = LOG_ERROR;

/** Log level names */
static const char *level_names[] = {
    "E", /* ERROR */
    "W", /* WARNING */
    "I", /* INFO */
    "D"  /* DEBUG */
};

/** ANSI color codes */
static const char *level_colors[] = {
    "\x1b[31m", /* Red for ERROR */
    "\x1b[33m", /* Yellow for WARNING */
    "",         /* Default for INFO */
    "\x1b[34m"  /* Blue for DEBUG */
};

/** ANSI reset code */
static const char *color_reset = "\x1b[0m";

/** Check if output supports colors */
static int supports_color = 0;

/**
 * @brief Initialize color support detection
 */
static void init_color_support(void)
{
#ifdef _WIN32
    /* Enable ANSI escape sequences on Windows 10+ */
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD dwMode = 0;
        if (GetConsoleMode(hOut, &dwMode)) {
            dwMode |= 0x0004; /* ENABLE_VIRTUAL_TERMINAL_PROCESSING */
            SetConsoleMode(hOut, dwMode);
        }
    }
#endif
    supports_color = isatty(fileno(stdout));
}

/**
 * @brief Initialize the logging system
 *
 * @param[in] level The minimum log level to display
 *
 * @return 0 on success, negative error code on failure
 */
int log_init(enum log_level level)
{
    if (level < LOG_ERROR || level > LOG_DEBUG) {
        return -1;
    }
    
    current_log_level = level;
    init_color_support();
    
    return 0;
}

/**
 * @brief Set the current log level
 *
 * @param[in] level The new log level
 */
void log_set_level(enum log_level level)
{
    if (level >= LOG_ERROR && level <= LOG_DEBUG) {
        current_log_level = level;
    }
}

/**
 * @brief Get the current log level
 *
 * @return The current log level
 */
enum log_level log_get_level(void)
{
    return current_log_level;
}

/**
 * @brief Log a message with specified level
 *
 * @param[in] level    The log level
 * @param[in] file     Source file name
 * @param[in] line     Source line number
 * @param[in] format   Printf-style format string
 * @param[in] ...      Variable arguments
 */
void log_write(enum log_level level, const char *file, int line, const char *format, ...)
{
    va_list args;
    time_t raw_time;
    struct tm *time_info;
    char time_buffer[32];
    const char *filename;
    
    /* Check if this message should be logged */
    if (level > current_log_level) {
        return;
    }
    
    /* Get current time */
    time(&raw_time);
    time_info = localtime(&raw_time);
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", time_info);
    
    /* Extract just the filename from the full path */
    filename = strrchr(file, '/');
    if (!filename) {
        filename = strrchr(file, '\\');
    }
    if (filename) {
        filename++;
    } else {
        filename = file;
    }
    
    /* Print log header with color if supported */
    if (supports_color && level_colors[level][0] != '\0') {
        printf("%s[%s](%s)%s ", level_colors[level], time_buffer, level_names[level], color_reset);
    } else {
        printf("[%s](%s) ", time_buffer, level_names[level]);
    }
    
    /* Print the actual message */
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    
    /* Add source location for debug messages */
    if (level == LOG_DEBUG) {
        printf(" [%s:%d]", filename, line);
    }
    
    printf("\n");
    fflush(stdout);
}

/**
 * @brief Cleanup logging resources
 */
void log_cleanup(void)
{
    /* Currently no resources to cleanup */
}