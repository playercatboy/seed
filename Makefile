# Seed Makefile for Linux/Unix systems

CC = gcc
CFLAGS = -Wall -Wextra -O2 -I./include -I./components/libuv/include -I./components/openssl/include
LDFLAGS = -L./components/libuv/lib -L./components/openssl/lib
LIBS = -luv -lssl -lcrypto -lpthread -ldl

# Debug flags
DEBUG_CFLAGS = -g -DDEBUG -O0
RELEASE_CFLAGS = -O3 -DNDEBUG

# Source files
SRCS = src/main.c \
       src/log.c \
       src/config.c \
       src/cmdline.c \
       src/jwt.c \
       src/auth.c \
       src/network.c \
       src/protocol.c \
       src/server.c \
       src/client.c \
       src/tcp_proxy.c \
       src/udp_proxy.c \
       src/tls.c \
       src/ssh.c \
       src/table_crypt.c \
       src/inih/ini.c

# Object files
OBJS = $(SRCS:.c=.o)

# Test source files
TEST_SRCS = $(wildcard tests/*.c)
TEST_OBJS = $(TEST_SRCS:.c=.o)

# Target executable
TARGET = seed

# Default target
all: $(TARGET)

# Debug build
debug: CFLAGS += $(DEBUG_CFLAGS)
debug: $(TARGET)

# Release build
release: CFLAGS += $(RELEASE_CFLAGS)
release: $(TARGET)

# Link the executable
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS) $(LIBS)

# Compile source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Build tests
test: $(TARGET) $(TEST_OBJS)
	@for test in $(TEST_OBJS); do \
		echo "Running $$test..."; \
		$(CC) $$test $(filter-out src/main.o, $(OBJS)) -o $${test%.o} $(LDFLAGS) $(LIBS); \
		./$${test%.o}; \
	done

# Clean build files
clean:
	rm -f $(OBJS) $(TEST_OBJS) $(TARGET) tests/*
	find . -name "*.o" -delete

# Install target
install: $(TARGET)
	install -D $(TARGET) /usr/local/bin/$(TARGET)
	install -D -m 644 doc/seed.conf.example /etc/seed/seed.conf.example

# Uninstall target
uninstall:
	rm -f /usr/local/bin/$(TARGET)
	rm -rf /etc/seed

# Format code using clang-format
format:
	find src include -name "*.c" -o -name "*.h" | xargs clang-format -i

# Static analysis
analyze:
	cppcheck --enable=all --suppress=missingIncludeSystem -I./include src/

# Help target
help:
	@echo "Available targets:"
	@echo "  all      - Build the seed executable (default)"
	@echo "  debug    - Build with debug symbols"
	@echo "  release  - Build with optimizations"
	@echo "  test     - Build and run tests"
	@echo "  clean    - Remove build files"
	@echo "  install  - Install seed to system"
	@echo "  uninstall- Remove seed from system"
	@echo "  format   - Format code using clang-format"
	@echo "  analyze  - Run static analysis"
	@echo "  help     - Show this help message"

.PHONY: all debug release test clean install uninstall format analyze help