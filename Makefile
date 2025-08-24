# Seed Makefile for Linux/Unix systems

CC = gcc
CFLAGS = -Wall -Wextra -O2 -I./include -I./components/libuv/include -I./components/openssl/include -I./components/libssh/include
LDFLAGS = -L./components/libuv/lib -L./components/openssl/lib -L./components/libssh/lib
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
       src/ssh_encrypt.c \
       src/table_encrypt.c \
       src/tls_encrypt.c \
       src/encrypt.c \
       src/inih/ini.c

# Object files
OBJS = $(SRCS:.c=.o)

# Test source files
TEST_SRCS = tests/test_framework.c \
            tests/test_config.c \
            tests/test_cmdline.c \
            tests/test_jwt.c \
            tests/test_protocol.c \
            tests/test_ssh_encrypt.c
TEST_OBJS = $(TEST_SRCS:.c=.o)

# Test runner
TEST_RUNNER_SRC = tests/run_tests.c
TEST_RUNNER_OBJ = $(TEST_RUNNER_SRC:.c=.o)
TEST_RUNNER = test_runner

# Standalone test files
STANDALONE_TESTS = tests/test_integration_simple.c \
                  tests/test_jwt_standalone.c \
                  tests/test_cmdline_standalone.c

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

# Build and run individual tests
test-individual: $(TARGET)
	@echo "Building individual tests..."
	@for test_src in $(TEST_SRCS); do \
		test_name=$${test_src%.c}; \
		echo "Building $$test_name..."; \
		$(CC) $(CFLAGS) $$test_src tests/test_framework.c $(filter-out src/main.o, $(OBJS)) -o $$test_name $(LDFLAGS) $(LIBS); \
		echo "Running $$test_name..."; \
		./$$test_name; \
	done

# Build and run comprehensive test suite
test: $(TARGET) $(TEST_OBJS) $(TEST_RUNNER_OBJ)
	@echo "Building test runner..."
	$(CC) $(TEST_RUNNER_OBJ) $(TEST_OBJS) $(filter-out src/main.o, $(OBJS)) -o $(TEST_RUNNER) $(LDFLAGS) $(LIBS)
	@echo "Running comprehensive test suite..."
	./$(TEST_RUNNER)

# Build standalone tests
test-standalone: $(TARGET)
	@echo "Building and running standalone tests..."
	@for test_src in $(STANDALONE_TESTS); do \
		test_name=$${test_src%.c}; \
		test_exe=$${test_name##*/}; \
		echo "Building $$test_exe..."; \
		$(CC) $(CFLAGS) $$test_src $(filter-out src/main.o, $(OBJS)) -o tests/$$test_exe $(LDFLAGS) $(LIBS); \
		echo "Running $$test_exe..."; \
		./tests/$$test_exe; \
		echo ""; \
	done

# Clean build files
clean:
	rm -f $(OBJS) $(TEST_OBJS) $(TEST_RUNNER_OBJ) $(TARGET) $(TEST_RUNNER)
	rm -f tests/test_config tests/test_cmdline tests/test_jwt tests/test_protocol tests/test_ssh_encrypt
	rm -f tests/test_integration_simple tests/test_jwt_standalone tests/test_cmdline_standalone
	rm -f *.exe tests/*.exe
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
	@echo "  all           - Build the seed executable (default)"
	@echo "  debug         - Build with debug symbols"
	@echo "  release       - Build with optimizations"
	@echo "  test          - Build and run comprehensive test suite"
	@echo "  test-individual - Build and run individual unit tests"
	@echo "  test-standalone - Build and run standalone integration tests"
	@echo "  clean         - Remove all build files and executables"
	@echo "  install       - Install seed to system"
	@echo "  uninstall     - Remove seed from system"
	@echo "  format        - Format code using clang-format"
	@echo "  analyze       - Run static analysis"
	@echo "  help          - Show this help message"

.PHONY: all debug release test test-individual test-standalone clean install uninstall format analyze help