/**
 * @file test_echo_simple.c
 * @brief Simple TCP/UDP echo test for Seed integration verification
 * @author Seed Development Team
 * @date 2025
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #pragma comment(lib, "ws2_32.lib")
    #define close closesocket
    #define sleep Sleep
    typedef HANDLE thread_handle_t;
    typedef DWORD WINAPI (*thread_func_t)(LPVOID);
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <signal.h>
    #include <pthread.h>
    typedef pthread_t thread_handle_t;
    typedef void* (*thread_func_t)(void*);
#endif

/* Test configuration */
#define TCP_ECHO_PORT 33000
#define UDP_ECHO_PORT 34000
#define TCP_PROXY_PORT 44000
#define UDP_PROXY_PORT 44000
#define TEST_PAYLOAD "Hello, Seed Proxy Test!"
#define TEST_PAYLOAD_SIZE (strlen(TEST_PAYLOAD) + 1)

/* Global state for thread synchronization */
static volatile int g_tcp_server_ready = 0;
static volatile int g_udp_server_ready = 0;
static volatile int g_test_running = 1;

/**
 * @brief Initialize network stack
 */
static int init_network(void)
{
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return -1;
    }
#endif
    return 0;
}

/**
 * @brief Cleanup network stack
 */
static void cleanup_network(void)
{
#ifdef _WIN32
    WSACleanup();
#endif
}

/**
 * @brief TCP echo server thread function
 */
#ifdef _WIN32
static DWORD WINAPI tcp_echo_server_thread(LPVOID arg)
#else
static void* tcp_echo_server_thread(void* arg)
#endif
{
    int port = *(int*)arg;
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[1024];
    int opt = 1;
    
    /* Create server socket */
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        printf("TCP Echo: Failed to create socket\n");
        g_tcp_server_ready = -1;
#ifdef _WIN32
        return 1;
#else
        return NULL;
#endif
    }
    
    /* Allow address reuse */
#ifdef _WIN32
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
#else
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif
    
    /* Bind and listen */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(port);
    
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        printf("TCP Echo: Failed to bind to port %d\n", port);
        close(server_fd);
        g_tcp_server_ready = -1;
#ifdef _WIN32
        return 1;
#else
        return NULL;
#endif
    }
    
    if (listen(server_fd, 1) < 0) {
        printf("TCP Echo: Failed to listen\n");
        close(server_fd);
        g_tcp_server_ready = -1;
#ifdef _WIN32
        return 1;
#else
        return NULL;
#endif
    }
    
    printf("TCP Echo: Server listening on port %d\n", port);
    g_tcp_server_ready = 1;
    
    /* Accept and echo */
    client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
    if (client_fd < 0) {
        printf("TCP Echo: Accept failed\n");
        close(server_fd);
#ifdef _WIN32
        return 1;
#else
        return NULL;
#endif
    }
    
    printf("TCP Echo: Client connected\n");
    
    /* Echo loop */
    while (g_test_running) {
        int bytes_received = recv(client_fd, buffer, sizeof(buffer), 0);
        if (bytes_received <= 0) {
            break;
        }
        
        printf("TCP Echo: Received %d bytes, echoing back\n", bytes_received);
        
        int bytes_sent = send(client_fd, buffer, bytes_received, 0);
        if (bytes_sent != bytes_received) {
            printf("TCP Echo: Send failed\n");
            break;
        }
    }
    
    close(client_fd);
    close(server_fd);
    printf("TCP Echo: Server stopped\n");
    
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/**
 * @brief UDP echo server thread function
 */
#ifdef _WIN32
static DWORD WINAPI udp_echo_server_thread(LPVOID arg)
#else
static void* udp_echo_server_thread(void* arg)
#endif
{
    int port = *(int*)arg;
    int server_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[1024];
    
    /* Create server socket */
    server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_fd < 0) {
        printf("UDP Echo: Failed to create socket\n");
        g_udp_server_ready = -1;
#ifdef _WIN32
        return 1;
#else
        return NULL;
#endif
    }
    
    /* Bind server */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(port);
    
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        printf("UDP Echo: Failed to bind to port %d\n", port);
        close(server_fd);
        g_udp_server_ready = -1;
#ifdef _WIN32
        return 1;
#else
        return NULL;
#endif
    }
    
    printf("UDP Echo: Server listening on port %d\n", port);
    g_udp_server_ready = 1;
    
    /* Echo loop */
    while (g_test_running) {
        int bytes_received = recvfrom(server_fd, buffer, sizeof(buffer), 0,
                                    (struct sockaddr*)&client_addr, &client_len);
        if (bytes_received <= 0) {
            continue;
        }
        
        printf("UDP Echo: Received %d bytes, echoing back\n", bytes_received);
        
        int bytes_sent = sendto(server_fd, buffer, bytes_received, 0,
                              (struct sockaddr*)&client_addr, client_len);
        if (bytes_sent != bytes_received) {
            printf("UDP Echo: Send failed\n");
        }
        
        /* For testing, handle one packet then break */
        break;
    }
    
    close(server_fd);
    printf("UDP Echo: Server stopped\n");
    
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/**
 * @brief Start a thread with platform-specific code
 */
static int start_thread(thread_handle_t* handle, thread_func_t func, void* arg)
{
#ifdef _WIN32
    *handle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)func, arg, 0, NULL);
    return (*handle != NULL) ? 0 : -1;
#else
    return pthread_create(handle, NULL, func, arg);
#endif
}

/**
 * @brief Wait for a thread to finish
 */
static int join_thread(thread_handle_t handle)
{
#ifdef _WIN32
    WaitForSingleObject(handle, INFINITE);
    CloseHandle(handle);
    return 0;
#else
    return pthread_join(handle, NULL);
#endif
}

/**
 * @brief Test TCP client functionality
 */
static int test_tcp_client(int port)
{
    int sock;
    struct sockaddr_in server_addr;
    char send_buffer[256];
    char recv_buffer[256];
    int retry_count = 0;
    
    /* Wait for server to be ready */
    while (g_tcp_server_ready == 0 && retry_count < 50) {
        sleep(100);
        retry_count++;
    }
    
    if (g_tcp_server_ready != 1) {
        printf("❌ TCP server not ready\n");
        return -1;
    }
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("❌ Failed to create TCP client socket\n");
        return -1;
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(port);
    
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        printf("❌ Failed to connect to TCP server on port %d\n", port);
        close(sock);
        return -1;
    }
    
    printf("✓ TCP Client connected to server\n");
    
    /* Send test payload */
    strncpy(send_buffer, TEST_PAYLOAD, sizeof(send_buffer) - 1);
    send_buffer[sizeof(send_buffer) - 1] = '\0';
    
    int bytes_sent = send(sock, send_buffer, TEST_PAYLOAD_SIZE, 0);
    if (bytes_sent != TEST_PAYLOAD_SIZE) {
        printf("❌ TCP Client failed to send data\n");
        close(sock);
        return -1;
    }
    
    printf("✓ TCP Client sent %d bytes: %s\n", bytes_sent, send_buffer);
    
    /* Receive echo */
    memset(recv_buffer, 0, sizeof(recv_buffer));
    int bytes_received = recv(sock, recv_buffer, sizeof(recv_buffer), 0);
    if (bytes_received != TEST_PAYLOAD_SIZE) {
        printf("❌ TCP Client failed to receive echo (got %d, expected %zu)\n", 
               bytes_received, TEST_PAYLOAD_SIZE);
        close(sock);
        return -1;
    }
    
    printf("✓ TCP Client received %d bytes: %s\n", bytes_received, recv_buffer);
    
    /* Verify payload with memcmp */
    if (memcmp(send_buffer, recv_buffer, TEST_PAYLOAD_SIZE) != 0) {
        printf("❌ TCP Payload verification FAILED!\n");
        printf("  Sent:     '%s'\n", send_buffer);
        printf("  Received: '%s'\n", recv_buffer);
        close(sock);
        return -1;
    }
    
    printf("✅ TCP memcmp() verification PASSED!\n");
    close(sock);
    return 0;
}

/**
 * @brief Test UDP client functionality
 */
static int test_udp_client(int port)
{
    int sock;
    struct sockaddr_in server_addr;
    char send_buffer[256];
    char recv_buffer[256];
    socklen_t addr_len = sizeof(server_addr);
    int retry_count = 0;
    
    /* Wait for server to be ready */
    while (g_udp_server_ready == 0 && retry_count < 50) {
        sleep(100);
        retry_count++;
    }
    
    if (g_udp_server_ready != 1) {
        printf("❌ UDP server not ready\n");
        return -1;
    }
    
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        printf("❌ Failed to create UDP client socket\n");
        return -1;
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(port);
    
    /* Send test payload */
    strncpy(send_buffer, TEST_PAYLOAD, sizeof(send_buffer) - 1);
    send_buffer[sizeof(send_buffer) - 1] = '\0';
    
    int bytes_sent = sendto(sock, send_buffer, TEST_PAYLOAD_SIZE, 0,
                           (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (bytes_sent != TEST_PAYLOAD_SIZE) {
        printf("❌ UDP Client failed to send data\n");
        close(sock);
        return -1;
    }
    
    printf("✓ UDP Client sent %d bytes: %s\n", bytes_sent, send_buffer);
    
    /* Receive echo */
    memset(recv_buffer, 0, sizeof(recv_buffer));
    int bytes_received = recvfrom(sock, recv_buffer, sizeof(recv_buffer), 0,
                                (struct sockaddr*)&server_addr, &addr_len);
    if (bytes_received != TEST_PAYLOAD_SIZE) {
        printf("❌ UDP Client failed to receive echo (got %d, expected %zu)\n", 
               bytes_received, TEST_PAYLOAD_SIZE);
        close(sock);
        return -1;
    }
    
    printf("✓ UDP Client received %d bytes: %s\n", bytes_received, recv_buffer);
    
    /* Verify payload with memcmp */
    if (memcmp(send_buffer, recv_buffer, TEST_PAYLOAD_SIZE) != 0) {
        printf("❌ UDP Payload verification FAILED!\n");
        printf("  Sent:     '%s'\n", send_buffer);
        printf("  Received: '%s'\n", recv_buffer);
        close(sock);
        return -1;
    }
    
    printf("✅ UDP memcmp() verification PASSED!\n");
    close(sock);
    return 0;
}

/**
 * @brief Main test function
 */
int main(void)
{
    printf("Seed Integration Test - Echo Server Verification\n");
    printf("================================================\n");
    printf("This test verifies TCP/UDP echo functionality for Seed proxy integration.\n");
    printf("Test payload: '%s' (size: %zu bytes)\n", TEST_PAYLOAD, TEST_PAYLOAD_SIZE);
    
    if (init_network() != 0) {
        printf("❌ Network initialization failed\n");
        return 1;
    }
    
    /* Thread handles and port variables */
    thread_handle_t tcp_thread, udp_thread;
    static int tcp_port = TCP_ECHO_PORT;
    static int udp_port = UDP_ECHO_PORT;
    int tcp_result = 0;
    int udp_result = 0;
    
    printf("\n=== Starting Echo Servers ===\n");
    
    /* Start TCP echo server thread */
    if (start_thread(&tcp_thread, (thread_func_t)tcp_echo_server_thread, &tcp_port) != 0) {
        printf("❌ Failed to start TCP server thread\n");
        cleanup_network();
        return 1;
    }
    
    /* Start UDP echo server thread */
    if (start_thread(&udp_thread, (thread_func_t)udp_echo_server_thread, &udp_port) != 0) {
        printf("❌ Failed to start UDP server thread\n");
        g_test_running = 0;
        join_thread(tcp_thread);
        cleanup_network();
        return 1;
    }
    
    /* Wait a bit for servers to start */
    sleep(1000);
    
    printf("\n=== Testing TCP Echo ===\n");
    tcp_result = test_tcp_client(TCP_ECHO_PORT);
    
    printf("\n=== Testing UDP Echo ===\n");
    udp_result = test_udp_client(UDP_ECHO_PORT);
    
    /* Stop servers */
    printf("\n=== Stopping Servers ===\n");
    g_test_running = 0;
    
    /* Give threads time to finish */
    sleep(500);
    
    /* Wait for threads to complete */
    join_thread(tcp_thread);
    join_thread(udp_thread);
    
    /* Summary */
    printf("\n" "=" "=" "=" " TEST SUMMARY " "=" "=" "=\n");
    printf("TCP Echo Test: %s\n", tcp_result == 0 ? "✅ PASSED" : "❌ FAILED");
    printf("UDP Echo Test: %s\n", udp_result == 0 ? "✅ PASSED" : "❌ FAILED");
    printf("memcmp() Verification: %s\n", 
           (tcp_result == 0 && udp_result == 0) ? "✅ PASSED" : "❌ FAILED");
    
    if (tcp_result == 0 && udp_result == 0) {
        printf("\n✅ ALL TESTS PASSED!\n");
        printf("Echo servers are working correctly.\n");
        printf("Next step: Test with actual Seed proxy on ports %d (TCP) and %d (UDP)\n", 
               TCP_PROXY_PORT, UDP_PROXY_PORT);
    } else {
        printf("\n❌ SOME TESTS FAILED!\n");
        printf("Check network configuration and firewall settings.\n");
    }
    
    cleanup_network();
    return (tcp_result == 0 && udp_result == 0) ? 0 : 1;
}