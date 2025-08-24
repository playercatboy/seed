/**
 * @file udp_echo_server.c
 * @brief Standalone UDP echo server for testing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    #define close closesocket
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif

#define BUFFER_SIZE 4096

static int init_network(void)
{
#ifdef _WIN32
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", result);
        return -1;
    }
#endif
    return 0;
}

static void cleanup_network(void)
{
#ifdef _WIN32
    WSACleanup();
#endif
}

int main(int argc, char *argv[])
{
    int port = 34000;
    int server_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    int bytes_received, bytes_sent;
    
    if (argc > 1) {
        port = atoi(argv[1]);
    }
    
    printf("UDP Echo Server starting on port %d...\n", port);
    
    if (init_network() != 0) {
        return 1;
    }
    
    /* Create socket */
    server_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_sock < 0) {
        perror("socket");
        cleanup_network();
        return 1;
    }
    
    /* Bind socket */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    
    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_sock);
        cleanup_network();
        return 1;
    }
    
    printf("UDP Echo Server listening on port %d\n", port);
    
    while (1) {
        /* Receive data */
        bytes_received = recvfrom(server_sock, buffer, sizeof(buffer) - 1, 0,
                                 (struct sockaddr*)&client_addr, &client_len);
        if (bytes_received < 0) {
            perror("recvfrom");
            continue;
        }
        
        buffer[bytes_received] = '\0';
        printf("Received %d bytes from %s:%d: %s\n", 
               bytes_received, inet_ntoa(client_addr.sin_addr), 
               ntohs(client_addr.sin_port), buffer);
        
        /* Echo back */
        bytes_sent = sendto(server_sock, buffer, bytes_received, 0,
                           (struct sockaddr*)&client_addr, client_len);
        if (bytes_sent < 0) {
            perror("sendto");
            continue;
        }
        
        printf("Echoed back %d bytes\n", bytes_sent);
    }
    
    close(server_sock);
    cleanup_network();
    return 0;
}