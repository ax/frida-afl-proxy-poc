#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int vuln(char *param){
    char local[64];
    local[0] = 'a';
    void (*crashme)() = 0x00;
    if(param[0] == 'b'){
        local[0]='x';
    }
    if(param[0] == 'f'){
        local[0]='a';
        if(param[1] == 'a'){
            local[0]='b';
            if(param[2] == 'f'){
                local[0]='c';
                if(param[3] == 'l'){
                    local[0]='d';
                    if(param[4] == 'a'){
                        local[0]='e';
                        if(param[5] == 'x'){
                            local[0]='f';
                            //strcpy(local,param);
                            crashme();
                        }
                    }
                }

            }
        }
    }
    if(param[1] == 'k'){
        local[0]='A';
    }
    return 1;
}

int main() {
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_received;

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_sock);
        exit(EXIT_FAILURE);
    }
    if (listen(server_sock, 5) < 0) {
        perror("Listen failed");
        close(server_sock);
        exit(EXIT_FAILURE);
    }
    printf("Server is listening on port %d...\n", PORT);
    while (1) {
        addr_len = sizeof(client_addr);
        client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addr_len);
        if (client_sock < 0) {
            perror("Accept failed");
            continue;
        }
        printf("Connection accepted from %s:%d\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        memset(buffer, 0, BUFFER_SIZE);
        bytes_received = recv(client_sock, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received < 0) {
            perror("recv failed");
        } else if (bytes_received == 0) {
            printf("Client disconnected without sending data.\n");
        } else {
            buffer[bytes_received] = '\0';
            printf("Received message: %s\n", buffer);
            vuln(buffer);
        }
        close(client_sock);
    }
    close(server_sock);
    return 0;
}
