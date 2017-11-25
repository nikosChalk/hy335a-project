

#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include "../lib/microtcp.h"

/*
 * You can use this file to write a test microTCP server.
 * This file is already inserted at the build system.
 */

int main(int argc, char **argv) {
    microtcp_sock_t socket = microtcp_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in server_sin;
    memset(&server_sin, 0, sizeof(struct sockaddr_in));

    server_sin.sin_family = AF_INET;
    server_sin.sin_port = htons(40000);
    inet_aton("127.0.0.1", &server_sin.sin_addr);

    microtcp_bind(&socket, (struct sockaddr *)&server_sin, sizeof(server_sin));
    microtcp_accept(&socket, NULL, 0);
}
