

#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include "../lib/microtcp.h"

/*
 * You can use this file to write a test microTCP client.
 * This file is already inserted at the build system.
 */

int main(int argc, char **argv) {
    microtcp_sock_t socket = microtcp_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in connect_to_sin;
    int bind_before_connect = 1;

    memset(&connect_to_sin, 0, sizeof(struct sockaddr_in));
    connect_to_sin.sin_family = AF_INET;
    connect_to_sin.sin_port = htons(40000);
    inet_aton("127.0.0.1", &connect_to_sin.sin_addr);

    if(bind_before_connect) {
        struct sockaddr_in listen_sin;
        memset(&listen_sin, 0, sizeof(struct sockaddr_in));

        listen_sin.sin_family = AF_INET;
        listen_sin.sin_port = htons(30000);
        inet_aton("127.0.0.1", &listen_sin.sin_addr);

        microtcp_bind(&socket, (struct sockaddr *) &listen_sin, sizeof(listen_sin));
    }

    microtcp_connect(&socket, (struct sockaddr *)&connect_to_sin, sizeof(connect_to_sin));
}
