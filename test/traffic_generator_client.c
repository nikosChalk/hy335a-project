/*
 * microtcp, a lightweight implementation of TCP for teaching,
 * and academic purposes.
 *
 * Copyright (C) 2017  Manolis Surligas <surligas@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/time.h>
#include <time.h>

#include "../lib/microtcp.h"
#include "../utils/log.h"

#define BUF_LEN 2048

static char running = 1;

static void sig_handler(int signal) {
  if(signal == SIGINT) {
    LOG_INFO("Stopping traffic generator client...");
    running = 0;
  }
}

int main(int argc, char **argv) {
    uint16_t port;
    int opt;
    char *ipstr = NULL;
    microtcp_sock_t socket;
    struct sockaddr_in server_address;
    socklen_t server_address_len;
    int ret;
    ssize_t ret_recv;
    char buffer[BUF_LEN];
    struct timespec start_time;
    struct timespec end_time;

    while ((opt = getopt (argc, argv, "p:a:")) != -1) {
        switch (opt)
        {
            case 'p':
                port = atoi (optarg);
                break;
            case 'a':
                ipstr = strdup (optarg);
                break;

            default:
                printf (
                        "Usage: bandwidth_test [-s] [-m] -p port -f file"
                                "Options:\n"
                                "   -p <int>            The listening port of the server\n"
                                "   -a <string>         The IP address of the server. This option is ignored if the tool runs in server mode.\n");
                exit (EXIT_FAILURE);
        }
    }
  /*
   * Register a signal handler so we can terminate the client with
   * Ctrl+C
   */
    signal(SIGINT, sig_handler);

  /*create a microtcp socket*/
    socket = microtcp_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    LOG_INFO("Start receiving traffic from port %u", port);

    memset(&server_address, 0, sizeof(struct sockaddr));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    inet_aton(ipstr, &server_address.sin_addr);
    server_address_len = sizeof(struct sockaddr_in);
    ret = microtcp_connect(&socket,(struct sockaddr *) &server_address,  server_address_len);

    if(ret!=0){
        LOG_ERROR("Failed to connect");
        return -EXIT_FAILURE;
    }

    while(running) {
        clock_gettime(CLOCK_MONOTONIC_RAW, &start_time);
        ret_recv = microtcp_recv(&socket,buffer, BUF_LEN,0);
        clock_gettime(CLOCK_MONOTONIC_RAW, &end_time);
        double elapsed = end_time.tv_sec - start_time.tv_sec + (end_time.tv_nsec - start_time.tv_nsec) * 1e-9;
        printf("%lf\n", elapsed);
        if(ret_recv == 0){
            break;
        }
    }

    LOG_INFO("Going to terminate microtcp connection...");
    microtcp_shutdown(&socket, SHUT_RDWR);
  /* Ctrl+C pressed! Store properly time measurements for plotting */
}

