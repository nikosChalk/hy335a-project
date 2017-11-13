/*
 * microtcp, a lightweight implementation of TCP for teaching,
 * and academic purposes.
 *
 * Copyright (C) 2015-2017  Manolis Surligas <surligas@gmail.com>
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

#include "microtcp.h"
#include "../utils/crc32.h"

/**
 * Converts the byte order of each field of header, from Network Byte Order
 * to Host Byte Order. We are assuming that the header is in Network Byte Order.
 * @param header The header to convert
 */
static void ntoh_header(microtcp_header_t *header);

/**
 * Converts the byte order of each field of header, from Host Byte Order
 * to Network Byte Order. We are assuming that the header is in Host Byte Order.
 * @param header The header to convert
 */
static void hton_header(microtcp_header_t *header);


microtcp_sock_t microtcp_socket (int domain, int type, int protocol) {
  /* Your code here */
}

int microtcp_bind (microtcp_sock_t *socket, const struct sockaddr *address, socklen_t address_len) {
  /* Your code here */
}

int microtcp_connect (microtcp_sock_t *socket, const struct sockaddr *address, socklen_t address_len) {
  /* Your code here */
}

int microtcp_accept (microtcp_sock_t *socket, struct sockaddr *address, socklen_t address_len) {    /* Header might change due to TA's typo */
    if(!socket)    /* socket must not be NULL */
        return -1;
    /* Check if binded */
    /* Check if listen has been called */
    /* Are all checks done? */
    uint8_t buffer[MICROTCP_RECVBUF_LEN];
    microtcp_header_t *header;
    ssize_t bytes_received;

    while((bytes_received = recvfrom(socket->sd, &buffer, MICROTCP_RECVBUF_LEN, 0, address, address_len)) == -1) {   /* Blocking */
        LOG_WARN("Someone attempted a connection but failed");
        perror(NULL);
    }
    header = (microtcp_header_t *)buffer;
    ntoh_header(header);    /* Header was travelling in the Network, therefore he is in Network Byte Order */

    /* Assume that the header is fine: contains seq of peer and it is a SYN packet. */

}

int microtcp_shutdown (microtcp_sock_t *socket, int how) {
  /* Your code here */
}

ssize_t microtcp_send (microtcp_sock_t *socket, const void *buffer, size_t length, int flags) {
    /* Your code here */
    /* Check also if socket has ESTABLISHED state */
}

ssize_t microtcp_recv (microtcp_sock_t *socket, void *buffer, size_t length, int flags) {
  /* Your code here */
}


static void ntoh_header(microtcp_header_t *header) {
    if(!header)
        return;
    header->seq_number = ntohl(header->seq_number);
    header->ack_number = ntohl(header->ack_number);
    header->control = ntohs(header->control);
    header->window = ntohs(header->window);
    header->data_len = ntohl(header->data_len);
    /* The type of future_use might change in the future
    header->future_use0 = ntohl(header->future_use0);
    header->future_use0 = ntohl(header->future_use0);
    header->future_use0 = ntohl(header->future_use0);
    */
    header->checksum = ntohl(header->checksum);
}

static void hton_header(microtcp_header_t *header) {
    if(!header)
        return;
    header->seq_number = htonl(header->seq_number);
    header->ack_number = htonl(header->ack_number);
    header->control = htons(header->control);
    header->window = htons(header->window);
    header->data_len = htonl(header->data_len);
    /* The type of future_use might change in the future
    header->future_use0 = htonl(header->future_use0);
    header->future_use0 = htonl(header->future_use0);
    header->future_use0 = htonl(header->future_use0);
    */
    header->checksum = htonl(header->checksum);
}