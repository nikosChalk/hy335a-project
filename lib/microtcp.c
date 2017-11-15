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

#include <time.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>
#include "microtcp.h"
#include "bits.h"
#include "../utils/crc32.h"
#include "../utils/log.h"

/**
 * Converts the byte order of each field of header, from Network Byte Order
 * to Host Byte Order. We are assuming that the header is in Network Byte Order.
 * @param header The header to convert. Must not be NULL.
 */
static void ntoh_header(microtcp_header_t *header);

/**
 * Converts the byte order of each field of header, from Host Byte Order
 * to Network Byte Order. We are assuming that the header is in Host Byte Order.
 * @param header The header to convert. Must not be NULL.
 */
static void hton_header(microtcp_header_t *header);

/**
 * Returns whether or not the given header has enabled its ACK control bit field.
 * @param header The header to check. Must not be NULL.
 * @return 1 if the ACK control bit field is 1. Otherwise, returns 0.
 */
static int is_ack(microtcp_header_t const *header);

/**
 * Returns whether or not the given header has enabled its RST control bit field.
 * @param header The header to check. Must not be NULL.
 * @return 1 if the RST control bit field is 1. Otherwise, returns 0.
 */
static int is_rst(microtcp_header_t const *header);

/**
 * Returns whether or not the given header has enabled its SYN control bit field.
 * @param header The header to check. Must not be NULL.
 * @return 1 if the SYN control bit field is 1. Otherwise, returns 0.
 */
static int is_syn(microtcp_header_t const *header);

/**
 * Returns whether or not the given header has enabled its FIN control bit field.
 * @param header The header to check. Must not be NULL.
 * @return 1 if the FIN control bit field is 1. Otherwise, returns 0.
 */
static int is_fin(microtcp_header_t const *header);

/**
 * Sets the ACK control bit field of the given header to the given bit.
 * @param header The header to change. Must not be NULL.
 * @param ack_bit The value of the ACK control bit field, which must be either 0 or 1.
 */
static void set_ack(microtcp_header_t *header, uint8_t ack_bit);

/**
 * Sets the RST control bit field of the given header to the given bit.
 * @param header The header to change. Must not be NULL.
 * @param ack_bit The value of the RST control bit field, which must be either 0 or 1.
 */
static void set_rst(microtcp_header_t *header, uint8_t rst_bit);

/**
 * Sets the SYN control bit field of the given header to the given bit.
 * @param header The header to change. Must not be NULL.
 * @param ack_bit The value of the SYN control bit field, which must be either 0 or 1.
 */
static void set_syn(microtcp_header_t *header, uint8_t syn_bit);

/**
 * Sets the FIN control bit field of the given header to the given bit.
 * @param header The header to change. Must not be NULL.
 * @param ack_bit The value of the FIN control bit field, which must be either 0 or 1.
 */
static void set_fin(microtcp_header_t *header, uint8_t fin_bit);


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
    microtcp_header_t *peer_header;
    microtcp_header_t host_syn_ack_header;
    socklen_t *tmp_addr_len;                            /****** MAYBE THIS SHOULD NOT BE POINTER ******/
    ssize_t bytes_received, bytes_sent;

    if(!socket)    /* socket must not be NULL */
        return -1;
    /* Check if binded */
    /* Check if listen has been called */
    /* Are all checks done? */

    socket->buf_length = MICROTCP_RECVBUF_LEN;
    socket->recvbuf = malloc(sizeof(*socket->recvbuf) * socket->buf_length);
    socket->buf_fill_level = 0;
    socket->seq_number = rand() % SIZE_MAX; /* SIZE_MAX is the max value for size_t types */
    socket->peer_sin = malloc(sizeof(*socket->peer_sin));
    memset(socket->peer_sin, 0, sizeof(*socket->peer_sin)); /* This is a struct sockaddr_in. It MUST be initialized to zero. */

    if(!address) {  /* We want the peer's information regardless what the API user requested */
        address = (struct sockaddr*)socket->peer_sin;
        address_len = tmp_addr_len;
    }
    while(1) {
        if ((bytes_received = recvfrom(socket->sd, socket->recvbuf, socket->buf_length, 0, address, address_len)) == -1) {   /* Blocking */
            LOG_WARN("Someone attempted a connection but failed");
            perror(NULL);
            continue;
        }

        peer_header = (microtcp_header_t *)socket->recvbuf;
        ntoh_header(peer_header);    /* Header was travelling in the Network, therefore he is in Network Byte Order */
        if(!is_syn(peer_header)) {
            LOG_WARN("Someone attempted a connection without SYN control field. Connection Refused.");
            continue;
        }
        /* Assuming that the packet does not have errors. (Implementation in phase B) */
        socket->buf_fill_level += bytes_received;
        if(address != (struct sockaddr*)socket->peer_sin)
            memcpy(socket->peer_sin, address, *address_len);
        break;
    }

    /*The peer_header is fine: contains seq of peer and it is a SYN packet. */
    socket->peer_seq_number = peer_header->seq_number;
    /* Sending SYN, ACK packet to peer */
    host_syn_ack_header.seq_number = socket->seq_number;
    host_syn_ack_header.ack_number = socket->peer_seq_number + bytes_received;
    set_syn(&host_syn_ack_header, 1);
    set_ack(&host_syn_ack_header, 1);
    hton_header(&host_syn_ack_header);

    bytes_sent = sendto(socket->sd, &host_syn_ack_header, sizeof(microtcp_header_t), 0, (struct sockaddr *)socket->peer_sin, sizeof(*socket->peer_sin));

}

int microtcp_shutdown (microtcp_sock_t *socket, int how) {
  /* Your code here */
}

ssize_t microtcp_send (microtcp_sock_t *socket, const void *buffer, size_t length, int flags) {
    /* Your code here */
    /* Fragment packets with data bigger than MICROTCP_RECVBUF_LEN-sizeof(header)-1?. */
    /* Check also if socket has ESTABLISHED state */
}

ssize_t microtcp_recv (microtcp_sock_t *socket, void *buffer, size_t length, int flags) {
  /* Your code here */
}


static void ntoh_header(microtcp_header_t *header) {
    assert(header);
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
    assert(header);
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

static int is_ack(microtcp_header_t const *header) {
    assert(header);
    return get_bit(&(header->control), sizeof(header->control), 1, 4);
}

static int is_rst(microtcp_header_t const *header) {
    assert(header);
    return get_bit(&(header->control), sizeof(header->control), 1, 5);
}

static int is_syn(microtcp_header_t const *header) {
    assert(header);
    return get_bit(&(header->control), sizeof(header->control), 1, 6);
}

static int is_fin(microtcp_header_t const *header) {
    assert(header);
    return get_bit(&(header->control), sizeof(header->control), 1, 7);
}


static void set_ack(microtcp_header_t *header, uint8_t ack_bit) {
    assert(header && (ack_bit == 0 || ack_bit == 1));
    set_bit(&(header->control), sizeof(header->control), 1, 4, ack_bit);
}

static void set_rst(microtcp_header_t *header, uint8_t rst_bit) {
    assert(header && (rst_bit == 0 || rst_bit == 1));
    set_bit(&(header->control), sizeof(header->control), 1, 5, rst_bit);
}

static void set_syn(microtcp_header_t *header, uint8_t syn_bit) {
    assert(header && (syn_bit == 0 || syn_bit == 1));
    set_bit(&(header->control), sizeof(header->control), 1, 6, syn_bit);
}

static void set_fin(microtcp_header_t *header, uint8_t fin_bit) {
    assert(header && (fin_bit == 0 || fin_bit == 1));
    set_bit(&(header->control), sizeof(header->control), 1, 7, fin_bit);
}