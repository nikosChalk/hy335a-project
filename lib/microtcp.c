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

/**
 * Same as "man 2 sendto", except that any packet attempted to be sent, and x bytes were successfully sent
 * through sendto(), with x < sizeof(microtcp_header_t) and x != -1, it is automatically retransmitted.
 * @param statistics Used to record statistics about the packets' transmission. Must not be NULL.
 */
static ssize_t threshold_sendto(int sd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen, microtcp_sock_statistics_t *statistics);

/**
 * Same as "man 2 recvfrom", except that any packet attempted to be received, and x bytes were successfully received
 * through rcvfrom(), with x < sizeof(microtcp_header_t) and x != -1, it is automatically dropped.
 * @param statistics Used to record statistics about the packets' transmission. Must not be NULL.
 */
static ssize_t threshold_recvfrom(int sd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen, microtcp_sock_statistics_t *statistics);

/**
 * Creates a microtcp_header_t and initializes every field to 0.
 * @return A microtcp_header_t header with each field initialized to 0.
 */
static microtcp_header_t microtcp_header();

/**
 * Same as microtcp_send() except that one passes both the header and the data to be sent. If data_buffer is NULL, then
 * only the header of the packet is sent.
 */
static ssize_t microtcp_send_packet(microtcp_sock_t *socket, const microtcp_header_t *header, const void *data_buffer, size_t data_length, int flags);




microtcp_sock_t microtcp_socket (int domain, int type, int protocol) {
    /* Your code here */
}

int microtcp_bind (microtcp_sock_t *socket, const struct sockaddr *address, socklen_t address_len) {
    /* Your code here */
    /* Na thetei to state tou socket se BINDED */
}

int microtcp_connect (microtcp_sock_t *socket, const struct sockaddr *address, socklen_t address_len) {
  /* Your code here */
}

int microtcp_accept (microtcp_sock_t *socket, struct sockaddr *address, socklen_t address_len) {
    microtcp_header_t *peer_header;
    microtcp_header_t host_syn_ack_header;
    ssize_t bytes_received;

    if(!socket) {    /* socket must not be NULL */
        LOG_ERROR("socket must not be NULL");
        return -1;
    } else if(socket->state != BINDED) {
        LOG_ERROR("socket must have been binded");
        socket->state = INVALID;
        return -1;
    }
    /* Check if binded */
    /* Check if listen has been called */
    /* Are all checks done? */

    socket->statistics = calloc(1, sizeof(*socket->statistics));    /* Memory initialized to 0 */
    socket->buf_length = MICROTCP_RECVBUF_LEN;
    socket->recvbuf = malloc(sizeof(*socket->recvbuf) * socket->buf_length);
    socket->buf_fill_level = 0;
    socket->seq_number = rand() % SIZE_MAX; /* SIZE_MAX is the max value for size_t types */
    socket->peer_sin = malloc(sizeof(*socket->peer_sin));
    memset(socket->peer_sin, 0, sizeof(*socket->peer_sin)); /* This is a struct sockaddr_in. It MUST be initialized to zero. */

    if(!address) {  /* We want the peer's information regardless what the API user requested */
        address = (struct sockaddr*)socket->peer_sin;
        address_len = sizeof(*socket->peer_sin);
    }
    while(1) {
        LOG_INFO("Waiting for connection...");
        bytes_received = threshold_recvfrom(socket->sd, socket->recvbuf, socket->buf_length, 0, address, &address_len, socket->statistics);
        if (bytes_received == -1) {   /* Blocking */
            LOG_ERROR("Someone attempted a connection but failed:");
            perror(NULL);
            socket->state = INVALID;
            return -1;
        }

        peer_header = (microtcp_header_t *)socket->recvbuf;
        ntoh_header(peer_header);    /* Header was travelling in the Network, therefore he is in Network Byte Order */
        if(!is_syn(peer_header)) {
            LOG_WARN("Someone attempted a connection without SYN control field. Connection Refused.");
            continue;
        }

        /* Assuming that the packet does not have errors. (Implementation in phase B) */
        /* In case of error, the bellow code should not be executed */
        socket->buf_fill_level += bytes_received;
        if(address != (struct sockaddr*)socket->peer_sin)
            memcpy(socket->peer_sin, address, address_len);         /************ This line should be tested. It may contain BUGS ************/
        break;
    }
    LOG_INFO("Received incoming SYN packet");

    /*The peer_header is fine: contains seq of peer and it is a SYN packet. */
    socket->peer_seq_number = peer_header->seq_number;
    /* Sending SYN, ACK packet to peer */
    host_syn_ack_header = microtcp_header();
    host_syn_ack_header.seq_number = socket->seq_number;
    host_syn_ack_header.ack_number = socket->peer_seq_number + bytes_received;
    set_syn(&host_syn_ack_header, 1);
    set_ack(&host_syn_ack_header, 1);
    hton_header(&host_syn_ack_header);
    socket->buf_fill_level = 0;         /* Empty buffer. Its information is no longer needed */

    LOG_INFO("Replying with SYN, ACK...");
    if(microtcp_send_packet(socket, &host_syn_ack_header, NULL, 0, 0) == -1) {
        LOG_ERROR("Attempted to send SYN, ACK but failed:");
        perror(NULL);
        socket->state = INVALID;
        return -1;
    }
    LOG_INFO("Connection successfully established!");
    socket->state = ESTABLISHED;
    return 0;
}

int microtcp_shutdown (microtcp_sock_t *socket, int how) {
  /* Your code here */
}

ssize_t microtcp_send (microtcp_sock_t *socket, const void *buffer, size_t length, int flags) {
    /* Your code here */
    /* Make header and call microtcp_send_packet() */
}

ssize_t microtcp_recv (microtcp_sock_t *socket, void *buffer, size_t length, int flags) {
    /* Your code here */
    /* threshold_rcvfrom() should be used instead of rcvfrom() */
}


static microtcp_header_t microtcp_header() {
    microtcp_header_t header;
    memset(&header, 0, sizeof(header));
    return header;
}

static ssize_t microtcp_send_packet(microtcp_sock_t *socket, const microtcp_header_t *header, const void *data_buffer, size_t data_length, int flags) {
    /* Fragment packets with data bigger than MICROTCP_RECVBUF_LEN-sizeof(header)-1?. */
    /* Check also if socket has ESTABLISHED state */
    /* Should deal with NULL data_buffer since that indicates that the packet is only a header */
    /* threshold_sendto() should be used instead of threshold_rcvfrom() */
}

static ssize_t threshold_recvfrom(int sd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen, microtcp_sock_statistics_t *statistics) {
    ssize_t bytes_received;
    assert(statistics);
    /* MUST FILL IN STATISTICS */
    do {
        bytes_received = recvfrom(sd, buf, len, flags, src_addr, addrlen);
        if(bytes_received == -1)
            return -1;
    } while(bytes_received < sizeof(microtcp_header_t));
    return bytes_received;
}

static ssize_t threshold_sendto(int sd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen, microtcp_sock_statistics_t *statistics) {
    ssize_t bytes_sent;
    assert(statistics);
    /* MUST FILL IN STATISTICS */
    do {
        bytes_sent = sendto(sd, buf, len, flags, dest_addr, addrlen);
        if(bytes_sent == -1)
            return -1;
    } while(bytes_sent < sizeof(microtcp_header_t));
    return bytes_sent;
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