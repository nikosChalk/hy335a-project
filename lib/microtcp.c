

#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <float.h>
#include <inttypes.h>
#include <assert.h>
#include <arpa/inet.h>
#include "microtcp.h"
#include "bits.h"
#include "../utils/crc32.h"
#include "../utils/log.h"

/****************************************************************/
/********************* FORWARD DECLARATIONS *********************/
/****************************************************************/

/**
 * Calculates the time difference between the two given points in time
 * @param end_time The ending time. Must not be NULL.
 * @param start_time The starting time. Must not be NULL.
 * @return the end_time - start_time in seconds
 */
static double get_time_diff(struct timespec const *end_time, struct timespec const *start_time);

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
 * Same as "man 2 recvfrom", except that any packet attempted to be received, and x bytes were successfully received
 * through rcvfrom(), with x < sizeof(microtcp_header_t) and x != -1, it is automatically dropped.
 */
static ssize_t threshold_recvfrom(int sd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);

/**
 * This function blocks until a packet is received from an address same as socket->peer_sin. Packets not from that address
 * are dropped and never stored.
 * Once a packet from that address has been received (valid packet), it is stored within socket->packet_buffer.
 * The packet's header will be stored in HOST Byte Order, while the packet's payload (data) will be
 * stored in NETWORK Byte Order. Its payload is NOT inserted into socket->recvbuf.
 * Also when the valid packet is received, bytes_received and packets_received of socket->statistics are updated.
 *
 * In case that the packet's checksum is wrong, packets_lost of socket->statistics are updated and 3 DUPs are sent.
 * After that, it waits again for a packet.
 *
 * Note that the socket->ack_number are left unaffected.
 * No ACK is send back to the sender.
 * It is guaranteed that at least sizeof(microtcp_header_t) data will be received in case of no error.
 * In error case (including CRC error), the socket is not changed except for socket->packet_buffer
 * @param socket The socket from which the data will be received. Must not be NULL and socket->peer_sin is assumed hold
 * valid information. Packet received will be stored in socket->packet_buffer with the header in HOST Byte Order and the
 * payload in NETWORK Byte order.
 * @param flags Same as "man 2 recvfrom"
 * @return Bytes that were received (>= sizeof(microtcp_header_t)) or -1 in error case.
 */
static ssize_t threshold_recv(microtcp_sock_t *socket, int flags);

/**
 * This function blocks until a packet is received from an address same as socket->peer_sin. The packet must
 * also be only a header with no data and its control field must match the given control field. Packets not satisfying
 * these constraints are never stored and are always dropped without altering socket's fields, except for socket->packet_buffer.
 * Once valid header has been received, it is stored within socket->packet_buffer.
 * The header will be stored in HOST Byte Order. Also when the valid packet is received, bytes_received and packets_received
 * of socket->statistics are updated. In addition to that, socket->ack_number is increased. (+= bytes_received)
 *
 * In case that the packet's checksum is wrong, packets_lost of socket->statistics are updated and 3 DUPs are sent.
 * After that, it waits again for a packet.
 *
 * Note that the socket->ack_number are left unaffected.
 * No ACK is send back to the sender.
 * It is guaranteed that at least sizeof(microtcp_header_t) data will be received in case of no error.
 * In error case (including CRC error), the socket is not changed except for socket->packet_buffer
 * @param socket The socket which waits for a specific header packet to be received. Must not be NULL and socket->peer_sin is assumed hold
 * valid information. The header received will be stored within socket->packet_buffer in HOST Byte order.
 * @param ack The ack bit, as in set_ack()
 * @param rst The rst bit, as in set_rst()
 * @param syn The syn bit, as in set_syn()
 * @param fin The fin bit, as in set_fin()
 * @param flags As Same as "man 2 recvfrom"
 * @return Bytes received (==sizeof(microtcp_header_t)) or -1 in case of error.
 */
static ssize_t recv_header(microtcp_sock_t *socket, uint8_t ack, uint8_t rst, uint8_t syn, uint8_t fin, int flags);

/**
 * Same as "man 2 sendto", except that any packet attempted to be sent, and x bytes were successfully sent
 * through sendto(), with x < sizeof(microtcp_header_t) and x != -1, it is automatically retransmitted.
 */
static ssize_t threshold_sendto(int sd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);

/**
 * This function sends a packet that is stored within socket->packet_buffer to the address defined by socket->peer_sin.
 * It is guaranteed that at least sizeof(microtcp_header_t) data will be sent in case of no error. Note that in
 * error case, the socket is not changed, except for socket->packet_buffer.
 * The socket->packet_buffer is assumed to have its header in HOST byte order without the checksum field calculated, and its data in
 * NETWORK byte order.
 * In a successful send, the socket->seq_number is updated with the number of bytes that were sent, which are equal
 * to the number of bytes returned. Also updates bytes_send, and packets_send of socket->statistics.
 * Note that after the packet is sent, the function does not wait for an ACK reply and simply returns.
 * Also note that, fragmentation should be taken care of by the caller.
 * Also note that, the packet's CRC is calculated.
 * @param socket The socket from which the data will be sent. Must not be NULL and socket->peer_sin is assumed hold
 * valid information. The socket->packet_buffer is assumed to have its header in HOST byte order and its data in
 * NETWORK byte order.
 * @param flags Same as "man 2 sendto"
 * @return Bytes that were sent (>= sizeof(microtcp_header_t) or -1 in case of error.
 */
static ssize_t threshold_send(microtcp_sock_t *socket, int flags);

/**
 * Sends a header with the given control fields to the address that is specified by socket->peer_sin.
 * If the send is successful, socket->seq_number is updated with the correct value and bytes_sent, packets_sent of socket->statistics
 * are also updated. In case of error, the socket is not changed, except for socket->packet_buffer.
 *
 * Note that this function uses packet->packet_buffer as the place where the header to be sent is stored. After the call, the
 * sent header is stored within socket->packet_buffer in HOST Byte Order.
 *
 * Also note that this function does not wait for an ACK packet to be received as a reply, it simply returns after sending the header.
 * Also note that, the packet's CRC is calculated.
 * @param socket The socket from which the data will be send. Must not be NULL.
 * @param ack The ack control bit. Same as set_ack()
 * @param ack_number If the ack is set to 0, then this field is ignored. Otherwise, if ack is set to 1, this field will be
 * used as the ack_number of the header to be send and will also update the socket->ack_number with this value.
 * @param rst The rst control bit. Same as set_rst()
 * @param syn The syn control bit. Same as set_syn(). If this bit is set to 1, then a random sequence number is chosen to be sent
 * and is also written in socket->seq_number
 * @param fin The fin control bit. Same as set_fin()
 * @param flags Same as threshold_send()
 * @return Bytes that were sent (>= sizeof(microtcp_header_t) or -1 in case of error.
 */
static ssize_t send_header(microtcp_sock_t *socket, uint8_t ack, uint32_t ack_number, uint8_t rst, uint8_t syn, uint8_t fin, int flags);

/**
 * Releases any dynamically allocated resources that this socket has acquired. Note that this function assumes that
 * socket has already acquired valid resources.
 * @param socket The socket whose resources will be released. Must not be NULL.
 */
static void release_sock_resources(microtcp_sock_t *socket);

/**
 * Acquires dynamic resources that this socket needs. All dynamically allocated resources are initialized to zero.
 * Note that this function assumes that the socket does not already
 * own any resources in order to avoid memory leaks. The state of the socket is unaffected.
 *
 * socket->statistics->rx_max_inter and socket->statistics->tx_max_inter are initialized to -1;
 * socket->statistics->rx_min_inter and socket->statistics->tx_min_inter are initialized to DBL_MAX;
 * Rest fields of socket->statistics are initialized to 0, normally.
 * @param socket The socket whose resources will be acquired. Must not be NULL.
 */
static void acquire_sock_resources(microtcp_sock_t *socket);

/**
 * Displays the statistics of this socket from the point when a peer was connected to it, until now.
 * Statistics are dumped in stdout
 * @param sock_statistics The socket's statistics which will be displayed. Must not be NULL.
 */
static void display_statistics(microtcp_sock_statistics_t *sock_statistics);

/**
 * Creates a microtcp_header_t and initializes every field to 0.
 * @return A microtcp_header_t header with each field initialized to 0.
 */
static microtcp_header_t microtcp_header();

/*******************************************************************/
/******************* END OF FORWARD DECLARATIONS *******************/
/*******************************************************************/

microtcp_sock_t microtcp_socket (int domain, int type, int protocol) {
    static int has_called_srand = 0;
    if(!has_called_srand) {
        has_called_srand = 1;
        srand(time(NULL));
    }
    microtcp_sock_t new_socket;

    /*initialize all fields*/
    new_socket.state = UNKNOWN;
    new_socket.init_win_size = 0;
    new_socket.curr_win_size = 0;
    new_socket.recvbuf = NULL;
    new_socket.packet_buffer = NULL;
    new_socket.cwnd = 0;
    new_socket.ssthresh = 0;
    new_socket.seq_number = 0;
    new_socket.ack_number = 0;

    new_socket.peer_sin = NULL;
    new_socket.statistics = NULL;

    /*check for errors*/
    if((new_socket.sd = (socket(domain, type, protocol))) == -1) {
        LOG_ERROR("Socket creation failed!");
        perror(NULL);
        new_socket.state = INVALID;
    }
    return new_socket;
}

int microtcp_bind (microtcp_sock_t *socket, const struct sockaddr *address, socklen_t address_len) {
    const struct sockaddr_in *tmp_addr = (const struct sockaddr_in *)address;

    if(socket->state == UNKNOWN && bind(socket->sd, address, address_len) == 0) {
        socket->state = BINDED;
        LOG_INFO("Socket binded in IP address \"%s\" and port %u", inet_ntoa(tmp_addr->sin_addr), ntohs(tmp_addr->sin_port));
        return 0;
    } else {
        LOG_ERROR("The socket's state is not unknown OR bind failed!");
        perror(NULL);
        return -1;
    }
}

int microtcp_connect (microtcp_sock_t *socket, const struct sockaddr *address, socklen_t address_len) {
    microtcp_header_t *peer_header;
    ssize_t bytes_received;
    ssize_t bytes_sent;

    /* Checking if parameters comply to documentation */
    if(!socket || !address) {
        LOG_ERROR("socket and address must not be NULL");
        return  -1;
    } else if(socket->state == UNKNOWN) {   /* Bind was not previously called. Socket must be binded to all available interfaces and in a random port */
        struct sockaddr_in host_sin;
        socklen_t host_addr_len;

        LOG_INFO("Connect invoked without having the socket binded. Binding the socket...");
        memset(&host_sin, 0, sizeof(host_sin));
        host_sin.sin_family = AF_INET;
        host_sin.sin_port = htons(0);   /* Bind to some available port defined by OS */
        host_sin.sin_addr.s_addr = INADDR_ANY;  /*  Bind to all available interfaces */
        host_addr_len = sizeof(host_sin);

        if(microtcp_bind(socket, (struct sockaddr*)(&host_sin), host_addr_len) == -1) {
            LOG_ERROR("Could not bind socket. Connect failed.");
            perror(NULL);
            return -1;
        }
    } else if(socket->state != BINDED) {
        LOG_ERROR("Could not connect to remote host. Invalid socket state.");
        return -1;
    }

    /* Acquiring resources and sendind SYN packet */
    acquire_sock_resources(socket);
    memcpy(socket->peer_sin, (struct sockaddr_in *)address, address_len);

    /* Sending SYN packet*/
    LOG_INFO("Attempting connection to IP address \"%s\" in port %u", inet_ntoa(socket->peer_sin->sin_addr), ntohs(socket->peer_sin->sin_port));
    LOG_INFO("Sending SYN packet...");
    if ((bytes_sent = send_header(socket, 0, 0, 0, 1, 0, 0)) == -1) {
        LOG_ERROR("Failed to dispatch SYN packet. Aborting connection to remote host.");
        perror(NULL);
        release_sock_resources(socket);
        socket->state = INVALID;
        return -1;
    }
    LOG_INFO("SYN packet sent with sequence number: %u.", (socket->seq_number-(uint32_t)bytes_sent));

    /* Waiting for SYN ACK packet... */
    LOG_INFO("Waiting for SYN ACK packet...");
    if((bytes_received = recv_header(socket, 1, 0, 1, 0, 0)) == -1) {
        LOG_ERROR("Error while receiving SYN ACK header. Connection aborted");
        perror(NULL);
        release_sock_resources(socket);
        socket->state = INVALID;
        return -1;
    }
    peer_header = (microtcp_header_t *)socket->packet_buffer;
    LOG_INFO("SYN ACK packet received with sequence number %u and ack number %u", peer_header->seq_number, peer_header->ack_number);

    /* Sending ACK packet */
    LOG_INFO("Sending ACK packet with ACK number %u", socket->ack_number);
    if((send_header(socket, 1, socket->ack_number, 0, 0, 0, 0)) == -1) {  /* Not a critical issue. The (server) user will call microtcp_rcv() which will re-dispatch this ACK */
        LOG_WARN("Failed to send ACK packet during 3-way handshake.");
        perror(NULL);
    }

    LOG_INFO("Connection successfully established!");
    LOG_INFO("Current Sequence Number: %u", socket->seq_number);
    LOG_INFO("Current ACK Number: %u", socket->ack_number);
    LOG_INFO("~~~\n");
    socket->state = ESTABLISHED;
    return 0;
}

int microtcp_accept (microtcp_sock_t *socket, struct sockaddr *address, socklen_t address_len) {
    microtcp_header_t *peer_header;
    uint32_t received_checksum;
    ssize_t bytes_received;
    ssize_t bytes_sent;

    if(!socket) {    /* socket must not be NULL */
        LOG_ERROR("socket must not be NULL");
        return -1;
    } else if(socket->state != BINDED) {
        LOG_ERROR("socket must have been binded");
        socket->state = INVALID;
        return -1;
    }

    acquire_sock_resources(socket);
    if(!address) {  /* We want the peer's information regardless what the API user requested */
        address = (struct sockaddr*)socket->peer_sin;
        address_len = sizeof(*socket->peer_sin);
    }

    while(1) {
        LOG_INFO("Waiting for connection...");
        bytes_received = threshold_recvfrom(socket->sd, socket->packet_buffer, (MICROTCP_MSS + sizeof(microtcp_header_t)), 0, address, &address_len); /* Blocking */
        if (bytes_received == -1) {
            LOG_ERROR("Waiting for connection failed:");
            perror(NULL);
            release_sock_resources(socket);
            socket->state = INVALID;
            return -1;
        }

        /* Check if received packet is SYN */
        peer_header = (microtcp_header_t *)socket->packet_buffer;
        ntoh_header(peer_header);    /* Header was travelling in the Network, therefore he is in Network Byte Order */
        if(!is_syn(peer_header)) {
            LOG_WARN("Someone attempted a connection without SYN control field. Connection Refused.");
            continue;
        }

        /* Check packet's CRC */
        received_checksum = peer_header->checksum;
        peer_header->checksum = 0;
        peer_header->checksum = crc32(socket->packet_buffer, (sizeof(microtcp_header_t) + peer_header->data_len));
        if(received_checksum != peer_header->checksum) {
            LOG_ERROR("Received packet with wrong checksum during 3 way handshake. Connection refused.");
            continue;
        }
        break;
    }
    if(address != (struct sockaddr*)socket->peer_sin)   /* PASSED address is not NULL. Copy peer's info to socket->peer_sin */
        memcpy(socket->peer_sin, address, address_len);

    /*The peer_header is fine: contains seq of peer and it is a SYN packet. */
    socket->ack_number = peer_header->seq_number + (uint32_t)bytes_received;

    LOG_INFO("Received incoming SYN packet from IP \"%s\" and port %u. Sequence number received: %u",
             inet_ntoa(socket->peer_sin->sin_addr), ntohs(socket->peer_sin->sin_port), peer_header->seq_number);

    /* Sending SYN, ACK packet to peer */
    LOG_INFO("Replying with SYN, ACK...");
    if((bytes_sent = send_header(socket, 1, socket->ack_number, 0, 1, 0, 0)) == -1) {
        LOG_ERROR("Attempted to send SYN, ACK but failed:");
        perror(NULL);
        release_sock_resources(socket);
        socket->state = INVALID;
        return -1;
    }
    LOG_INFO("SYN ACK packet sent with seq_number %u and ack_number %u", (socket->seq_number-(uint32_t)bytes_sent), socket->ack_number);

    /* Waiting for ACK packet */
    LOG_INFO("Waiting ACK packet...");
    if(recv_header(socket, 1, 0, 0, 0, 0) == -1) {
        LOG_ERROR("Error while receiving ACK packet:");
        perror(NULL);
        release_sock_resources(socket);
        socket->state = INVALID;
        return -1;
    }
    LOG_INFO("ACK packet received with seq_number %u and ack_number %u", peer_header->seq_number, peer_header->ack_number);

    LOG_INFO("Connection successfully established!");
    LOG_INFO("Current Sequence Number: %u", socket->seq_number);
    LOG_INFO("Current ACK Number: %u", socket->ack_number);
    LOG_INFO("~~~\n");
    socket->state = ESTABLISHED;
    return 0;
}

int microtcp_shutdown (microtcp_sock_t *socket, int how) {
    microtcp_header_t *header = (microtcp_header_t *)socket->packet_buffer;

    if(socket->state == ESTABLISHED || socket->state == CLOSING_BY_PEER) {    /* User explicitly requests connection termination */
        LOG_INFO("Connection termination requested...");

        /* Send FIN, ACK */
        LOG_INFO("Sending FIN header...");
        if(send_header(socket, 1, socket->ack_number, 0, 0, 1, 0) == -1) {
            LOG_ERROR("Error while sending FIN ACK. Shutdown failed.");
            perror(NULL);
            return -1;
        }
        LOG_INFO("FIN ACK header sent with seq_number %u and ack_number %u", header->seq_number, header->ack_number);

        /* Waiting for ACK */
        LOG_INFO("Waiting for ACK...");
        if(recv_header(socket, 1, 0, 0, 0, 0) == -1) {
            LOG_ERROR("Error while waiting for ACK. Shutdown failed.");
            perror(NULL);
            return -1;
        }
        LOG_INFO("ACK packet received with seq_number %u and ack_number %u", header->seq_number, header->ack_number);

        if(socket->state == ESTABLISHED) {
            socket->state = CLOSING_BY_HOST;

            /* Waiting for FIN ACK */
            LOG_INFO("Waiting for FIN ACK...");
            if(recv_header(socket, 1, 0, 0, 1, 0) == -1) {
                LOG_ERROR("Error while receiving FIN ACK packet. Shutdown failed.");
                perror(NULL);
                return -1;
            }
            LOG_INFO("FIN ACK packet received with seq_number %u and ack_number %u", header->seq_number, header->ack_number);

            /* Sending ACK */
            if(send_header(socket, 1, socket->ack_number, 0, 0, 0, 0) == -1) {
                LOG_ERROR("Error sending ACK. Shutdown failed.");
                perror(NULL);
                return -1;
            }
            LOG_INFO("ACK packet sent with seq_number %u and ack_number %u", header->seq_number, header->ack_number);
        }

        LOG_INFO("Connection successfully terminated");
        LOG_INFO("Statistics:");
        display_statistics(socket->statistics);

        release_sock_resources(socket);
        shutdown(socket->sd, SHUT_RDWR);
        close(socket->sd);
        socket->state = CLOSED;
        return 0;

    } else {
        LOG_ERROR("Invalid call to shutdown. Socket is not in state ESTABLISHED nor in state CLOSING_BY_PEER.");
        return -1;
    }
}

ssize_t microtcp_send(microtcp_sock_t *socket, const void *buffer, size_t length, int flags) {
    static struct timespec last_call_time;
    static struct timespec cur_call_time;
    static struct timeval timeout;    /* For ACK timeout */
    static struct timeval no_timeout;
    static int isFirstCall = 1;
    double time_diff;

    microtcp_header_t *header;
    ssize_t bytes_sent;
    ssize_t bytes_received;
    int retransmit = 0;  /* Boolean in order to check if retransmission is needed */

    if(!socket) {
        LOG_ERROR("NULL socket passed");
        return -1;
    } else if(socket->state != ESTABLISHED) {
        LOG_ERROR("Socket has invalid state");
        return -1;
    }

    /* TODO: Fragmentation */
    header = (microtcp_header_t*)socket->packet_buffer;

    /* Copy data */
    length = MIN(length, MICROTCP_MSS); /* TODO: remove this line with the appropriate */
    memcpy(socket->packet_buffer + sizeof(microtcp_header_t), buffer, length);

    if(isFirstCall) {
        /* Set the timeout interval struct */
        timeout.tv_sec = 0;
        timeout.tv_usec = MICROTCP_ACK_TIMEOUT_US;

        no_timeout.tv_sec = 0;
        no_timeout.tv_usec = 0;
    }

    do {
        /* Create header */
        *header = microtcp_header();
        header->seq_number = socket->seq_number;
        header->data_len = (uint32_t)length;

        /* Send header + data */
        LOG_INFO("Sending total %zu bytes with seq_number %u, of which %zu are user bytes",
                 (length + sizeof(microtcp_header_t)), header->seq_number, length);

        bytes_sent = threshold_send(socket, flags);
        if (bytes_sent == -1) {
            LOG_ERROR("Error while sending packet with seq_number %u", header->seq_number);
            perror(NULL);
            return -1;
        }

        /* Set ack timeout option */
        if (setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {    /* Enable timeout */
            LOG_ERROR("Call to setsockopt() failed while enabling timeout. Aborting ACK receive");
            perror(NULL);
            return -1;
        }

        /* Receive ACK */
        LOG_INFO("Waiting for ACK...");
        bytes_received = recv_header(socket, 1, 0, 0, 0, 0);
        if(bytes_received == -1) { /* Timed out, or something went wrong */
            retransmit = (errno == EAGAIN || errno == EWOULDBLOCK); /* Time out */
            if(!retransmit) {
                LOG_ERROR("Error while receiving ACK");
                perror(NULL);
                return -1;
            }
        } else {    /* ACK received. Check it */
            retransmit = (header->ack_number != socket->seq_number);
            if(retransmit)
                socket->seq_number -= bytes_sent;   /* We will re-send the same packet. The re-transmitted packet must have the same seq_number. */
            else
                socket->ack_number = header->seq_number + (uint32_t)bytes_received;    /* We explicitly change this, since we might have missed a few ACKs in previous loops */
        }
    } while(retransmit);

    /* Restore socket to non-time out mode */
    if (setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO, &no_timeout, sizeof(timeout)) < 0) {    /* Disable timeout */
        LOG_ERROR("Call to setsockopt() failed while disabling timeout.");
        perror(NULL);
        return -1;
    }

    /* For statistics */
    if(isFirstCall) {
        clock_gettime(CLOCK_MONOTONIC_RAW, &last_call_time);
        isFirstCall = 0;
    } else {
        clock_gettime(CLOCK_MONOTONIC_RAW, &cur_call_time);
        time_diff = get_time_diff(&cur_call_time, &last_call_time);
        socket->statistics->tx_min_inter = (time_diff < socket->statistics->tx_min_inter) ? (time_diff) : socket->statistics->tx_min_inter;
        socket->statistics->tx_max_inter = (time_diff > socket->statistics->tx_max_inter) ? (time_diff) : socket->statistics->tx_max_inter;
        socket->statistics->tx_mean_inter += time_diff;

        memcpy(&last_call_time, &cur_call_time, sizeof(cur_call_time));
    }

    return bytes_sent-sizeof(microtcp_header_t);    /* It is always guaranteed that at least sizeof(microtcp_header_t) will be sent */
}

ssize_t microtcp_recv (microtcp_sock_t *socket, void *buffer, size_t length, int flags) {
    static struct timespec last_call_time;
    static struct timespec cur_call_time;
    static int isFirstCall = 1;
    double time_diff;

    microtcp_header_t *header_pointer;
    ssize_t bytes_received, bytes_sent;
    int is_fin_header;
    int is_in_order_packet;
    void *data_pointer;

    if(!socket) {
        LOG_ERROR("NULL socket passed");
        return -1;
    } else if(socket->state != ESTABLISHED) {
        LOG_ERROR("Socket has invalid state");
        return -1;
    }

    /* Wait for packet and drop out of order ones. */
    do {
        LOG_INFO("Waiting for packet...");
        bytes_received = threshold_recv(socket, flags);
        if (bytes_received == -1) {
            LOG_ERROR("Waiting for packet failed:");
            perror(NULL);
            return -1;
        }

        header_pointer = (microtcp_header_t *) socket->packet_buffer;
        data_pointer = socket->packet_buffer + sizeof(microtcp_header_t);

        LOG_INFO("Packet received with seq_number %u", header_pointer->seq_number);
        is_in_order_packet = (header_pointer->seq_number == socket->ack_number) || (header_pointer->seq_number <= (socket->ack_number - bytes_received)); /* TODO: triple check this */
        if (!is_in_order_packet) {
            LOG_WARN("    Packet dropped. Received packet with seq_number %u, while expecting %u",
                     header_pointer->seq_number, socket->ack_number);
            socket->statistics->packets_lost++;
            socket->statistics->bytes_lost = header_pointer->seq_number - socket->ack_number;
        }
        /* TODO: 3 dups */
    } while(!is_in_order_packet);
    is_fin_header = is_fin(header_pointer);

    /* Copy received data to recvbuf */
    cyclic_buffer_append(socket->recvbuf, data_pointer, (bytes_received-sizeof(microtcp_header_t)));

    /* Send ACK */
    LOG_INFO("Replying with ACK packet with seq number %u and ack number %u", socket->seq_number, (socket->ack_number+(uint32_t)bytes_received));
    bytes_sent = send_header(socket, 1, (socket->ack_number+(uint32_t)bytes_received), 0, 0, 0, 0);
    if(bytes_sent == -1) {
        LOG_ERROR("Failed to send ACK header in response to FIN.");
        perror(NULL);
        return -1;
    }

    /* Check if the packet received is FIN */
    if(is_fin_header) {
        /* Shutting down connection */
        LOG_INFO("    Packet received with sequence num %u was FIN.", (socket->ack_number-(uint32_t)bytes_sent));
        LOG_INFO("    State set to: CLOSING_BY_PEER");
        socket->state = CLOSING_BY_PEER;
        return -1;
    }

    /* Return data to user */
    cyclic_buffer_pop(socket->recvbuf, buffer, (bytes_received-sizeof(microtcp_header_t))); /* TODO: It shouldn't be like this. */

    /* For statistics */
    if(isFirstCall) {
        clock_gettime(CLOCK_MONOTONIC_RAW, &last_call_time);
        isFirstCall = 0;
    } else {
        clock_gettime(CLOCK_MONOTONIC_RAW, &cur_call_time);
        time_diff = get_time_diff(&cur_call_time, &last_call_time);
        socket->statistics->rx_min_inter = (time_diff < socket->statistics->rx_min_inter) ? (time_diff) : socket->statistics->rx_min_inter;
        socket->statistics->rx_max_inter = (time_diff > socket->statistics->rx_max_inter) ? (time_diff) : socket->statistics->rx_max_inter;
        socket->statistics->rx_mean_inter += time_diff;

        memcpy(&last_call_time, &cur_call_time, sizeof(cur_call_time));
    }

    return bytes_received-sizeof(microtcp_header_t); /* It is always guaranteed that at least sizeof(microtcp_header_t) bytes will be received */
}

static void acquire_sock_resources(microtcp_sock_t *socket) {
    assert(socket);
    socket->recvbuf = cyclic_buffer_make(MICROTCP_RECVBUF_LEN);
    socket->init_win_size = socket->curr_win_size = cyclic_buffer_free_size(socket->recvbuf);

    socket->peer_sin = calloc(1, sizeof(*socket->peer_sin));       /* This is a struct sockaddr_in. It MUST be initialized to zero. */
    socket->statistics = calloc(1, sizeof(*socket->statistics));    /* Memory initialized to 0 */

    socket->statistics->rx_max_inter = socket->statistics->tx_max_inter = -1;
    socket->statistics->rx_min_inter = socket->statistics->tx_min_inter = DBL_MAX;
}

static void release_sock_resources(microtcp_sock_t *socket) {
    assert(socket);
    cyclic_buffer_delete(socket->recvbuf);
    free(socket->peer_sin);
    free(socket->statistics);
}

static microtcp_header_t microtcp_header() {
    microtcp_header_t header;
    memset(&header, 0, sizeof(header));
    return header;
}

static void display_statistics(microtcp_sock_statistics_t *sock_statistics) {
    if(sock_statistics->tx_max_inter == -1) /* Field has its initial value. No more than 1 data packet was sent. */
        sock_statistics->tx_min_inter = sock_statistics->tx_max_inter = 0;

    if(sock_statistics->rx_max_inter == -1) /* Field has its initial value. No more than 1 data packet was received. */
        sock_statistics->rx_min_inter = sock_statistics->rx_max_inter = 0;

    sock_statistics->rx_mean_inter /= (sock_statistics->packets_received -1);
    sock_statistics->tx_mean_inter /= (sock_statistics->packets_send -1);

    printf("Packets received \t: %" PRIu64 "\n", sock_statistics->packets_received);
    printf("Packets sent \t\t: %" PRIu64 "\n", sock_statistics->packets_send);
    printf("Packets lost \t\t: %" PRIu64 "\n", sock_statistics->packets_lost);
    printf("Packet lost ratio \t: %.6lf %%\n", ((sock_statistics->packets_lost*100)/((double)sock_statistics->packets_received)));
    printf("Packet inter-arrival RX\n");
    printf("Min \t\t\t: %.6lf\n", sock_statistics->rx_min_inter);
    printf("Max \t\t\t: %.6lf\n", sock_statistics->rx_max_inter);
    printf("Mean \t\t\t: %.6lf\n", sock_statistics->rx_mean_inter);
    printf("Std^2 (Variance)\t: ...\n");
    printf("Packet inter-arrival TX\n");
    printf("Min \t\t\t: %.6lf\n", sock_statistics->tx_min_inter);
    printf("Max \t\t\t: %.6lf\n", sock_statistics->tx_max_inter);
    printf("Mean \t\t\t: %.6lf\n", sock_statistics->tx_mean_inter);
    printf("Std^2 (Variance)\t: ...\n");
}

static ssize_t threshold_recvfrom(int sd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
    ssize_t bytes_received;

    do {
        bytes_received = recvfrom(sd, buf, len, flags, src_addr, addrlen);
        if(bytes_received == -1)
            return -1;
    } while((uint32_t)bytes_received < sizeof(microtcp_header_t));
    return bytes_received;
}

static ssize_t threshold_recv(microtcp_sock_t *socket, int flags) {
    struct sockaddr_in remote_addr;
    socklen_t remote_addr_len = sizeof(remote_addr);

    microtcp_header_t *peer_header_p;
    uint32_t received_checksum;
    ssize_t bytes_received;
    assert(socket);

    while(1) {
        bytes_received = threshold_recvfrom(socket->sd, socket->packet_buffer, (MICROTCP_MSS + sizeof(microtcp_header_t)),
                                            flags, (struct sockaddr *)&remote_addr, &remote_addr_len);
        if(bytes_received == -1)
            return -1;

        /* Check where did that packet came from */
        if(socket->peer_sin->sin_family != remote_addr.sin_family ||
           socket->peer_sin->sin_addr.s_addr != remote_addr.sin_addr.s_addr ||
           socket->peer_sin->sin_port != remote_addr.sin_port)
        {
            LOG_WARN("  Received packet from non-connected peer (different family, address or port detected). Packet Dropped.");
            continue;
        }

        /* Check its checksum */
        peer_header_p = (microtcp_header_t *)socket->packet_buffer;
        ntoh_header(peer_header_p);

        received_checksum = peer_header_p->checksum;
        peer_header_p->checksum = 0;
        peer_header_p->checksum = crc32(socket->packet_buffer, (sizeof(microtcp_header_t) + peer_header_p->data_len));
        if(received_checksum != peer_header_p->checksum) {
            LOG_WARN("    Received packet with wrong checksum. Sending 3 DUPs");
            socket->statistics->packets_lost++;
            /*TODO: send 3 DUPs */
            continue;
        }
        break;
    }

    socket->statistics->packets_received++;
    socket->statistics->bytes_received += bytes_received;
    return bytes_received;
}

static ssize_t recv_header(microtcp_sock_t *socket, uint8_t ack, uint8_t rst, uint8_t syn, uint8_t fin, int flags) {
    /* TODO: statistics */
    microtcp_header_t *peer_header_p;
    microtcp_header_t dummy_header = microtcp_header();
    ssize_t bytes_received;

    set_ack(&dummy_header, ack);
    set_rst(&dummy_header, rst);
    set_syn(&dummy_header, syn);
    set_fin(&dummy_header, fin);
    while(1) {
        if( (bytes_received = threshold_recv(socket, flags))== -1)
            return -1;

        peer_header_p = (microtcp_header_t *)socket->packet_buffer;
        if(bytes_received == sizeof(microtcp_header_t) && peer_header_p->control == dummy_header.control) {
            if(is_syn(peer_header_p))
                socket->ack_number = peer_header_p->seq_number + (uint32_t)bytes_received;
            else
                socket->ack_number += bytes_received;
            return bytes_received;
        } else {    /* Packet is not the requested one. Remove it from the buffer and revert changes in the socket */
            LOG_WARN("    Received different pack than expected. Packet Dropped. (Requested <control, packet_size>: <%u, %zu (header only)>"
                     ", Received <control, packet_size>: <%u, %u>)", dummy_header.control, sizeof(microtcp_header_t), peer_header_p->control, (uint32_t)bytes_received);
            socket->statistics->packets_received--;
            socket->statistics->bytes_received -= bytes_received;
        }
    }
}

static ssize_t threshold_sendto(int sd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
    ssize_t bytes_sent;

    do {
        bytes_sent = sendto(sd, buf, len, flags, dest_addr, addrlen);
        if(bytes_sent == -1)
            return -1;
    } while((uint32_t)bytes_sent < sizeof(microtcp_header_t));
    return bytes_sent;
}

static ssize_t threshold_send(microtcp_sock_t *socket, int flags) {
    microtcp_header_t* header;
    ssize_t bytes_sent;
    uint32_t data_len;
    assert(socket);

    /* Calculate checksum and change header bytes to Network Byte Order */
    header = (microtcp_header_t *)socket->packet_buffer;
    data_len = header->data_len;
    header->checksum = 0;
    header->checksum = crc32(socket->packet_buffer, (data_len + sizeof(microtcp_header_t)));
    hton_header(header);

    bytes_sent = threshold_sendto(socket->sd, socket->packet_buffer, (data_len + sizeof(microtcp_header_t)), flags,
                                  (struct sockaddr*)socket->peer_sin, sizeof(*socket->peer_sin));
    if(bytes_sent == -1)
        return -1;
    socket->seq_number += bytes_sent;
    socket->statistics->packets_send++;
    socket->statistics->bytes_send += bytes_sent;
    return bytes_sent;
}

static ssize_t send_header(microtcp_sock_t *socket, uint8_t ack, uint32_t ack_number, uint8_t rst, uint8_t syn, uint8_t fin, int flags) {
    microtcp_header_t *header = (microtcp_header_t *)socket->packet_buffer;
    ssize_t bytes_sent;
    assert(socket);

    *header = microtcp_header();
    /* Create the Header with the given parameters */
    set_ack(header, ack);
    set_rst(header, rst);
    set_syn(header, syn);
    set_fin(header, fin);
    if(is_ack(header)) {
        header->ack_number = ack_number;
        header->window = (uint16_t)cyclic_buffer_free_size(socket->recvbuf);
    }
    header->seq_number = (is_syn(header)) ? (rand() % UINT32_MAX/2) : (socket->seq_number);   /* Divided by 2 in order to avoid rare overflows */

    /* Convert to Network Byte Order and send */
    hton_header(header);
    if((bytes_sent = threshold_send(socket, flags)) == -1)
        return -1;
    assert(bytes_sent == sizeof(microtcp_header_t));

    /* Update socket */
    ntoh_header(header);
    if(is_ack(header))
        socket->ack_number = header->ack_number;
    socket->seq_number = header->seq_number + (uint32_t)bytes_sent;
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

static double get_time_diff(struct timespec const *end_time, struct timespec const *start_time) {
    assert(start_time && end_time);
    return (double)(end_time->tv_sec - start_time->tv_sec
    + (end_time->tv_nsec - start_time->tv_nsec) * 1e-9);
}