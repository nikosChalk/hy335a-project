

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
#include "../utils/utils.h"

#define DUPS 3

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
 * Also when the valid packet is received, bytes_received, packets_received and time measurements of socket->statistics are updated.
 *
 * In case that the packet's checksum is wrong 3 DUPs are sent. After that, it waits again for a packet.
 *
 * Note that the socket->ack_number is left unaffected.
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
 * of socket->statistics are updated.
 *
 * In addition to that, socket->ack_number is set to header->seq_number + bytes_received.
 * Also if the header is ACK, socket->peer_win_size is updated.
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
 * to the number of bytes returned. Also updates bytes_send, packets_send and time measurements of socket->statistics.
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
 *
 * Note that in error case, the socket is not changed, except for socket->packet_buffer.
 * @param socket The socket from which the data will be send. Must not be NULL.
 * @param ack The ack control bit. Same as set_ack()
 * @param ack_number If the ack is set to 0, then this field is ignored. Otherwise, if ack is set to 1, this field will be
 * used as the ack_number of the header to be send and will also update the socket->ack_number with this value.
 * @param rst The rst control bit. Same as set_rst()
 * @param syn The syn control bit. Same as set_syn(). If this bit is set to 1, then a random sequence number is chosen to be sent
 * and is also written in socket->seq_number
 * @param fin The fin control bit. Same as set_fin()
 * @param flags Same as threshold_send()
 * @return Bytes that were sent (== sizeof(microtcp_header_t) or -1 in case of error.
 */
static ssize_t send_header(microtcp_sock_t *socket, uint8_t ack, uint32_t ack_number, uint8_t rst, uint8_t syn, uint8_t fin, int flags);

/**
 * Attempts to send length bytes from buffer and waits for an ACK reply. socket->peer_sin is assumed to hold valid infromation.
 * After the send, the socket waits for a timeout interval for an ACK reply and retransmits the packet unless it has received the ACK
 * in that time period. Also receiving duplicate ACKs or corrupted packets (invalid checksum) causes retransmissions.
 *
 * In a successful send, socket->peer_win_size, socket->packet_buffer, socket->seq_number and socket->statisticsare changed.
 * If wait_for_ack is set to 1, then also socket->ack_number is updated.
 * In case of error only socket->packet_buffer is affected.
 *
 * After this call, if wait_for_ack is 1, socket->packet_buffer contains the last received ACK in HOST Byte order.
 * Otherwise it contains the packet sent in NETWORK Byte order.
 * @param socket The socket from which the data will be send. Must not be NULL.
 * @param buffer The buffer from which the data are to be sent
 * @param length How many bytes to send (payload). Must be <= MICROTCP_MSS
 * @param flags The flags of sendto()
 * @param wait_for_ack 1 if function should wait for ack, 0 if function should't wait.
 * @return The payload bytes that were send (<= length) or -1 in case of error.
 */
static ssize_t send_packet(microtcp_sock_t *socket, const void *buffer, size_t length, int flags, int wait_for_ack);

/**
 * Sends dups duplicate ACKs to the address that is specified by socket->peer_sin.
 * In a successful send, the socket->seq_number is increased by dups times sizeof(microtcp_header_t).
 * Also all dups duplicate ACKs have the same ack number.
 * Also bytes_sent, packets_sent of socket->statistics are updated.
 *
 * Note that this function uses packet->packet_buffer as the place where the header to be sent is stored. After the call, the
 * sent header is stored within socket->packet_buffer in HOST Byte Order.
 *
 * Note that in error case, the socket is not changed, except for socket->packet_buffer.
 * @param socket The socket from which the data will be send. Must not be NULL.
 * @param dups The number of duplicate ACKs to send. Must be > 0
 * @return Bytes that were sent (== dups*sizeof(microtcp_header_t)) or -1 in case of error.
 */
static ssize_t send_dups(microtcp_sock_t *socket, size_t dups);

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

/**
 * Sets the socket's option to timeout after micro_sec_timeout has elapsed when a recv() or recvfrom() is called
 * on that socket.
 * @param socket The socket whose options will change. Must not be NULL and socket->sd must be valid.
 * @param micro_sec_timeout The timeout interval in micro seconds. 0 disables the timeout option and the socket will receive
 * (block) until a packet arrives.
 * @return On success 0 is returned. Otherwise -1 is returned just as setsockopt().
 */
static int set_recv_timeout(microtcp_sock_t *socket, uint32_t micro_sec_timeout);

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
    new_socket.peer_win_size = 0;
    new_socket.recvbuf = NULL;
    new_socket.cwnd = MICROTCP_INIT_CWND;
    new_socket.ssthresh = MICROTCP_INIT_SSTHRESH;
    new_socket.seq_number = 0;
    new_socket.ack_number = 0;

    new_socket.peer_sin = NULL;
    new_socket.statistics = NULL;

    memset(new_socket.packet_buffer, 0, MICROTCP_MSS + sizeof(microtcp_header_t));
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

    /* Acquiring resources and sending SYN packet */
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

    if(socket->state == ESTABLISHED || socket->state == CLOSING_BY_PEER) {    /* User explicitly requests connection termination or FIN received */
        LOG_INFO("Connection termination requested...");

        /* Send FIN, ACK */
        LOG_INFO("Sending FIN ACK header...");
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

        if(socket->state == ESTABLISHED) { /* User explicitly requests connection termination */
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
    microtcp_header_t *const header = (microtcp_header_t *)socket->packet_buffer;
    ssize_t total_payload_sent, bytes_received;
    size_t payload_left, payload_to_send, chunk_payload;
    size_t chunk_count, ack_count, bytes_sent;
    size_t i, j;
    uint32_t previous_ack_number, init_seq_number;
    int duplicate_count, pos;
    void const *tmp_buffer_ptr;

    /* Used to determine how many DATA Bytes were sent when we receive an ACK that is not within expected_ack_nums */
    size_t total_log_elements = MAX(1, (length/MICROTCP_MSS));
    size_t valid_log_elements = 0;
    uint32_t *log_sent_seq_nums = malloc(sizeof(uint32_t)*total_log_elements);
    size_t *log_data_len_sent = malloc(sizeof(uint32_t)*total_log_elements);

    if(!socket) {
        LOG_ERROR("NULL socket passed");
        return -1;
    } else if(socket->state == CLOSING_BY_PEER) {
        LOG_WARN("Called microtcp_send() while socket's state is CLOSING_BY_PEER. Returning -1");
        return -1;
    } else if(socket->state != ESTABLISHED) {
        LOG_ERROR("Socket has invalid state");
        return -1;
    }

    payload_left = length;
    total_payload_sent = 0;
    while(payload_left>0) {
        payload_to_send = MIN3(payload_left, socket->cwnd, socket->peer_win_size);

        /* Determine how many chunks to send. */
        LOG_INFO("Sending %zu payload bytes in chunks:", payload_to_send);
        chunk_count = payload_to_send / MICROTCP_MSS;
        if(payload_to_send % MICROTCP_MSS != 0)
            chunk_count++;
        init_seq_number = socket->seq_number;
        tmp_buffer_ptr = buffer;

        /* Send the chunks and save the sent sequence numbers and the corresponding expected ack numbers */
        uint32_t sent_seq_nums[chunk_count];    /* sequence numbers with which chunks will be sent */
        uint32_t expected_ack_nums[chunk_count]; /* ack numbers with which the chunks will be acknowledged */
        for(i=0; i<chunk_count; i++) {
            chunk_payload = MIN2(payload_to_send, MICROTCP_MSS);
            sent_seq_nums[i] = socket->seq_number;

            if(send_packet(socket, tmp_buffer_ptr, chunk_payload, flags, 0) == -1) {
                LOG_ERROR("Failed to send packet.");
                perror(NULL);
                return (total_payload_sent>0) ? total_payload_sent : -1;
            }
            expected_ack_nums[i] = socket->seq_number;
            tmp_buffer_ptr = ((uint8_t const *)(tmp_buffer_ptr)) + chunk_payload;
            payload_to_send -= chunk_payload;

            /* Log the sending of packet with sequence number: sent_seq_nums[i] */
            /* Search if a packet with that sequence number was previously sent */
            j=0;
            while(j<valid_log_elements && log_sent_seq_nums[j] != sent_seq_nums[i]) /* Use linear search because overflow might occur */
                j++;
            if(j == valid_log_elements) { /* No packet with sent_seq_nums[i] was found.  */
                if(valid_log_elements == total_log_elements) { /* array is full. Double the size before insertion */
                    total_log_elements *= 2;
                    log_sent_seq_nums = realloc(log_sent_seq_nums, sizeof(*log_sent_seq_nums) * total_log_elements);
                    log_data_len_sent = realloc(log_data_len_sent, sizeof(*log_data_len_sent) * total_log_elements);
                }
                valid_log_elements++;
            }
            log_sent_seq_nums[j] = sent_seq_nums[i];
            log_data_len_sent[j] = chunk_payload;
        }

        /* Congestion avoidance */
        if(set_recv_timeout(socket, MICROTCP_ACK_TIMEOUT_US) < 0) {    /* Enable timeout */
            LOG_ERROR("  Call to setsockopt() failed while enabling timeout. Aborting ACK receive");
            perror(NULL);
            return (total_payload_sent>0) ? total_payload_sent : -1;
        }


        /* Start receiving ACKs */
        LOG_INFO("  Chunks sent. Start receiving ACKs...");
        uint8_t received_ack_flags[chunk_count];
        memset(received_ack_flags, 0, chunk_count*sizeof(*received_ack_flags));
        duplicate_count = 0;
        for(ack_count=0; ack_count<chunk_count && duplicate_count < DUPS;) {
            bytes_received = threshold_recv(socket, 0);
            if(bytes_received == -1) {  /* Timed out, or something went wrong */
                if(errno == EAGAIN || errno == EWOULDBLOCK) {   /* Timed out */
                    LOG_INFO("  Timed out while waiting for ACK");
                    socket->ssthresh = socket->cwnd/2 + 1;
                    socket->cwnd = MIN2(MICROTCP_MSS, socket->ssthresh);
                    break;
                }
                return -1;
            }

            if(is_fin(header)) {
                LOG_INFO("  FIN received while waiting for ACK reply to sent packet.");
                LOG_INFO("  Setting state to CLOSING_BY_PEER");
                socket->state = CLOSING_BY_PEER;

                if(set_recv_timeout(socket, 0) < 0) {    /* Disable timeout */
                    LOG_ERROR("  Call to setsockopt() failed while disabling timeout.");
                    perror(NULL);
                }
                if(send_header(socket, 1, (socket->ack_number+(uint32_t)bytes_received), 0, 0, 0, 0) == -1) {   /* Reply to FIN with ACK */
                    LOG_ERROR("Failed to send ACK header in response to FIN.");
                    perror(NULL);
                }
                return (total_payload_sent>0) ? total_payload_sent : -1;
            } else if(!is_ack(header)) {
                LOG_WARN("  Received packet was not ACK while expecting ACK packet. Packet dropped.");
                continue;
            }
            LOG_INFO("  ACK received with seq_number %u and ack_number %u", header->seq_number, header->ack_number);
            socket->ack_number = header->seq_number + (uint32_t)bytes_received;
            socket->peer_win_size = header->window;

            pos=0;
            while(pos<chunk_count && header->ack_number != expected_ack_nums[pos])
                pos++;
            if(pos == chunk_count) {    /* Received ACK was duplicate and peer did not receive even the first packet */
                previous_ack_number = init_seq_number;
                duplicate_count++;
                LOG_INFO("  ACK received was duplicate indicating peer did not receive the first packet. Current dup_count: %u", duplicate_count);
            } else if(ack_count == 0 || header->ack_number != previous_ack_number) {  /* first received ack. Cannot be duplicate. OR. non-duplicate, normal ACK received */
                LOG_INFO("  ACK received was normal one and not duplicate.");
                previous_ack_number = header->ack_number;
                received_ack_flags[pos] = 1;
                duplicate_count = 0;
                ack_count++;
            } else if (header->ack_number == previous_ack_number ) { /* received duplicate ACK */
                duplicate_count++;
                LOG_INFO("  ACK received was duplicate. Current dup_count: %u", duplicate_count);
            }
        }

        /* Find the last ack_number that we received */
        pos = -1;
        for(i=0; i<chunk_count; i++)
            if(received_ack_flags[i] == 1)
                pos = (int)i;

        /* Find the retransmission sequence number and store it in socket->seq_number */
        if(pos == -1) { /* Peer did not receive even the first chunk or we timed out a few times before receiving his ACKS */
            if(ack_count == 0 || header->ack_number == init_seq_number) { /* Peer did not receive even the first chunk */
                bytes_sent = 0;
                socket->seq_number = init_seq_number;
            } else {
                /* We timed out a few times. Hence our congestion window has dropped significantly and the received ack number */
                /* cannot exist within expected_ack_nums[] array since it is an ack_number greater than the values within the array */
                /* No retansmission should occur */

                /* Search the packet to which this ack_number belongs and calculate the payload which was not acknowledged */
                bytes_sent = 0;
                for(j=0; log_sent_seq_nums[j] != header->ack_number; j++)
                    bytes_sent += log_data_len_sent[j];
                assert(j<=valid_log_elements);
                socket->seq_number = header->ack_number;

                /* Since such an ACK was received, we can safely delete elements with index < j */
                valid_log_elements = valid_log_elements - j;
                total_log_elements = valid_log_elements*2;
                memmove(log_sent_seq_nums, (log_sent_seq_nums + j), (sizeof(*log_sent_seq_nums) * valid_log_elements));
                memmove(log_data_len_sent, (log_data_len_sent + j), (sizeof(*log_data_len_sent) * valid_log_elements));
                log_sent_seq_nums = realloc(log_sent_seq_nums, sizeof(*log_sent_seq_nums) * total_log_elements);
                log_data_len_sent = realloc(log_data_len_sent, sizeof(*log_data_len_sent) * total_log_elements);
            }
        } else if (expected_ack_nums[pos] != socket->seq_number) {  /* peer received some chunks */
            assert(pos < chunk_count);
            bytes_sent = sent_seq_nums[pos+1]-init_seq_number-(pos+1)*sizeof(microtcp_header_t);
            socket->seq_number = sent_seq_nums[pos+1];
        } else {    /* Peer received all chunks */
            /* No retransmission */
            bytes_sent = socket->seq_number-init_seq_number-chunk_count*sizeof(microtcp_header_t);
        }
        payload_left -= bytes_sent;
        total_payload_sent += bytes_sent;
        buffer = ((uint8_t const *)(buffer)) + bytes_sent;

        if(duplicate_count == 3){
            socket->ssthresh = socket->cwnd/2 + 1;
            socket->cwnd = socket->cwnd/2 + 1;
        }

        /* Restore socket to non-time out mode */
        if(set_recv_timeout(socket, 0) < 0) {    /* Disable timeout */
            LOG_ERROR("  Call to setsockopt() failed while disabling timeout.");
            perror(NULL);
            return (total_payload_sent>0) ? total_payload_sent : -1;
        }

        /* Peer's buffer might be filled up. Probe him until we get a positive window. */
        while(socket->peer_win_size == 0 && payload_left>0) {
            LOG_INFO("  Probing until we receive positive window...");
            if(usleep((uint32_t)rand() % (MICROTCP_ACK_TIMEOUT_US+1)) == -1){
                LOG_ERROR("  Failed to sleep when attempting to probe due to empty window");
                perror(NULL);
                break;
            }
            if(send_packet(socket, NULL, 0, flags, 1) == -1) {
                LOG_ERROR("  Error while probing for empty window.");
                perror(NULL);
                break;
            }
        }
    }

    return total_payload_sent;
}

ssize_t microtcp_recv (microtcp_sock_t *socket, void *buffer, size_t length, int flags) {
    microtcp_header_t * const header = (microtcp_header_t *) socket->packet_buffer;
    void * const data_pointer = socket->packet_buffer + sizeof(microtcp_header_t);

    ssize_t bytes_received, bytes_sent;
    int is_fin_header, is_ack_header, is_out_of_order;

    if(!socket) {
        LOG_ERROR("NULL socket passed");
        return -1;
    } else if(socket->state == CLOSING_BY_PEER) {
        LOG_INFO("microtcp_recv called when socket's state is CLOSING_BY_PEER");

        if(!cyclic_buffer_is_empty(socket->recvbuf) && length>0) {
            LOG_INFO("  Internal buffer still has data to satisfy user's demands. Returning those...");
                return cyclic_buffer_pop(socket->recvbuf, buffer, MIN2(length, cyclic_buffer_cur_size(socket->recvbuf)));
        } else {
            LOG_INFO("  Internal buffer is empty. Returning -1");
            return -1;
        }
    } else if(socket->state != ESTABLISHED) {
        LOG_ERROR("Socket has invalid state");
        return -1;
    }

    /* While buffer can hold more data and we have not satisfied the user, keep receiving. */
    while((!cyclic_buffer_is_full(socket->recvbuf)) && (cyclic_buffer_cur_size(socket->recvbuf) < length)) {

        /* In case that we have some data available, wait up to 0.6 secs for more data. */
        if(!cyclic_buffer_is_empty(socket->recvbuf)) {
            if(set_recv_timeout(socket, 600000) < 0) {    /* Enable timeout */
                LOG_ERROR("  Call to setsockopt() failed while enabling timeout.");
                perror(NULL);
            }
        }

        /* Wait for packet and drop out of order ones or dangling ACKs. */
        do {
            LOG_INFO("Waiting for packet...");
            bytes_received = threshold_recv(socket, flags);
            if (bytes_received == -1) {

                if ((errno == EAGAIN || errno == EWOULDBLOCK)) {    /* Timed out. Returning already gathered data to user */
                    LOG_INFO("   Timed out while waiting for packet and we already have data in internal buffer. Returning those...");
                    if(set_recv_timeout(socket, 0) < 0) {    /* Disable timeout */
                        LOG_ERROR("  Call to setsockopt() failed while disabling timeout.");
                        perror(NULL);
                        return -1;
                    }
                    return cyclic_buffer_pop(socket->recvbuf, buffer, MIN2(length, cyclic_buffer_cur_size(socket->recvbuf)) );

                } else {    /* Error while receiving data */
                    LOG_ERROR("Waiting for packet failed:");
                    perror(NULL);
                    return -1;
                }
            }

            LOG_INFO("Packet received with seq_number %u", header->seq_number);
            is_ack_header = is_ack(header);
            is_fin_header = is_fin(header);
            is_out_of_order = (header->seq_number != socket->ack_number);
            if (is_ack_header && !is_fin_header) {
                LOG_INFO("    Packet received was a dangling ACK or sender failed the CRC checksum when receiving 3 DUPs. Packet ignored.");
            } else if (!is_ack_header && is_out_of_order) {    /* Check if received packet is out of order. */
                LOG_WARN("    Packet dropped. Received packet with seq_number %u, while expecting %u. Sending %u DUPs...", header->seq_number, socket->ack_number, DUPS);
                if (send_dups(socket, DUPS) == -1)
                    LOG_WARN("    Could not send DUPs.");
                else
                    LOG_INFO("    All DUPs successfully sent with ack_number %u. Current seq_number %u", socket->ack_number, socket->seq_number);
            }
        } while (is_out_of_order || (is_ack_header && !is_fin_header));

        if(set_recv_timeout(socket, 0) < 0) {    /* Disable timeout */
            LOG_ERROR("  Call to setsockopt() failed while disabling timeout.");
            perror(NULL);
            return -1;
        }

        /* Copy received data to recvbuf */
        cyclic_buffer_resize(socket->recvbuf, MICROTCP_MSS);
        cyclic_buffer_append(socket->recvbuf, data_pointer, (bytes_received-sizeof(microtcp_header_t)));

        /* Send ACK */
        bytes_sent = send_header(socket, 1, (socket->ack_number+(uint32_t)bytes_received), 0, 0, 0, 0);
        if(bytes_sent == -1) {
            LOG_ERROR("Failed to send ACK header in response to FIN.");
            perror(NULL);
            return -1;
        }
        LOG_INFO("ACK packet sent with seq_number %u and ack_number %u", header->seq_number, header->ack_number);

        /* Check if the packet received is FIN */
        if(is_fin_header) {
            /* Shutting down connection */
            LOG_INFO("    Packet received with seq_num %u was FIN.", (socket->ack_number-(uint32_t)bytes_sent));
            LOG_INFO("    State set to: CLOSING_BY_PEER");
            socket->state = CLOSING_BY_PEER;
            if(!cyclic_buffer_is_empty(socket->recvbuf) && length>0) {
                LOG_INFO("    Internal buffer still has data to satisfy user's demands. Returning those...");
                return cyclic_buffer_pop(socket->recvbuf, buffer, MIN2(length, cyclic_buffer_cur_size(socket->recvbuf)));
            } else {
                LOG_INFO("    Internal buffer is empty. Returning -1");
                return -1;
            }
        }
    }

    /* Return data to user */
    return cyclic_buffer_pop(socket->recvbuf, buffer, MIN2(length, cyclic_buffer_cur_size(socket->recvbuf)) );
}

static void acquire_sock_resources(microtcp_sock_t *socket) {
    assert(socket);
    socket->recvbuf = cyclic_buffer_make(MICROTCP_RECVBUF_LEN);
    socket->init_win_size = (uint16_t)cyclic_buffer_free_size(socket->recvbuf);

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

/**
 * Sets the socket's option to timeout after micro_sec_timeout has elapsed when a recv() or recvfrom() is called
 * on that socket.
 * @param socket The socket whose options will change. Must not be NULL and socket->sd must be valid.
 * @param micro_sec_timeout The timeout interval in micro seconds. 0 disables the timeout option and the socket will receive
 * (block) until a packet arrives.
 * @return On success 0 is returned. Otherwise -1 is returned just as setsockopt().
 */
static int set_recv_timeout(microtcp_sock_t *socket, uint32_t micro_sec_timeout) {
    struct timeval timeout;
    assert(socket);

    /* Set the timeout interval struct */
    timeout.tv_sec = 0;
    timeout.tv_usec = micro_sec_timeout;

    return setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
}

static void display_statistics(microtcp_sock_statistics_t *sock_statistics) {
    if(sock_statistics->tx_max_inter == -1) /* Field has its initial value. No more than 1 data packet was sent. */
        sock_statistics->tx_min_inter = sock_statistics->tx_max_inter = 0;

    if(sock_statistics->rx_max_inter == -1) /* Field has its initial value. No more than 1 data packet was received. */
        sock_statistics->rx_min_inter = sock_statistics->rx_max_inter = 0;

    sock_statistics->rx_mean_inter /= sock_statistics->packets_received;
    sock_statistics->rx_std_inter /= sock_statistics->packets_received;
    sock_statistics->rx_std_inter = sock_statistics->rx_std_inter - (sock_statistics->rx_mean_inter * sock_statistics->rx_mean_inter);

    sock_statistics->tx_mean_inter /= sock_statistics->packets_send;
    sock_statistics->tx_std_inter /= sock_statistics->packets_send;
    sock_statistics->tx_std_inter = sock_statistics->tx_std_inter - (sock_statistics->tx_mean_inter * sock_statistics->tx_mean_inter);


    printf("Packets received \t: %" PRIu64 "\n", sock_statistics->packets_received);
    printf("Packets sent \t\t: %" PRIu64 "\n", sock_statistics->packets_send);
    printf("Packets lost \t\t: %" PRIu64 "\n", sock_statistics->packets_lost);
    printf("Packet lost ratio \t: %.6lf %%\n", ((sock_statistics->packets_lost*100)/((double)sock_statistics->packets_received)));
    printf("Packet inter-arrival RX\n");
    printf("Min \t\t\t: %.6lf\n", sock_statistics->rx_min_inter);
    printf("Max \t\t\t: %.6lf\n", sock_statistics->rx_max_inter);
    printf("Mean \t\t\t: %.6lf\n", sock_statistics->rx_mean_inter);
    printf("Std^2 (Variance)\t: %.6lf\n", sock_statistics->rx_std_inter);
    printf("Packet inter-arrival TX\n");
    printf("Min \t\t\t: %.6lf\n", sock_statistics->tx_min_inter);
    printf("Max \t\t\t: %.6lf\n", sock_statistics->tx_max_inter);
    printf("Mean \t\t\t: %.6lf\n", sock_statistics->tx_mean_inter);
    printf("Std^2 (Variance)\t: %.6lf\n", sock_statistics->tx_std_inter);
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
    static struct timespec last_call_time;
    static struct timespec cur_call_time;
    static int isFirstCall = 1;
    double time_diff;

    struct sockaddr_in remote_addr;
    socklen_t remote_addr_len = sizeof(remote_addr);

    microtcp_header_t *header;
    uint32_t received_checksum;
    ssize_t bytes_received;
    int is_checksum_ok;
    assert(socket);

    header = (microtcp_header_t *)socket->packet_buffer;
    is_checksum_ok = 0; /* False */
    do {
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
            continue;   /* Jumps to EVALUATION of while's condition */
        }

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
            socket->statistics->rx_std_inter += time_diff*time_diff;

            memcpy(&last_call_time, &cur_call_time, sizeof(cur_call_time));
        }

        /* Check its checksum */
        ntoh_header(header);

        received_checksum = header->checksum;
        header->checksum = 0;
        header->checksum = crc32(socket->packet_buffer, (sizeof(microtcp_header_t) + header->data_len));
        is_checksum_ok = (received_checksum == header->checksum);
        if(!is_checksum_ok) {
            LOG_WARN("    Received packet with wrong checksum. Sending %u DUPs...", DUPS);
            if(send_dups(socket, DUPS) == -1)
                LOG_WARN("    Could not send DUPs.");
            else
                LOG_INFO("    All DUPs successfully sent with seq_number %u and ack_number %u", header->seq_number, header->ack_number);
        }
    } while(!is_checksum_ok);

    socket->statistics->packets_received++;
    socket->statistics->bytes_received += bytes_received;
    return bytes_received;
}

static ssize_t recv_header(microtcp_sock_t *socket, uint8_t ack, uint8_t rst, uint8_t syn, uint8_t fin, int flags) {
    /* TODO: statistics */
    microtcp_header_t *received_header;
    microtcp_header_t dummy_header = microtcp_header();
    ssize_t bytes_received;

    set_ack(&dummy_header, ack);
    set_rst(&dummy_header, rst);
    set_syn(&dummy_header, syn);
    set_fin(&dummy_header, fin);
    received_header = (microtcp_header_t *)socket->packet_buffer;
    while(1) {
        if( (bytes_received = threshold_recv(socket, flags))== -1)
            return -1;

        if(bytes_received == sizeof(microtcp_header_t) && received_header->control == dummy_header.control) {
            socket->ack_number = received_header->seq_number + (uint32_t)bytes_received;

            if(is_ack(received_header))
                socket->peer_win_size = received_header->window;
            return bytes_received;
        } else {    /* Packet is not the requested one. Remove it from the buffer and revert changes in the socket */
            LOG_WARN("    Received different pack than expected. Packet Dropped. (Requested <control, packet_size>: <%u, %zu (header only)>"
                     ", Received <control, packet_size>: <%u, %u>)", dummy_header.control, sizeof(microtcp_header_t), received_header->control, (uint32_t)bytes_received);
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
    static struct timespec last_call_time;
    static struct timespec cur_call_time;
    static int isFirstCall = 1;
    double time_diff;

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
        socket->statistics->tx_std_inter += time_diff*time_diff;

        memcpy(&last_call_time, &cur_call_time, sizeof(cur_call_time));
    }

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

static ssize_t send_packet(microtcp_sock_t *socket, const void *buffer, size_t length, int flags, int wait_for_ack) {
    microtcp_header_t *header = (microtcp_header_t*)socket->packet_buffer;
    ssize_t bytes_sent, bytes_received;
    size_t dup_count;
    uint32_t init_seq_number;
    int retransmit = 0;  /* Boolean in order to check if retransmission is needed */
    int packet_acknowledged;
    assert(socket && length<=MICROTCP_MSS && (wait_for_ack == 0 || wait_for_ack == 1));

    /* Copy data */
    memcpy(socket->packet_buffer + sizeof(microtcp_header_t), buffer, length);

    /* Set ack timeout option in case we are expecting one. */
    if(wait_for_ack) {
        if(set_recv_timeout(socket, MICROTCP_ACK_TIMEOUT_US) < 0) {    /* Enable timeout */
            LOG_ERROR("  Call to setsockopt() failed while enabling timeout. Aborting ACK receive");
            perror(NULL);
            return -1;
        }
    }

    /* Start sending */
    init_seq_number = socket->seq_number;
    do {
        retransmit = 0;
        /* Create header */
        *header = microtcp_header();
        header->seq_number = socket->seq_number;
        header->data_len = (uint32_t)length;

        /* Send header + data */
        LOG_INFO("  Sending total %zu bytes with seq_number %u, of which %zu are payload", (length + sizeof(microtcp_header_t)), header->seq_number, length);
        bytes_sent = threshold_send(socket, flags);
        if (bytes_sent == -1) {
            LOG_ERROR("  Error while sending packet with seq_number %u", header->seq_number);
            perror(NULL);
            return -1;
        }

        if(wait_for_ack == 1) { /* check if should wait for ACK */
            dup_count = 0;
            packet_acknowledged = 0;
            do {
                /* Receive ACK and drop other packets */
                LOG_INFO("  Waiting for ACK...");
                bytes_received = recv_header(socket, 1, 0, 0, 0, 0);    /* Receiving anything else than header can destroy the data copied */
                if(bytes_received == -1) { /* Timed out, or something went wrong */
                    retransmit = (errno == EAGAIN || errno == EWOULDBLOCK); /* Time out */
                    if (!retransmit) {
                        LOG_ERROR("  Error while receiving ACK");
                        perror(NULL);
                        return -1;
                    } else {
                        LOG_INFO("  Waiting for ACK timed out. Retransmitting...");
                    }
                } else { /* ACK received. Check it */
                    if(header->ack_number == init_seq_number)
                        dup_count++;
                    else if(header->ack_number == socket->seq_number)
                        packet_acknowledged = 1;
                    LOG_INFO("  Received ACK with ack_number %u while expecting %u. Retransmitting...", header->ack_number, socket->seq_number);
                }
            } while((dup_count>0 && dup_count <3) && (!packet_acknowledged) && (!retransmit));
            if(dup_count == 3)
                retransmit = 1;

            if(retransmit) {
                socket->seq_number = init_seq_number;   /* We will re-send the same packet. The re-transmitted packet must have the same seq_number. */
                socket->statistics->packets_lost++;
                socket->statistics->bytes_lost += bytes_sent;
            } else {
                socket->ack_number = header->seq_number + (uint32_t) bytes_received;    /* We explicitly change this, since we might have missed a few ACKs */
                LOG_INFO("  ACK received with seq_number %u and ack_number %u", header->seq_number, header->ack_number);
            }
        }
     } while(retransmit && wait_for_ack);

    /* Restore socket to non-time out mode */
    if(wait_for_ack) {
        if(set_recv_timeout(socket, 0) < 0) {    /* Disable timeout */
            LOG_ERROR("  Call to setsockopt() failed while disabling timeout.");
            perror(NULL);
            return -1;
        }
    }

    return bytes_sent-sizeof(microtcp_header_t);    /* It is always guaranteed that at least sizeof(microtcp_header_t) will be sent */
}

static ssize_t send_dups(microtcp_sock_t *socket, size_t dups) {
    ssize_t cur_bytes_sent, total_bytes_sent;
    size_t i;
    assert(socket && dups>0);

    for(i=0, total_bytes_sent=0; i<dups; i++) {
        if((cur_bytes_sent = send_header(socket, 1, socket->ack_number, 0, 0, 0, 0)) == -1)
            return -1;
        total_bytes_sent += cur_bytes_sent;
    }

    return total_bytes_sent;
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