

#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include "microtcp.h"
#include "bits.h"
#include "../utils/crc32.h"
#include "../utils/log.h"

#define MIN(X,Y) (((X) < (Y)) ? (X) : (Y))

/****************************************************************/
/********************* FORWARD DECLARATIONS *********************/
/****************************************************************/

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
 * Returns a pointer within socket->recvbuf which points to the 1st byte of the last packet received with packet size bytes_received.
 * Note that this function should only be called after a call to either threshold_recv() or recv_header()
 * @param socket The socket which contains the buffer for storing received packets. Must not be NULL.
 * @param bytes_received The packet's total size in bytes
 * @return Pointer within socket->recvbuf which points to the 1st byte of the received packet
 */
static void* get_last_packet_ptr(const microtcp_sock_t *socket, size_t bytes_received);

/**
 * Same as "man 2 recvfrom", except that any packet attempted to be received, and x bytes were successfully received
 * through rcvfrom(), with x < sizeof(microtcp_header_t) and x != -1, it is automatically dropped.
 */
static ssize_t threshold_recvfrom(int sd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);

/**
 * This function blocks until a packet is received from an address same as socket->peer_sin. Packets not from that address
 * are dropped and never stored.
 * Once a packet from that address has been received (valid packet), it is stored within socket->recvbuf and socket->buff_fill_level is
 * updated. The packet's header will be stored in HOST Byte Order, while the packet's payload (data) will be
 * stored in NETWORK Byte Order. Also when the valid packet is received, bytes_received and packets_received
 * of socket->statistics are updated. Note that the socket->peer_seq_number is left unaffected.
 * No ACK is send back to the sender.
 * It is guaranteed that at least sizeof(microtcp_header_t) data will be received in case of no error.
 * In error case, the socket is not changed.
 * @param socket The socket from which the data will be received. Must not be NULL and socket->peer_sin is assumed hold
 * valid information.
 * @param flags Same as "man 2 recvfrom"
 * @return Bytes that were received (>= sizeof(microtcp_header_t)) or -1 in error case.
 */
static ssize_t threshold_recv(microtcp_sock_t *socket, int flags);

/**
 * This function blocks until a packet is received from an address same as socket->peer_sin. The packet must
 * also be only a header with no data and its control field must match the given control field. Packets not satisfying
 * these constraints are never stored and are always dropped without altering socket's fields.
 * Once valid header has been received, it is stored within socket->recvbuf and socket->buff_fill_level is
 * updated. The header will be stored in HOST Byte Order. Also when the valid packet is received, bytes_received and packets_received
 * of socket->statistics are updated.
 * Note that the socket->peer_seq_number are left unaffected.
 * It is guaranteed that at least sizeof(microtcp_header_t) data will be received in case of no error.
 * In error case, the socket is not changed.
 * @param socket The socket which waits for a specific header packet to be received. Must not be NULL and socket->peer_sin is assumed hold
 * valid information. The header received will be stored within socket->recvbuf in HOST Byte order
 * and socket->buff_fill_level will be updated. (+= header_size)
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
 * This function sends a packet with the given header and the given data_buffer to the address defined by socket->peer_sin.
 * It is guaranteed that at least sizeof(microtcp_header_t) data will be sent in case of no error. Note that in
 * error case, the socket is not changed.
 * In a successful send, the socket->seq_number is updated with the number of bytes that were sent, which are equal
 * to the number of bytes returned. Also updates bytes_send, and packets_send of socket->statistics.
 * Note that after the packet is sent, the function does not wait for an ACK reply and simply returns.
 * @param socket The socket from which the data will be sent. Must not be NULL and socket->peer_sin is assumed hold
 * valid information.
 * @param header The header which will be send. Must be in HOST Byte Order. Must not be NULL.
 * @param data_buffer The packet's payload. Must be in NETWORK Byte Order. Must not be NULL.
 * @param data_length The data_buffer's length in bytes. Must be less than MICROTCP_MSS and > 0.
 * Fragmentation should be taken care of by the caller.
 * @param flags Same as "man 2 sendto"
 * @return Bytes that were sent (>= sizeof(microtcp_header_t) or -1 in case of error.
 */
static ssize_t threshold_send(microtcp_sock_t *socket, microtcp_header_t const *header, const void *data_buffer, size_t data_length, int flags);

/**
 * Sends a header with the given control fields to the address that is specified by socket->peer_sin.
 * If the send is successful, socket->seq_number is updated with the correct value and bytes_sent, packets_sent of socket->statistics
 * are also updated. In case of error, the socket is not changed.
 * Note that this function does not wait for an ACK packet to be received as a reply, it simply returns after sending the header.
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
 * Releases any dynamically allocated resources that this socket has aquired. Note that this function assumes that
 * socket has already aquired valid resources. Also sets the state of this socket to INVALID.
 * @param socket The socket whose resources will be released. Must not be NULL.
 */
static void release_sock_resources(microtcp_sock_t *socket);

/**
 * Acquires dynamic resources that this socket needs. Note that this function assumes that the socket does not already
 * own any resources in order to avoid memory leaks. The state of the socket is unaffected.
 * @param socket The socket whose resources will be acquired. Must not be NULL.
 */
static void acquire_sock_resources(microtcp_sock_t *socket);

/**
 * Displays the statistics of this socket from the point when a peer was connected to it, until now.
 * Statistics are dumped in stdout
 * @param socket The socket whose statistics will be displayed. Must not be NULL and socket->statistics must hold valid
 * information.
 */
static void display_statistics(microtcp_sock_t const *socket);

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
    new_socket.buf_length = MICROTCP_RECVBUF_LEN;
    new_socket.buf_fill_level = 0;
    new_socket.cwnd = 0;
    new_socket.ssthresh = 0;
    new_socket.seq_number = 0;
    new_socket.ack_number = 0;
    new_socket.peer_seq_number = 0;

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
    memcpy(socket->peer_sin, (struct sockaddr_in *)address, address_len);           /* TODO: /******* EXPECT BUUUUGS???? *******/

    /* Sending SYN packet*/
    LOG_INFO("Attempting connection to IP address \"%s\" in port %u", inet_ntoa(socket->peer_sin->sin_addr), ntohs(socket->peer_sin->sin_port));
    LOG_INFO("Sending SYN packet...");
    if (send_header(socket, 0, 0, 0, 1, 0, 0) == -1) {
        LOG_ERROR("Failed to dispatch SYN packet. Aborting connection to remote host.");
        perror(NULL);
        release_sock_resources(socket);
        return -1;
    }
    LOG_INFO("SYN packet sent with sequence number: %u.", socket->seq_number);

    /* Waiting for SYN ACK packet... */
    LOG_INFO("Waiting for SYN ACK packet...");
    if((bytes_received = recv_header(socket, 1, 0, 1, 0, 0)) == -1) {
        LOG_ERROR("Error while receiving SYN ACK header. Connection aborted");
        perror(NULL);
        release_sock_resources(socket);
        return -1;
    }
    peer_header = get_last_packet_ptr(socket, (size_t)bytes_received);
    socket->peer_seq_number = peer_header->seq_number;
    socket->buf_fill_level -= bytes_received;
    LOG_INFO("SYN ACK packet received with sequence number %u and ack number ...", socket->peer_seq_number); /*TODO: print ack number */

    /* Sending ACK packet */
    LOG_INFO("Sending ACK packet with ACK number ..."); /* TODO: fill ACK number */
    if((send_header(socket, 1, (socket->peer_seq_number+(uint32_t )bytes_received), 0, 0, 0, 0)) == -1) {  /* Not a critical issue. The (server) user will call microtcp_rcv() which will re-dispatch this ACK */
        LOG_WARN("Failed to send ACK packet during 3-way handshake.");
        perror(NULL);
    }

    LOG_INFO("Connection successfully established!");
    socket->state = ESTABLISHED;
    return 0;
}

int microtcp_accept (microtcp_sock_t *socket, struct sockaddr *address, socklen_t address_len) {
    microtcp_header_t *peer_header;
    ssize_t bytes_received;

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
        bytes_received = threshold_recvfrom(socket->sd, socket->recvbuf, socket->buf_length, 0, address, &address_len); /* Blocking */
        if (bytes_received == -1) {
            LOG_ERROR("Waiting for connection failed:");
            perror(NULL);
            release_sock_resources(socket);
            return -1;
        }

        peer_header = (microtcp_header_t *)socket->recvbuf;
        ntoh_header(peer_header);    /* Header was travelling in the Network, therefore he is in Network Byte Order */
        if(!is_syn(peer_header)) {
            LOG_WARN("Someone attempted a connection without SYN control field. Connection Refused.");
            continue;
        }
        /* TODO: checksum */
        break;
    }
    socket->buf_fill_level += bytes_received;
    if(address != (struct sockaddr*)socket->peer_sin)   /* PASSED address is not NULL. Copy peer's info to socket->peer_sin */
        memcpy(socket->peer_sin, address, address_len);

    /*The peer_header is fine: contains seq of peer and it is a SYN packet. */
    socket->peer_seq_number = peer_header->seq_number;
    socket->buf_fill_level = 0;         /* Empty buffer. Its information is no longer needed */

    LOG_INFO("Received incoming SYN packet from IP \"%s\" and port %u. Sequence number received: %u",
             inet_ntoa(socket->peer_sin->sin_addr), ntohs(socket->peer_sin->sin_port), peer_header->seq_number);

    /* Sending SYN, ACK packet to peer */
    LOG_INFO("Replying with SYN, ACK...");
    if(send_header(socket, 1, (socket->peer_seq_number + (uint32_t)bytes_received), 0, 1, 0, 0) == -1) {
        LOG_ERROR("Attempted to send SYN, ACK but failed:");
        perror(NULL);
        release_sock_resources(socket);
        return -1;
    }
    LOG_INFO("SYN ACK packet sent with seq_number %u and ack_number ...", socket->seq_number); /* TODO: add ack number */

    /* Waiting for ACK packet */
    LOG_INFO("Waiting ACK packet...");
    if((bytes_received = recv_header(socket, 1, 0, 0, 0, 0)) == -1) {
        LOG_ERROR("Error while receiving ACK packet:");
        perror(NULL);
        release_sock_resources(socket);
        return -1;
    }
    peer_header = get_last_packet_ptr(socket, (size_t)bytes_received);
    LOG_INFO("ACK packet received with seq_number %u and ack_number ...", peer_header->seq_number);    /* TODO: add ack number */
    if(socket->peer_seq_number+bytes_received != peer_header->seq_number) {
        /* TODO: ... */
    }
    socket->peer_seq_number = peer_header->seq_number;

    /* TODO: check received ack number */
    socket->state = ESTABLISHED;
    socket->buf_fill_level= 0;

    LOG_INFO("Connection successfully established!");
    return 0;
}

int microtcp_shutdown (microtcp_sock_t *socket, int how) {
    microtcp_header_t *peer_header;
    ssize_t bytes_received, bytes_sent;

    if(socket->state == ESTABLISHED) {    /* User explicitly requests connection termination */
        LOG_INFO("Connection termination requested by host...");

        /* Send FIN, ACK */
        LOG_INFO("Sending FIN, ACK header...");
        if(send_header(socket, 1, 0, 0, 0, 1, 0) == -1) {
            LOG_ERROR("Error while sending FIN ACK. Shutdown failed.");
            perror(NULL);
            return -1;
        }
        LOG_INFO("FIN, ACK header sent with seq_number %u", socket->seq_number);

        /* Waiting for ACK */
        LOG_INFO("Waiting for ACK...");
        if((bytes_received = recv_header(socket, 1, 0, 0, 0, 0)) == -1) {
            LOG_ERROR("Error while waiting for ACK. Shutdown failed.");
            perror(NULL);
            return -1;
        }
        peer_header = get_last_packet_ptr(socket, (size_t)bytes_received);
        socket->peer_seq_number = peer_header->seq_number;   /* TODO: Do not ignore packet losses? */
        socket->buf_fill_level -= bytes_received;
        socket->state = CLOSING_BY_HOST;
        LOG_INFO("ACK packet received with seq_number %u and ack_number ...", socket->seq_number);    /* TODO: ACK number */

        /* Waiting for FIN ACK */
        LOG_INFO("Waiting for FIN ACK...");
        if((bytes_received = recv_header(socket, 1, 0, 0, 1, 0)) == -1) {
            LOG_ERROR("Error while receiving FIN ACK packet. Connection terminated forcefully.");
            perror(NULL);
            /* TODO: release sock resources. Display statistics */
            return -1;
        }
        peer_header = get_last_packet_ptr(socket, (size_t)bytes_received);
        socket->peer_seq_number = peer_header->seq_number;   /* TODO: Do not ignore packet losses? */
        socket->buf_fill_level -= bytes_received;
        LOG_INFO("FIN ACK packet received with seq_number %u and ack_number ... ", );    /* TODO: ACK number */

        /* Sending ACK */
        if(send_header(socket, 1, 0, 0, 0, 0, 0) == -1) {
            LOG_ERROR("Error sending ACK. Connection terminated forcefully.");
            perror(NULL);
            /* TODO: release sock resources. Display statistics */
            return -1;
        }
        LOG_INFO("ACK packet sent with seq_number %u and ack_number ...", socket->seq_number);    /* TODO: ACK number */

        LOG_INFO("Connection successfully terminated");
        LOG_INFO("Statistics:");
        display_statistics(socket);

        release_sock_resources(socket);
        shutdown(socket->sd, SHUT_RDWR);
        close(socket->sd);
        socket->state = CLOSED;
        return 0;

    } else if(socket->state == CLOSING_BY_PEER) {
        /* Sending FIN, ACK */
        LOG_INFO("Sending FIN, ACK header...");
        if(send_header(socket, 1, 0, 0, 0, 1, 0) == -1) {
            LOG_ERROR("Error while sending FIN ACK. Shutdown failed.");
            perror(NULL);
            return -1;
        }
        LOG_INFO("FIN, ACK header sent with seq_number %u", socket->seq_number);

        /* Waiting for ACK */
        LOG_INFO("Waiting for ACK...");
        if((bytes_received = recv_header(socket, 1, 0, 0, 0, 0)) == -1) {
            LOG_ERROR("Error while waiting for ACK. Shutdown failed.");
            perror(NULL);
            return -1;
        }
        peer_header = get_last_packet_ptr(socket, (size_t)bytes_received);
        socket->peer_seq_number = peer_header->seq_number;   /* TODO: Do not ignore packet losses? */
        socket->buf_fill_level -= bytes_received;
        LOG_INFO("ACK packet received with seq_number %u and ack_number ...", socket->seq_number);    /* TODO: ACK number */

        LOG_INFO("Connection successfully terminated");
        LOG_INFO("Statistics:");
        display_statistics(socket);

        release_sock_resources(socket);
        shutdown(socket->sd, SHUT_RDWR);
        close(socket->sd);
        socket->state = CLOSED;
        return 0;
    }
    /* TODO... */
}

ssize_t microtcp_send (microtcp_sock_t *socket, const void *buffer, size_t length, int flags) {
    microtcp_header_t header = microtcp_header();
    ssize_t bytes_sent;

    if(!socket) {
        LOG_ERROR("NULL socket passed");
        return -1;
    } else if(socket->state != ESTABLISHED) {
        LOG_ERROR("Socket has invalid state");
        return -1;
    }

    if(length > MICROTCP_MSS) {
        LOG_INFO("User requested %zu bytes to be send. Max payload is %d. %u bytes discarded.", length, MICROTCP_MSS, (MICROTCP_MSS-length));
        length = MICROTCP_MSS;
    }

    /* Create Header */
    header.seq_number = socket->seq_number + sizeof(microtcp_header_t) + length;
    header.data_len = (uint32_t)length;
    /* TODO: header.checksum = ... */

    /* Send header + data */
    LOG_INFO("Sending total %zu bytes with seq_number %u, of whcih %u are user bytes", (length + sizeof(microtcp_header_t)), header.seq_number, length);
    bytes_sent = threshold_send(socket, &header, buffer, length, flags);
    if(bytes_sent == -1) {
        LOG_ERROR("Error while sending packet with seq_number %u",header.seq_number);
        perror(NULL);
        return -1;
    }

    /* TODO: checksum? */
    /* TODO: receive ACK */
    /* TODO: retransmit if ACK has not been received */
    return bytes_sent;
}

ssize_t microtcp_recv (microtcp_sock_t *socket, void *buffer, size_t length, int flags) {
    ssize_t bytes_received;
    microtcp_header_t *header_pointer;
    int is_fin_header;
    void *data_pointer;

    LOG_INFO("Waiting for packet...");
    bytes_received = threshold_recv(socket,flags);
    if(bytes_received == -1){
        LOG_ERROR("Waiting for packet failed:");
        perror(NULL);
        return -1;
    }
    header_pointer = (microtcp_header_t*)socket->recvbuf;
    data_pointer = socket->recvbuf  + sizeof(microtcp_header_t);

    LOG_INFO("Packet received with seq_number %u", header_pointer->seq_number);
    if(header_pointer->seq_number != socket->peer_seq_number + bytes_received){
        LOG_WARN("    Packet loss. Received packet with seq_number %u, while expecting %u", header_pointer->seq_number, (socket->peer_seq_number + (uint32_t)bytes_received));
        socket->statistics->packets_lost++;
        socket->statistics->bytes_lost = header_pointer->seq_number - (socket->peer_seq_number + (uint32_t)bytes_received);
    }
    socket->peer_seq_number = header_pointer->seq_number;
    memcpy(buffer, data_pointer, bytes_received - sizeof(microtcp_header_t));
    is_fin_header = is_fin(header_pointer);
    socket->buf_fill_level -= bytes_received;

    if(is_fin_header) {    /* Received FIN while waiting for data. Shutting down connection */
        LOG_INFO("Pack received was FIN. Replying with ACK...");
        if(send_header(socket, 1, 0, 0, 0, 0, 0) == -1) {
            LOG_ERROR("Failed to send ACK header in response to FIN.");
            perror(NULL);
            return -1;
        }
        LOG_INFO("ACK packet sent with seq_number %u and ack_number ...", socket->seq_number);  /* TODO: ack number */
        LOG_INFO("State set to: CLOSING_BY_PEER");
        socket->state = CLOSING_BY_PEER;
        return 0;
    }

    /* TODO: checksum? */
    /* TODO: wait for re-transmission in case of different seq_number?*/
    return bytes_received;
}

static void acquire_sock_resources(microtcp_sock_t *socket) {
    assert(socket);
    socket->recvbuf = malloc(socket->buf_length);
    socket->buf_fill_level = 0;

    socket->statistics = calloc(1, sizeof(*socket->statistics));    /* Memory initialized to 0 */
    socket->peer_sin = calloc(1, sizeof(*socket->peer_sin));       /* This is a struct sockaddr_in. It MUST be initialized to zero. */
}

static void release_sock_resources(microtcp_sock_t *socket) {
    assert(socket);
    free(socket->recvbuf);
    free(socket->peer_sin);
    free(socket->statistics);
    socket->state = INVALID;
}

static microtcp_header_t microtcp_header() {
    microtcp_header_t header;
    memset(&header, 0, sizeof(header));
    return header;
}

static void display_statistics(microtcp_sock_t const *socket) {
    /* TODO: implement...*/
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
    ssize_t bytes_received;
    uint8_t *tmp_buffer;
    size_t tmp_buf_length = socket->buf_length * sizeof(*tmp_buffer);
    microtcp_header_t *peer_header_p;
    assert(socket);

    tmp_buffer = calloc(tmp_buf_length, 1);
    while(1) {
        bytes_received = threshold_recvfrom(socket->sd, tmp_buffer, tmp_buf_length, flags, (struct sockaddr *)&remote_addr, &remote_addr_len);
        if(bytes_received == -1) {
            free(tmp_buffer);
            return -1;
        }

        if(socket->peer_sin->sin_family != remote_addr.sin_family ||
           socket->peer_sin->sin_addr.s_addr != remote_addr.sin_addr.s_addr ||
           socket->peer_sin->sin_port != remote_addr.sin_port)
        {
            LOG_WARN("  Received packet from non-connected peer (different family, address or port detected). Packet Dropped.");
            continue;
        }
        /* TODO: checksum */
        break;
    }
    peer_header_p = (microtcp_header_t *)tmp_buffer;
    ntoh_header(peer_header_p);

    memcpy((socket->recvbuf+socket->buf_fill_level), tmp_buffer, (size_t)bytes_received);
    free(tmp_buffer);

    socket->buf_fill_level += bytes_received;
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

        peer_header_p = (microtcp_header_t *)get_last_packet_ptr(socket, (size_t)bytes_received);
        if(bytes_received == sizeof(microtcp_header_t) && peer_header_p->control == dummy_header.control) {
            return bytes_received;
        } else {    /* Packet is not the requested one. Remove it from the buffer and revert changes in the socket */
            LOG_WARN("    Received different pack than expected. Packet Dropped. (Requested <control, packet_size>: <%u, %zu (header only)>"
                     ", Received <control, packet_size>: <%u, %u>)", dummy_header.control, sizeof(microtcp_header_t), peer_header_p->control, (uint32_t)bytes_received);
            socket->buf_fill_level -= bytes_received;   /* This variable was altered by threshold_recv() */
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

static ssize_t threshold_send(microtcp_sock_t *socket, microtcp_header_t const *header, const void *data_buffer, size_t data_length, int flags) {
    /* TODO: wait for ACK */
    microtcp_header_t to_send_header = microtcp_header();
    uint8_t *to_send_buffer = calloc((sizeof(microtcp_header_t) + data_length), sizeof(uint8_t));
    ssize_t bytes_sent;
    assert(socket && header && data_buffer && data_length>0 && data_length<MICROTCP_MSS);

    /* Change header bytes to Network Byte Order */
    memcpy(&to_send_header, header, sizeof(microtcp_header_t));
    hton_header(&to_send_header);

    /* Copy header + data to a seamless continious buffer */
    memcpy(to_send_buffer, &to_send_header, sizeof(microtcp_header_t));
    memcpy((to_send_buffer + sizeof(microtcp_header_t)), data_buffer, data_length);

    bytes_sent = threshold_sendto(socket->sd, to_send_buffer, (data_length + sizeof(microtcp_header_t)), flags,
                                  (struct sockaddr*)socket->peer_sin, sizeof(*socket->peer_sin));
    if(bytes_sent == -1) {
        free(to_send_buffer);
        return -1;
    }
    socket->seq_number += bytes_sent;
    socket->statistics->packets_send++;
    socket->statistics->bytes_send += bytes_sent;
    free(to_send_buffer);
    return 0;
}

static ssize_t send_header(microtcp_sock_t *socket, uint8_t ack, uint32_t ack_number, uint8_t rst, uint8_t syn, uint8_t fin, int flags) {
    microtcp_header_t host_header = microtcp_header();
    microtcp_header_t netwrok_header;
    ssize_t bytes_sent;
    assert(socket);

    /* Create the Header with the given parameters */
    set_ack(&host_header, ack);
    set_rst(&host_header, rst);
    set_syn(&host_header, syn);
    set_fin(&host_header, fin);
    if(is_ack(&host_header))
        host_header.ack_number = ack_number;
    host_header.seq_number = (is_syn(&host_header)) ? (rand() % UINT32_MAX/2) : (socket->seq_number + sizeof(microtcp_header_t));   /* Divided by 2 in order to avoid rare overflows */

    /* Convert to Network Byte Order and send */
    memcpy(&netwrok_header, &host_header, sizeof(microtcp_header_t));
    hton_header(&netwrok_header);
    bytes_sent = threshold_sendto(socket->sd, &netwrok_header, sizeof(microtcp_header_t), flags, (struct sockaddr*)socket->peer_sin, sizeof(*socket->peer_sin));
    if(bytes_sent == -1) {
        return -1;
    }
    assert(bytes_sent == sizeof(microtcp_header_t));

    /* Update socket */
    if(is_ack(&host_header))
        socket->ack_number = host_header.ack_number;
    socket->seq_number = host_header.seq_number;
    socket->statistics->bytes_send += bytes_sent;
    socket->statistics->packets_send++;
    return bytes_sent;
}

static void* get_last_packet_ptr(const microtcp_sock_t *socket, size_t bytes_received) {
    assert(socket);
    return (socket->recvbuf + socket->buf_fill_level -  bytes_received);
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