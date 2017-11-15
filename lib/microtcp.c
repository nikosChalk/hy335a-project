

#include <time.h>
#include <stdlib.h>
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
 * Same as microtcp_send() except that one passes both the header and the data to be sent. If data_buffer is NULL, then
 * only the header of the packet is sent.
 */
static ssize_t microtcp_send_packet(microtcp_sock_t *socket, const microtcp_header_t *header, const void *data_buffer, size_t data_length, int flags);

/**
 * Sends an ACK packet to the peer that socket is connected to, without any data (only the header is sent). Note that
 * this function does not wait for an ACK reply for the sent packet. Also changes the seq_number of socket to the
 * appropriate value.
 * @param socket The socket from which the data are sent. Must have a connection ESTABLISHED state.
 * @param flags Same as microtcp_send()
 * @return Same as microtcp_send()
 */
static ssize_t sendACK(microtcp_sock_t *socket, int flags);

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
 * Creates a microtcp_header_t and initializes every field to 0.
 * @return A microtcp_header_t header with each field initialized to 0.
 */
static microtcp_header_t microtcp_header();

/*******************************************************************/
/******************* END OF FORWARD DECLARATIONS *******************/
/*******************************************************************/

microtcp_sock_t microtcp_socket (int domain, int type, int protocol) {
    /* Your code here */
    /* Na thethei to state tou socket se UNKNOWN */
    /* init all fields. pointers and seq_nunmber should be set to NULL and 0 accordingly */
}

int microtcp_bind (microtcp_sock_t *socket, const struct sockaddr *address, socklen_t address_len) {
    /* Your code here */
    /* Na thetei to state tou socket se BINDED iff htan UNKNOWN prin.*/
}

int microtcp_connect (microtcp_sock_t *socket, const struct sockaddr *address, socklen_t address_len) {
    microtcp_header_t syn_header;
    microtcp_header_t *peer_header;
    ssize_t bytes_sent;

    /* Checking if parameters comply to documentation */
    if(!socket || !address) {
        LOG_ERROR("socket and address must not be NULL");
        return  -1;
    } else if(socket->state != BINDED) {
        LOG_ERROR("Could not connect to remote host. Socket is not binded.");
        return -1;
    }

    /* Acquiring resources and sendind SYN packet */
    acquire_sock_resources(socket);
    socket->seq_number = rand() % SIZE_MAX; /* SIZE_MAX is the max value for size_t types */
    memcpy(socket->peer_sin, (struct sockaddr_in *)address, address_len);           /******* EXPECT BUUUUGS???? *******/

    /* Creating SYN packet to send */
    syn_header = microtcp_header();
    set_syn(&syn_header, 1);
    syn_header.seq_number = socket->seq_number;

    while(1) {
        LOG_INFO("Attempting connection...");
        bytes_sent = microtcp_send_packet(socket, &syn_header, NULL, 0, 0); /* Blocking */
        if (bytes_sent == -1) {
            LOG_ERROR("Failed to dispatch SYN packet. Aborting connection to remote host.");
            perror(NULL);
            release_sock_resources(socket);
            return -1;
        }

        peer_header = (microtcp_header_t *)socket->recvbuf;
        ntoh_header(peer_header);    /* Header was travelling in the Network, therefore he is in Network Byte Order */

        /* Assuming that the packet does not have errors (Checksum, crc32). (Implementation in phase B) */
        /* In case of error, the bellow code should not be executed */
        break;
    }
    assert(is_syn(peer_header) && is_ack(peer_header));    /* ACK mechanism guarantees that this is the the packet that I am looking for. Otherwise a logical mistake has been made */
    socket->peer_seq_number = peer_header->seq_number;
    socket->state = ESTABLISHED;
    socket->buf_fill_level = 0;

    if(sendACK(socket, 0) == -1) {  /* Not a critical issue. The (server) user will call microtcp_rcv() which will re-dispatch this ACK */
        LOG_WARN("Failed to dispatch ACK packet during 3-way handshake.");
        perror(NULL);
    }
    return 0;
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

    acquire_sock_resources(socket);
    socket->seq_number = rand() % SIZE_MAX; /* SIZE_MAX is the max value for size_t types */

    if(!address) {  /* We want the peer's information regardless what the API user requested */
        address = (struct sockaddr*)socket->peer_sin;
        address_len = sizeof(*socket->peer_sin);
    }
    while(1) {
        LOG_INFO("Waiting for connection...");
        bytes_received = threshold_recvfrom(socket->sd, socket->recvbuf, socket->buf_length, 0, address, &address_len, socket->statistics); /* Blocking */
        if (bytes_received == -1) {
            LOG_ERROR("Someone attempted a connection but failed:");
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

        /* Assuming that the packet does not have errors (Checksum, crc32). (Implementation in phase B) */
        /* In case of error, the bellow code should not be executed */
        break;
    }
    socket->buf_fill_level += bytes_received;
    if(address != (struct sockaddr*)socket->peer_sin)
        memcpy(socket->peer_sin, address, address_len);         /************ This line should be tested. It may contain BUGS ************/
    LOG_INFO("Received incoming SYN packet");

    /*The peer_header is fine: contains seq of peer and it is a SYN packet. */
    socket->peer_seq_number = peer_header->seq_number;
    /* Sending SYN, ACK packet to peer */
    host_syn_ack_header = microtcp_header();
    host_syn_ack_header.seq_number = socket->seq_number;
    host_syn_ack_header.ack_number = socket->peer_seq_number + bytes_received;
    set_syn(&host_syn_ack_header, 1);
    set_ack(&host_syn_ack_header, 1);
    socket->buf_fill_level = 0;         /* Empty buffer. Its information is no longer needed */

    LOG_INFO("Replying with SYN, ACK...");
    if(microtcp_send_packet(socket, &host_syn_ack_header, NULL, 0, 0) == -1) {
        LOG_ERROR("Attempted to send SYN, ACK but failed:");
        perror(NULL);
        release_sock_resources(socket);
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

static void acquire_sock_resources(microtcp_sock_t *socket) {
    assert(socket);
    socket->recvbuf = malloc(sizeof(*socket->recvbuf) * socket->buf_length);
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

static ssize_t microtcp_send_packet(microtcp_sock_t *socket, const microtcp_header_t *header, const void *data_buffer, size_t data_length, int flags) {
    /* Header does not need to be in Network Byte Order. It will be automatically converted in here */
    /* However, data_buffer must be in Network Byte Order. */
    microtcp_header_t network_header = *header;
    hton_header(&network_header);
    /* Fragment packets with data bigger than MICROTCP_RECVBUF_LEN-sizeof(header)-1?. */
    /* Check also if socket has ESTABLISHED state */
    /* Should deal with NULL data_buffer since that indicates that the packet is only a header */
    /* threshold_sendto() should be used instead of sendto() */
    /* must block until ACK is received. Will wait for an ack */
    /* ACK packets received, WILL be placed within socket->recvbuf (storing header only, since ACK have no data), */
    /* since they may contain useful information for the caller.  */
    /* data written in socket->recvbuf are in Network Byte Order */
    /* Will also updade seq_number and ack_number of socket due to ACK packet being received */
}

static ssize_t sendACK(microtcp_sock_t *socket, int flags) {
    microtcp_header_t ack_header;
    ssize_t bytes_sent;
    assert(socket && socket->state == ESTABLISHED);

    ack_header  = microtcp_header();
    set_ack(&ack_header, 1);
    ack_header.seq_number = socket->seq_number;
    ack_header.ack_number = socket->ack_number;
    hton_header(&ack_header);
    bytes_sent = threshold_sendto(socket->sd, &ack_header, sizeof(microtcp_header_t), flags, (struct sockaddr*)socket->peer_sin,
                                  sizeof(*socket->peer_sin), socket->statistics);
    if(bytes_sent != -1)
        socket->seq_number += bytes_sent;
    return bytes_sent;
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