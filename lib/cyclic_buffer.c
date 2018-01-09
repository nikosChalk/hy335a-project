

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "cyclic_buffer.h"
#include "utils.h"

struct cyclic_buffer {
    size_t total_size;

    uint8_t *data_buffer;
    size_t head; /* Index of the rightmost used element */
    size_t tail; /* Index of the leftmost used element */
    size_t guard; /* Guard value used to indicate when the buffer is empty */

    /*
     * If head == tail == guard , the buffer is empty.
     * If (head+1) % total_size == tail, the buffer is full.
     *
     * head and tail live in range [0, total_size) union {guard_value}
     */
};


cyclic_buffer_t* cyclic_buffer_make(size_t size) {
    cyclic_buffer_t *buf = malloc(sizeof(cyclic_buffer_t));

    buf->total_size = size;
    buf->data_buffer = malloc(sizeof(*(buf->data_buffer))*size);
    buf->head = buf->tail = buf->guard = size+1;
    return buf;
}

void cyclic_buffer_append(cyclic_buffer_t* cy_buf, void const *data, size_t data_len) {
    size_t front_data_len; /* Free space available until we hit the end of our buffer */

    assert(cy_buf && data_len<=cyclic_buffer_free_size(cy_buf));
    if(data_len == 0)   /* Nothing to do here */
        return;

    if(cyclic_buffer_is_empty(cy_buf)) {
        memcpy(cy_buf->data_buffer, data, data_len);
        cy_buf->head = data_len-1;
        cy_buf->tail = 0;
        return;
    }

    if(cy_buf->tail > cy_buf->head) {
        memcpy(cy_buf->data_buffer+cy_buf->head+1, data, data_len);
        cy_buf->head += data_len;   /* No wrap around will occur since head < tail < total_size */
        return;
    }

    /* tail <= head < total_size */
    front_data_len = cy_buf->total_size - (cy_buf->head+1);
    if(data_len > front_data_len && front_data_len > 0) {
        /* Two memcpy must be performed. One writes at the end of the buffer, and the other writes at the start of the buffer */
        memcpy(cy_buf->data_buffer+cy_buf->head+1, data, front_data_len);
        data = ((uint8_t const *)(data)) + front_data_len;
        data_len -= front_data_len;
        cy_buf->head = cy_buf->head+front_data_len; /* No wrap around occurs */
    }
    cy_buf->head = (cy_buf->head+1) % cy_buf->total_size;
    memcpy(cy_buf->data_buffer+cy_buf->head, data, data_len);
    cy_buf->head += data_len-1; /* No wrap around will occur */
}

void cyclic_buffer_pop(cyclic_buffer_t* cy_buf, void *buffer, size_t data_len) {
    size_t pop_from_end;
    assert(cy_buf && data_len<=cyclic_buffer_cur_size(cy_buf));

    if(data_len==0) /* Nothing to do here */
        return;

    if(cy_buf->tail > cy_buf->head) {
        pop_from_end = MIN2(cy_buf->total_size-cy_buf->tail, data_len);
        memcpy(buffer, cy_buf->data_buffer+cy_buf->tail, pop_from_end);
        cy_buf->tail = (cy_buf->tail+pop_from_end) % cy_buf->total_size;
        data_len -= pop_from_end;
        buffer = ((uint8_t*)(buffer)) + pop_from_end;
    }
    /* tail < head OR data_len == 0 (or both)*/
    memcpy(buffer, cy_buf->data_buffer+cy_buf->tail, data_len);
    cy_buf->tail = (cy_buf->tail+data_len) % cy_buf->total_size;   /* Possible wrap around if tail==0 and head == total_size-1 */

    if(cy_buf->tail == (cy_buf->head+1)%cy_buf->total_size) /* Tail surpassed head. Buffer is empty */
        cy_buf->tail= cy_buf->head = cy_buf->guard;
}

size_t cyclic_buffer_total_size(cyclic_buffer_t* cy_buf) {
    assert(cy_buf);
    return cy_buf->total_size;
}

size_t cyclic_buffer_cur_size(cyclic_buffer_t* cy_buf) {
    assert(cy_buf);

    if(cy_buf->head == cy_buf->guard)
        return 0;
    else if(cy_buf->head >= cy_buf->tail)
        return cy_buf->head - cy_buf->tail + 1;
    else
        return (cy_buf->total_size - cy_buf->tail) + (cy_buf->head+1);
}

size_t cyclic_buffer_free_size(cyclic_buffer_t* cy_buf) {
    assert(cy_buf);
    return cy_buf->total_size - cyclic_buffer_cur_size(cy_buf);
}

int cyclic_buffer_is_empty(cyclic_buffer_t *cy_buf) {
    assert(cy_buf);
    return (cy_buf->head == cy_buf->guard);
}

int cyclic_buffer_is_full(cyclic_buffer_t *cy_buf) {
    assert(cy_buf);
    return (cyclic_buffer_cur_size(cy_buf) == cy_buf->total_size);
}

void cyclic_buffer_delete(cyclic_buffer_t* cy_buf) {
    assert(cy_buf);
    free(cy_buf->data_buffer);
    free(cy_buf);
}
