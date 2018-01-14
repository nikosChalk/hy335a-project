

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

size_t cyclic_buffer_pop(cyclic_buffer_t* cy_buf, void *buffer, size_t data_len) {
    size_t pop_from_end;
    assert(cy_buf && data_len<=cyclic_buffer_cur_size(cy_buf));

    if(data_len==0) /* Nothing to do here */
        return 0;

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
    return data_len;
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

/**
 * Resizes this cyclic buffer. If at least 75% of the buffer is full, then the buffer's size is doubled, with total
 * size up to MAX_BUFFER_SIZE.
 * If less than or equal to the 25% of the buffer is full, then the buffer is shrunk in half size. The total size cannot be less
 * than MIN_BUFFER_SIZE.
 * In all cases min_available_space is always guaranteed for the buffer after the resize operation.
 * @param cy_buf The cyclic buffer to resize. Must not be NULL.
 * @param min_available_space The available min space that the buffer should have after the resize operation. Must be >= MIN_BUFFER_SIZE
 * and <=MAX_BUFFER_SIZE
 * @return The buffer's new size in Bytes.
 */
size_t cyclic_buffer_resize(cyclic_buffer_t* cy_buf, size_t min_available_space) {
    size_t old_size, tmp_size;
    int expand, shrink;
    assert(cy_buf && min_available_space>=MIN_BUFFER_SIZE && min_available_space<=MAX_BUFFER_SIZE);

    old_size = cy_buf->total_size;
    expand = cyclic_buffer_cur_size(cy_buf) >= (cy_buf->total_size)*0.75;
    shrink = cyclic_buffer_cur_size(cy_buf) <= (cy_buf->total_size)*0.25;

    if(expand || (cyclic_buffer_free_size(cy_buf) < min_available_space)) {  /* Expand */
        if(cy_buf->total_size == MAX_BUFFER_SIZE)   /* No expansion available */
            return MAX_BUFFER_SIZE;

        /* Expand buffer */
        /* tmp_size == how much space must be at least allocated to satisfy the min_available_space request */
        tmp_size = (cyclic_buffer_free_size(cy_buf) > min_available_space) ? 0 : (min_available_space - cyclic_buffer_free_size(cy_buf));
        tmp_size = MAX(((cy_buf->total_size)*2), tmp_size); /* The buffer's new size */
        cy_buf->total_size = MIN2(MAX_BUFFER_SIZE, tmp_size);
        cy_buf->data_buffer = realloc(cy_buf->data_buffer, cy_buf->total_size);
        if(cy_buf->tail > cy_buf->head) {   /* Tail pointer and data must be moved */
            tmp_size = old_size - cy_buf->tail; /* Data which are right of tail */
            memmove((cy_buf->data_buffer + cy_buf->total_size - tmp_size), (cy_buf->data_buffer + cy_buf->tail), tmp_size);
            cy_buf->tail = cy_buf->total_size - tmp_size;
        }

    } else if (shrink && (cyclic_buffer_free_size(cy_buf)/2 >= min_available_space)){    /* Shrink if user's demand will still be satisfied after the shrinking. */
        if(cy_buf->total_size == MIN_BUFFER_SIZE)   /* No shrinking available */
            return MIN_BUFFER_SIZE;

        cy_buf->total_size = MAX(MIN_BUFFER_SIZE, (cy_buf->total_size)/2);
        if(cy_buf->head != cy_buf->guard) { /* cyclic buffer is not empty */

            if((cy_buf->tail <= cy_buf->head) && (cy_buf->head >= cy_buf->total_size)) {    /* Tail is before head and data must be moved before re-alloc */
                tmp_size = cy_buf->head - cy_buf->tail + 1;   /* Current data size in buffer */
                memmove(cy_buf->data_buffer, (cy_buf->data_buffer + cy_buf->tail), tmp_size); /* We do not care for overlapping memory */
                cy_buf->tail = 0;
                cy_buf->head = tmp_size - 1;
            } else if(cy_buf->tail > cy_buf->head) {    /* tail is after head, hence data must be moved before re-alloc */
                tmp_size = old_size - cy_buf->tail; /* Data which are right of tail */
                memmove((cy_buf->data_buffer + cy_buf->total_size - tmp_size), (cy_buf->data_buffer + cy_buf->tail), tmp_size);
                cy_buf->tail = cy_buf->total_size - tmp_size;
            }
        }
        cy_buf->data_buffer = realloc(cy_buf->data_buffer, cy_buf->total_size);
    }

    return cy_buf->total_size;
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
