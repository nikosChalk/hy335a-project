

#include <stdint.h>
#include "cyclic_buffer.h"

struct cyclic_buffer {
    size_t total_size;

    uint8_t *data_buffer;
    uint8_t *head;
    uint8_t *tail;
};

/*
 * If head   == tail, the buffer is empty.
 * If head+1 == tail, the buffer is full.
 */