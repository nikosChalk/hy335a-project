/**
 * Cyclic Buffer API. A cyclic buffer is a FIFO queue in which arbitrary data can be inserted and retrieved.
 */

#ifndef MICROTCP_CYCLIC_BUFFER_H
#define MICROTCP_CYCLIC_BUFFER_H

#include <stddef.h>

typedef struct cyclic_buffer cyclic_buffer_t;

/**
 * Creates a cyclic buffer with the given size and returns a pointer to it.
 * @param size The total size of the cyclic buffer in bytes.
 * @return The cyclic buffer
 */
cyclic_buffer_t* cyclic_buffer_make(size_t size);

/**
 * Inserts the given data to the FIFO cyclic buffer
 * @param cy_buf The cyclic buffer. Must not be NULL.
 * @param data The data buffer to insert as is.
 * @param data_len The length of the data in bytes. Must be <= cyclic_buffer_free_size()
 */
void cyclic_buffer_append(cyclic_buffer_t* cy_buf, void const *data, size_t data_len);

/**
 * Pops data_len bytes and copies them into buffer.
 * @param cy_buf The cyclic buffer, must not be NULL.
 * @param buffer The buffer where the retrieved data will be written.
 * @param data_len The amount of data to retrieve. Must be <= cyclic_buffer_cur_size()
 */
void cyclic_buffer_pop(cyclic_buffer_t* cy_buf, void *buffer, size_t data_len);

/**
 * Returns the total allocated size of the cyclic buffer.
 * @param cy_buf The cyclic buffer, must not be NULL.
 * @return The total allocated size of the cyclic buffer, in Bytes
 */
size_t cyclic_buffer_total_size(cyclic_buffer_t* cy_buf);

/**
 * Returns how much the buffer has been filled.
 * @param cy_buf The cyclic buffer, must not be NULL.
 * @return How many bytes out of total cyclic_buffer_total_size(), are currently being used.
 */
size_t cyclic_buffer_cur_size(cyclic_buffer_t* cy_buf);

/**
 * Returns how much of the buffer is still free.
 * @param cy_buf The cyclic buffer, must not be NULL.
 * @return How many bytes out of total cyclic_buffer_total_size(), are currently free.
 */
size_t cyclic_buffer_free_size(cyclic_buffer_t* cy_buf);

/**
 * Delets the cyclic buffer and de-allocates resources. After this call, cy_buf is no longer usable.
 * @param cy_buf The cyclic buffer, must not be NULL.
 */
void cyclic_buffer_delete(cyclic_buffer_t* cy_buf);

#endif /*MICROTCP_CYCLIC_BUFFER_H */
