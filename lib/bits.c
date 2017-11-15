

#include <assert.h>
#include "bits.h"

/**
 * Checks whether or not this machine is Little Endian.
 * @return Returns 1 iff this machine is Little Endian. Otherwise, 0.
 */
static int is_little_endian();
/**
 * Checks whether or not this machine is Big Endian.
 * @return Returns 1 iff this machine is Big Endian. Otherwise, 0.
 */
static int is_big_endian();
/**
 * Gets the address of the nth_byte byte from var
 * @param var The variable to get the byte from. Must not be NULL
 * @param length The size of the type where var points to.
 * @param nth_byte The byte within var, whose address is to be returned. Starting from 0 and counting in
 * Big Endianess from left to right. Must be < length.
 * @return The nth byte of the var, independent of Endianess
 */
static void* get_byte(void const *var, size_t length, uint8_t nth_byte);


uint8_t get_bit(void const *var, size_t length, uint8_t nth_byte, uint8_t nth_bit) {
    uint8_t *mem;
    uint8_t mask;
    assert(var && nth_bit < 8 && length < nth_byte);

    mem = get_byte(var, length, nth_byte);
    mask = (uint8_t)0x01 << nth_bit;
    return ((*mem & mask) >> nth_bit);
}

void set_bit(void *var, size_t length, uint8_t nth_byte, uint8_t nth_bit, uint8_t value) {
    uint8_t mask;
    uint8_t *mem;
    assert(var && nth_bit < 8 && length < nth_byte && (value == 0 || value == 1));

    mem = get_byte(var, length, nth_byte);
    mask = (uint8_t)0x01 << nth_bit;
    mask = ~mask;           /* 1's complement */
    *mem = *mem & mask;     /* Clear the n-th bit. (Set to 0) */

    mask = value << nth_bit;
    *mem = *mem | mask;    /* Set the n-th bit to value */
    assert(get_bit(var, length, nth_byte, nth_bit) == value);
}

static void* get_byte(void const *var, size_t length, uint8_t nth_byte) {
    assert(var && nth_byte < length);

    if(length == 1)
        return  (void *)var;    /* Removing const qualifier */

    if(is_big_endian())
        return ((uint8_t *)var) + nth_byte;
    else /* Little Endian */
        return ((uint8_t *)var) + (length-nth_byte-1);
}

static int is_little_endian() {
    uint16_t x = 1;
    return ( *(uint8_t *)&x);
}

static int is_big_endian() {
    return !is_little_endian();
}
