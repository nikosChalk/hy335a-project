

#ifndef MICROTCP_BITS_H
#define MICROTCP_BITS_H

#include <stdint.h>
#include <stdlib.h>

/**
 * Get the nth bit of the nth byte of the variable. Note that the variable must have at least length bytes
 * @param var The variable to search. Must not be NULL.
 * @param length The size of the type where var points to.
 * @param nth_byte The byte in which the nth_bit resides, starting from 0 and counting in Big Endianess from
 * left to right. Must be < length.
 * @param nth_bit The bit in the nth_byte to alter. Starting from 0 and counting from left to right within the byte.
 * Must be < 8.
 * @return The nth_bit of the nth_bit of variable. Returned value is either 0 or 1.
 */
uint8_t get_bit(void const *var, size_t length, uint8_t nth_byte, uint8_t nth_bit);

/**
 * Sets the nth bit of the nth byte of the variable to the given value. Note that the variable must have at least
 * length bytes.
 * @param var The variable to alter. Must not be NULL.
 * @param length The size of the type where var points to.
 * @param nth_byte The byte in which the nth_bit resides, starting from 0 and counting in Big Endianess from
 * left to right. Must be < length.
 * @param nth_bit The bit in the nth_byte to alter. Starting from 0 and counting from left to right within the byte.
 * Must be < 8.
 * @param value The value to change the specific bit. Must be either 0 or 1
 */
void set_bit(void *var, size_t length, uint8_t nth_byte, uint8_t nth_bit, uint8_t value);

#endif /* MICROTCP_BITS_H */
