
#include <stdint.h>
#include <assert.h>
#include "../lib/bits.h"
#include "../lib/microtcp.h"

void test_suit(uint8_t bit_val) {
    uint16_t control = 0x0000;  /* 0xff a3 */

    set_bit(&control, sizeof(control), 1, 4, bit_val);
    assert(get_bit(&control, sizeof(control), 1, 4) == bit_val);

    set_bit(&control, sizeof(control), 1, 5, bit_val);
    assert(get_bit(&control, sizeof(control), 1, 5) == bit_val);

    set_bit(&control, sizeof(control), 1, 6, bit_val);
    assert(get_bit(&control, sizeof(control), 1, 6) == bit_val);

    set_bit(&control, sizeof(control), 1, 7, bit_val);
    assert(get_bit(&control, sizeof(control), 1, 7) == bit_val);
}

int main() {
    test_suit(1);
    test_suit(0);
    return 0;
}