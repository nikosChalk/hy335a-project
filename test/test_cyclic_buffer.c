

#include <string.h>
#include <stdint.h>
#include "../lib/cyclic_buffer.h"

int main() {
    cyclic_buffer_t *cy_buf;
    uint8_t data_buf[12000];
    int i=0;

    cy_buf = cyclic_buffer_make(8192);

    for(i=0; i<10; i++) {

        cyclic_buffer_resize(cy_buf, 1400);
        cyclic_buffer_append(cy_buf, data_buf, 1400);
    }

    return 0;
}

