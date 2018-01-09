

#include <string.h>
#include "../lib/cyclic_buffer.h"

void foo(int x) {
    x++;
    memcpy(NULL, &x, x-6);
    return;
}

int main() {
    int *p = NULL;
    int x = 5;
    int z = x*13*0;
    int y = 32*x*z;

    foo(5);
    return 0;
}

