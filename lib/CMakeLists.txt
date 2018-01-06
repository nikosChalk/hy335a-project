include_directories(${MICROTCP_INCLUDE_DIRS})

add_library(microtcp SHARED microtcp.c bits.c cyclic_buffer.c)