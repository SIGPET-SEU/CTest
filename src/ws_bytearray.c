//
// Created by lxyu on 24-10-17.
//

#include "ws_bytearray.h"
#include <stdio.h>

gboolean to_hex(const guchar* in, guint inlen, gchar* out){
    for(guint i = 0; i < inlen; i++)
        sprintf(out + 2*i, "%02X", in[i]);

    out[2*inlen] = '\0';
}

void
put_uint16_be(uint16_t value, unsigned char* buffer) {
    buffer[0] = (value >> 8) & 0xFF;  // Most significant byte
    buffer[1] = value & 0xFF;         // Least significant byte
}

void
put_uint16_le(uint16_t value, unsigned char* buffer) {
    buffer[0] = value & 0xFF;         // Least significant byte
    buffer[1] = (value >> 8) & 0xFF;  // Most significant byte
}
