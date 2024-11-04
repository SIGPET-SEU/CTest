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
