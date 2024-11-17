//
// Created by lxyu on 24-10-17.
//

#ifndef LIBGCRYPT_WS_BYTEARRAY_H
#define LIBGCRYPT_WS_BYTEARRAY_H

#endif //LIBGCRYPT_WS_BYTEARRAY_H

#include <glib-2.0/glib.h>
#include <stdint.h>

/*
 * Convert a byte array to its hex string representation, the returned
 * string is nul terminated.
 *
 * @param in        The byte array to convert
 * @param inlen     The length of input buffer
 * @param out       The nul terminated string which is the hex representation of in,
 *                  the caller is responsible to allocate enough space for it.
 *
 * @return gboolean TRUE on success.
 */
gboolean to_hex(const guchar* in, guint inlen, gchar* out);

/*
 * Convert a uint16 number into its byte-wise representation in Big Endian manner
 */
void
put_uint16_be(uint16_t value, unsigned char* buffer);

/*
 * Convert a uint16 number into its byte-wise representation in Little Endian manner
 */
void
put_uint16_le(uint16_t value, unsigned char* buffer);