//
// Created by lxyu on 24-10-16.
//

#ifndef LIBGCRYPT_VMESS_H
#define LIBGCRYPT_VMESS_H

#endif //LIBGCRYPT_VMESS_H

#include "ws_hashmap.h"

/* Build regex for vmess keylog */
GRegex* vmess_compile_keyfile_regex();

void keylog_process_line(const char* data, guint8 datalen, key_map_t* km);

/*
 * Wrapper function for keylog_process_line, where we read lines from a keylog file,
 * and parse it with the vmess_compile_keyfile_regex(), then insert the result into the
 * key map.
 *
 * This function is responsible for error handling, e.g., errors with file operations, and
 * ignores some commented lines, i.e., lines started with #.
 *
 * NOTE: This function differs from the keylog load function used for VMess dissector,
 * you should consider it only a prototype for VMess key load, which makes it easier to
 * debug and test.
 *
 * @param file_path     The path to the keylog file.
 * @param km            The keymap to insert with parse results.
 */
void keylog_read(const char* file_path, key_map_t* km);

/*
 * Write the content of a string into its hex form. For example, given the string
 * "0102030aefbb", we convert each octet into a single byte into the target.
 * After conversion, the result should be "\x01\x02\x03\x0a\xef\xbb".
 *
 * @param in    The string to be converted.
 * @param out   The output hex-formed string.
 * @param datalen   The length of the input string.
 *
 * @return  TRUE if succeeded, FALSE otherwise.
 */
gboolean from_hex(const char* in, GByteArray* out, guint datalen);

/**
 * This is the raw char* version of from_hex, used for handling the raw bytes
 * read from tvb, where looking up the GHashMap with GByteArray would be cumbersome.
 *
 * NOTE that the caller is responsbile for memory allocattion with reasonable size.
 */
gboolean from_hex_raw(const char* in, gchar *out, guint datalen);

/*
 * Helper function stolen from Wireshark codebase. It maps 0,1,...,F to the corresponding
 * hex value. For example, it maps 'A' (or 'a', case-insensitive) to 10.
 */
int ws_xton(char ch);