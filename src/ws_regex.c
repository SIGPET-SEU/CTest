//
// Created by lxyu on 24-10-16.
//

#include "ws_regex.h"
#include "stdio.h"

GRegex *vmess_compile_keyfile_regex() {
#define OCTET "(?:[[:xdigit:]]{2})"
    const gchar *pattern =
            "(?:"
            /* VMess AUTH to Derived Secrets mapping. */
            "HEADER_KEY (?<header_key>" OCTET "{16})"
            "|HEADER_IV (?<header_iv>" OCTET "{16})"
            "|DATA_KEY (?<data_key>" OCTET "{16})"
            "|DATA_IV (?<data_iv>" OCTET "{16})"
            "|RESPONSE_TOKEN (?<response_token>" OCTET "{16})"
            ") (?<secret>" OCTET "+)";
#undef OCTET
    static GRegex *regex = NULL;
    GError *gerr = NULL;
    if (!regex) {
        regex = g_regex_new(pattern,
                            (GRegexCompileFlags)(G_REGEX_OPTIMIZE | G_REGEX_ANCHORED | G_REGEX_RAW),
                            G_REGEX_MATCH_ANCHORED, &gerr);
        if (gerr) {
            g_print("%s failed to compile regex: %s\n", G_STRFUNC,
                             gerr->message);
            g_error_free(gerr);
            regex = NULL;
        }
    }
    return regex;
}

void keylog_process_line(const char *data, const guint8 datalen, key_map_t *km) {
    vmess_key_match_group_t km_group[] = {
            {"header_key", km->header_key},
            {"header_iv", km->header_iv},
            {"data_key", km->data_key},
            {"data_iv", km->data_iv},
            {"response_token", km->response_token}
    };

    GRegex *regex = vmess_compile_keyfile_regex();
    if (!regex)
        return;

    /* Strip possible newline characters, e.g., '\r', '\n'. */
    const char *next_line = (const char *)data;
    const char *line_end = next_line + datalen;
    const char *line = next_line;
    next_line = (const char *)memchr(line, '\n', line_end - line);
    gssize linelen;

    if (next_line) {
        linelen = next_line - line;
        next_line++;    /* drop LF */
    } else {
        linelen = (gssize)(line_end - line);
    }
    if (linelen > 0 && line[linelen - 1] == '\r') {
        linelen--;      /* drop CR */
    }

    GMatchInfo *mi;
    gboolean result = g_regex_match_full(regex, line, linelen, 0, G_REGEX_MATCH_ANCHORED, &mi, NULL);
    if (result){
        /* Note that the secret read in is in plaintext form, it should be converted into hex form later. */
        gchar* hex_secret;
        gchar *auth;
        GByteArray *secret = g_byte_array_new(); /* We use byte array to store the hex-formed secrets. */
        GHashTable *ht = NULL;

        hex_secret = g_match_info_fetch_named(mi, "secret");

        /* G_N_ELEMENTS counts the number of entries in a static initialized array,
         * by computing sizeof(arr)/sizeof(arr[0]). Therefore, calling this macro
         * on a dynamically allocated array gives an incorrect answer.
         */
        for(int i = 0; i < G_N_ELEMENTS(km_group); i++){
            vmess_key_match_group_t* g = &km_group[i];
            auth = g_match_info_fetch_named(mi, g->re_group_name);
            if (auth && *auth){
                ht = g->key_ht;
                from_hex(hex_secret, secret, strlen(hex_secret));
                g_free(hex_secret);
                break;
            }
        }
        g_hash_table_insert(ht, auth, secret);
    }else if (linelen > 0 && line[0] != '#'){
        return; /* In VMess dissection, here one should raise some exception. */
    }
    /* always free match info even if there is no match. */
    g_match_info_free(mi);
}

gboolean from_hex(const char *in, GByteArray *out, guint datalen) {
    if(datalen & 1) /* The datalen should never be odd */
        return FALSE;
    out->len = datalen/2;
    out->data = g_malloc(out->len);
    gsize i;

    for(i = 0; i < datalen; i+=2){
        char a, b;
        a = ws_xton(in[i]), b = ws_xton(in[i+1]);
        if(a == -1 || b == -1)
            return FALSE;
        out->data[i/2] = (guint8)(a<<4|b);
    }
    return TRUE;
}

int
ws_xton(char ch)
{
    switch (ch) {
        case '0': return 0;
        case '1': return 1;
        case '2': return 2;
        case '3': return 3;
        case '4': return 4;
        case '5': return 5;
        case '6': return 6;
        case '7': return 7;
        case '8': return 8;
        case '9': return 9;
        case 'a':  case 'A': return 10;
        case 'b':  case 'B': return 11;
        case 'c':  case 'C': return 12;
        case 'd':  case 'D': return 13;
        case 'e':  case 'E': return 14;
        case 'f':  case 'F': return 15;
        default: return -1;
    }
}

void keylog_read(const char *file_path, key_map_t *km) {
    FILE *file = fopen(file_path, "r");
    for(;;){
        char buf[512], *line;
        line = fgets(buf, sizeof(buf), file);
        if(!line){
            if(feof(file))
                clearerr(file);
            else if(ferror(file))
                fclose(file);
            break;
        }
        keylog_process_line(line, strlen(line), km);
    }
}

gboolean from_hex_raw(const char* in, gchar *out, guint datalen)
{
    if (datalen & 1) /* The datalen should never be odd */
        return FALSE;
    gsize i;

    for (i = 0; i < datalen; i += 2) {
        char a, b;
        a = ws_xton(in[i]), b = ws_xton(in[i + 1]);
        if (a == -1 || b == -1)
            return FALSE;
        out[i / 2] = (guint8)(a << 4 | b);
    }
    out[datalen / 2 + 1] = '\0';
    return TRUE;
}
