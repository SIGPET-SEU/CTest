//
// Created by lxyu on 24-10-20.
//

#ifndef LIBGCRYPT_WS_ENCRYPT_H
#define LIBGCRYPT_WS_ENCRYPT_H

#endif //LIBGCRYPT_WS_ENCRYPT_H

/*
 * If we're running GCC or clang define _U_ to be "__attribute__((unused))"
 * so we can use _U_ to flag unused function parameters and not get warnings
 * about them. Otherwise, define _U_ to be an empty string so that _U_ used
 * to flag an unused function parameters will compile with other compilers.
 *
 * XXX - similar hints for other compilers?
 */
#if defined(__GNUC__) || defined(__clang__)
    #define _U_ __attribute__((unused))
#elif defined(_MSC_VER)
    #define _U_ __pragma(warning(suppress:4100 4189))
#else
    #define _U_
#endif

#include "gcrypt.h"
#include <glib.h>
#include <stdarg.h>
#include <inttypes.h>

/* Define some basic params, e.g., key length and iv length */
#define AES_KEY_SIZE 16
#define AES_BLOCK_SIZE 16

#define GCM_IV_SIZE 12
#define GCM_TAG_SIZE 16

#define VMESS_CIPHER_CTX gcry_cipher_hd_t

// Error handling for libgcrypt
#define GCRYPT_CHECK(gcry_error)                        \
    if (gcry_error) {                                   \
        fprintf(stderr, "Failure at line %d: %s\n",     \
                __LINE__, gcry_strerror(gcry_error));   \
        return gcry_error;                              \
    }

typedef enum {
    MODE_NONE,      /* No encryption, for debug only */
    MODE_CFB,       /* CFB mode */
    MODE_GCM,       /* GenericAEADCipher */
    MODE_POLY1305,  /* AEAD_CHACHA20_POLY1305 with 16 byte auth tag (RFC 7905) */
} vmess_cipher_mode_t;

typedef struct _VMessCipherSuite {
    vmess_cipher_mode_t mode;
} VMessCipherSuite;

typedef struct {
    /* In this version, I decide to use GByteArray instead of StringInfo used in packet-tls-utils.h
     * to record key/iv or other things. Since GByteArray has an intrinsic length field, it should
     * avoid some cumbersome operations (I hope so).
     */
    GByteArray write_iv;
    const VMessCipherSuite *cipher_suite;
    VMESS_CIPHER_CTX evp;
} VMessDecoder;

static const char* kdfSaltConstVMessAEADKDF = "VMess AEAD KDF";

/*
 * The C implementation of VMess HMACCreator implemented in Clash.
 */
typedef struct HMACCreator_t {
    struct HMACCreator_t* parent;
    guchar* value;
    gsize value_len;
} HMACCreator;

HMACCreator *hmac_creator_new(HMACCreator* parent, const guchar* value, gsize value_len);

/*
 * HMAC creator cleanup routine, it will clear all the memory the possible parents allocated recursively.
 * NOTE: This routine also frees the param, so the caller should NOT free the param again.
 */
void hmac_creator_free(HMACCreator *creator);

gcry_error_t
hmac_create(const HMACCreator* creator, gcry_md_hd_t* hd);

/*
 * Cipher initialization routine.
 *
 * @param alg       The encryption algorithm
 * @param mode      The cipher mode
 * @param key       The encryption key
 * @param key_len   The length of the key, if set 0, automatic inference will be used
 * @param iv        The initialization IV
 * @param iv_len    The length of the iv, if set 0, automatic inference will be used
 * @param flag      The flag for encryption
 *
 * @return gboolean TRUE on success.
 */
gcry_error_t
vmess_cipher_init(gcry_cipher_hd_t* hd, int algo, int mode, guchar * key, gsize key_len, guchar * iv, gsize iv_len, guint flag);

/*
 * Array data encryption, which encrypts an arbitrary buffer of raw bytes and attach the authentication tag to the tail.
 *
 * -------------------------------
 * |             in              |
 * -------------------------------
 *               |
 *               v
 * ---------------------------------------------------
 * |                      out                        |
 * ---------------------------------------------------
 * |               cipher             |      tag     |
 * ---------------------------------------------------
 *
 * @param encoder   The VMess encoder
 * @param in        The input byte array
 * @param inl       The size of the input byte array
 * @param out       The output byte array
 * @param outl      The size of the output byte array, the caller should be aware of the output length, which includes
 *                  the tag length
 * @param ad        (Optional) The associated data for authentication
 * @param ad_len    The length of the associated data
 *
 * @return gcry_error_t     The possible error, 0 on success.
 */
gcry_error_t
vmess_byte_encryption(VMessDecoder * encoder, guchar* in, gsize inl, guchar* out, gsize outl,
                 const guchar* ad _U_, gsize ad_len _U_);

/*
 * Array data decryption, which decrypts an arbitrary buffer of raw bytes. It resolves the authentication tag and only
 * return the plaintext.
 *
 * ---------------------------------------------------
 * |                      in                         |
 * ---------------------------------------------------
 * |               cipher             |      tag     |
 * ---------------------------------------------------
 *                         |                  ^ Check match
 *                         v                  v
 * --------------------------------   ----------------
 * |             out              |   |      tag     |
 * --------------------------------   ----------------
 *
 * @param decoder   The VMess decoder
 * @param in        The input byte array (ciphertext)
 * @param inl       The size of the input byte array
 * @param out       The output byte array (plaintext)
 * @param outl      The size of the output byte array
 * @param ad        (Optional) The associated data for authentication
 * @param ad_len    The length of the associated data
 *
 * @return gcry_error_t     The possible error, 0 on success.
 */
gcry_error_t
vmess_byte_decryption(VMessDecoder * decoder, guchar* in, gsize inl, guchar* out, gsize outl,
                 const guchar* ad _U_, gsize ad_len _U_);

/*
 * Key derive function for VMess.
 *
 * @param key           The original key used for key derivation
 * @param derived_key   The key derived by the KDF
 * @param num           The number of the messages for key derivation
 *
 * @return guchar*      The derived key byte buffer
 */
guchar*
vmess_kdf(const guchar *key, guint key_len, guint num, ...);

/*
 * Create nested HMAC using the existing hash function with the provided key.
 * This is a customized implementation since gcrypt does not allow creating
 * hash function from existing hash handle.
 *
 * OpenSSL may provide the similar mechanism.
 *
 * @param hd        The existing hash function handle
 * @param key       The key for the new HMAC
 *
 * @return new_hd   The created hash function handle
 */
gcry_error_t
nested_hmac(gcry_md_hd_t* hd, const guchar* key, gcry_md_hd_t* new_hd);









/*
 * File encryption function.
 *
 * @param hd        The handle of the cipher
 * @param in        Input file descriptor
 * @param out       Output file descriptor
 * @param ad        (Optional) The associated data for authentication
 * @param ad_len    The length of the associated data
 *
 * @return gcry_error_t     The possible error, 0 on success.
 */
gcry_error_t
file_encryption(gcry_cipher_hd_t* hd, FILE** in, FILE **out, const guchar* ad _U_, gsize ad_len _U_);

/*
 * File decryption function.
 *
 * @param hd        The handle of the cipher
 * @param in        Input file descriptor
 * @param out       Output file descriptor
 * @param ad        (Optional) The associated data for authentication
 * @param ad_len    The length of the associated data
 *
 * @return gcry_error_t     The possible error, 0 on success.
 */
gcry_error_t
file_decryption(gcry_cipher_hd_t* hd, FILE** in, FILE **out, const guchar* ad _U_, gsize ad_len _U_);