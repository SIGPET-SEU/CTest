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

const char* kdfSaltConstAuthIDEncryptionKey             = "AES Auth ID Encryption";
const char* kdfSaltConstAEADRespHeaderLenKey            = "AEAD Resp Header Len Key";
const char* kdfSaltConstAEADRespHeaderLenIV             = "AEAD Resp Header Len IV";
const char* kdfSaltConstAEADRespHeaderPayloadKey        = "AEAD Resp Header Key";
const char* kdfSaltConstAEADRespHeaderPayloadIV         = "AEAD Resp Header IV";
const char* kdfSaltConstVMessAEADKDF                    = "VMess AEAD KDF";
const char* kdfSaltConstVMessHeaderPayloadAEADKey       = "VMess Header AEAD Key";
const char* kdfSaltConstVMessHeaderPayloadAEADIV        = "VMess Header AEAD Nonce";
const char* kdfSaltConstVMessHeaderPayloadLengthAEADKey = "VMess Header AEAD Key_Length";
const char* kdfSaltConstVMessHeaderPayloadLengthAEADIV  = "VMess Header AEAD Nonce_Length";


/*
 * The C implementation of VMess HMACCreator implemented in Clash.
 * Currently, only SHA256-based HMAC is supported.
 */
#define SHA_256_BLOCK_SIZE 64

typedef struct HMACCreator_t {
    struct HMACCreator_t* parent;
    guchar* value;
    gsize value_len;
    gcry_md_hd_t* h_in, *h_out;
} HMACCreator;

/*
 * Note that it is hmac_create's duty to open hashing handles, this
 * function only takes care of setting up keys.
 */
HMACCreator *
hmac_creator_new(HMACCreator* parent, const guchar* value, gsize value_len);

/*
 * HMAC creator cleanup routine, it will clear all the memory the
 * possible parents allocated recursively.
 *
 * Since it will also close the hashing handles, the caller should
 * keep in mind to call hmac_create FIRST to avoid closing an
 * uninitialized hashing handle, which ALWAYS raises SIGSEGV error.
 *
 * NOTE: This routine also frees the param, so the caller should NOT free the param again.
 */
void
hmac_creator_free(HMACCreator *creator);

/*
 * Create HMAC using the base creator.
 */
gcry_error_t
hmac_create(const HMACCreator* creator);

/*
 * This struct is used to produce the actual nested HMAC computation.
 * It is based on the array structure, where each of the entry is a
 * hash handle.
 */
typedef struct HMACDigester_t {
    int size;
    guint *order;
    gcry_md_hd_t **head;
} HMACDigester;

/*
 * Create the digester based on the creator.
 */
HMACDigester *
hmac_digester_new(HMACCreator* creator);

/*
 * HMAC digester cleanup routine, it will clear all the memory for the digester.
 *
 * Note that all the hash handles are copies of the original ones, so the digester
 * only closes their copies. The caller is responsible to call hmac_creator_free to
 * safely free the allocated memory for that creator.
 *
 * NOTE: This routine also frees the param, so the caller should NOT free the param again.
 */
void
hmac_digester_free(HMACDigester *digester);

/*
 * This function computes nested HMAC based on iterative approach instead of
 * the recursive one which is adopted in the Golang implementation.
 */
gcry_error_t
hmac_digest(HMACDigester *digester, const guchar *msg, gssize msg_len, guchar* digest);

/*
 * This function is a convenient function to compute the digest of msg given hd, while
 * maintain the internal state of hd by creating a copy of it. Therefore, using this
 * routine will NOT change the internal state of hd.
 *
 * NOTE that the caller is responsible to allocate enough memory for param digest.
 */
gcry_error_t
hmac_digest_on_copy(gcry_md_hd_t hd, const guchar *msg, gssize msg_len, guchar* digest);

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

guint *request_order(int size);

/* COMMENT: Shall we encapsulate the encryption/decryption processes into a routine? */
/*
 * Encrypt the data using the sealVMessAEADHeader. This is the C version of the
 * Clash sealVMessAEADHeader function, which is originally implemented in Golang.
 *
 * @param key               The original key (IKM) for key derivation, it should be 16 bytes long
 * @param nonce             The salt for KDF, it should be 8 bytes long
 * @param generatedAuthID   The associated data for AEAD, used for authentication, it should be 16 bytes long
 * @param in                The input data to be encryption
 * @param in_len            The length of the input data
 * @param out               The encryption result
 * @param out_len           The output length, the caller is responsible to allocate
 *                          enough space for the @out.
 */
gcry_error_t
sealVMessAEADHeader(const char *key, const char *nonce, const char* generatedAuthID,
                    guchar *in, guint in_len, guchar *out, guint out_len);







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