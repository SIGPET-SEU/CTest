//
// Created by lxyu on 24-10-20.
//

#include "ws_encrypt_vmess.h"

const char* kdfSaltConstAuthIDEncryptionKey = "AES Auth ID Encryption";
const char* kdfSaltConstAEADRespHeaderLenKey = "AEAD Resp Header Len Key";
const char* kdfSaltConstAEADRespHeaderLenIV = "AEAD Resp Header Len IV";
const char* kdfSaltConstAEADRespHeaderPayloadKey = "AEAD Resp Header Key";
const char* kdfSaltConstAEADRespHeaderPayloadIV = "AEAD Resp Header IV";
const char* kdfSaltConstVMessAEADKDF = "VMess AEAD KDF";
const char* kdfSaltConstVMessHeaderPayloadAEADKey = "VMess Header AEAD Key";
const char* kdfSaltConstVMessHeaderPayloadAEADIV = "VMess Header AEAD Nonce";
const char* kdfSaltConstVMessHeaderPayloadLengthAEADKey = "VMess Header AEAD Key_Length";
const char* kdfSaltConstVMessHeaderPayloadLengthAEADIV = "VMess Header AEAD Nonce_Length";

VMessDecoder *
vmess_decoder_new(int algo, int mode, guchar *key, guchar *iv, guint flags) {
    VMessDecoder *decoder = malloc(sizeof(VMessDecoder));

    vmess_cipher_suite_t *suite = malloc(sizeof(vmess_cipher_suite_t));
    suite->mode = mode;
    suite->algo = algo;
    decoder->cipher_suite = suite;

    guint key_len = gcry_cipher_get_algo_keylen(algo);
    guint iv_len;
    switch (mode) {
        // For GCM and POLY1305, bulk length needs to be overwritten.
        case GCRY_CIPHER_MODE_GCM:
            iv_len = GCM_IV_SIZE;
        case GCRY_CIPHER_MODE_POLY1305:
            iv_len = POLY1305_IV_SIZE;
        default:
            iv_len = gcry_cipher_get_algo_blklen(algo);
    }
    vmess_cipher_init(&decoder->evp, algo, mode, key, key_len, iv, iv_len, flags);
    /* Save IV for possible cipher reset */
    decoder->write_iv = g_byte_array_new();
    decoder->write_iv = g_byte_array_append(decoder->write_iv, iv, iv_len);
    return decoder;
}


gcry_error_t
vmess_cipher_init(gcry_cipher_hd_t* hd, int algo, int mode, guchar * key, gsize key_len, guchar * iv, gsize iv_len, guint flags) {
    /*
     * As the libgcrypt manual indicates (Sec 3.2.1), the gcry_error_t consists of code and source
     * components. However, when set to 0, the error itself represents a success.
     */
    gcry_error_t err = 0;
    err = gcry_cipher_open(hd, algo, mode, flags);
    GCRYPT_CHECK(err)

    if(key_len == 0) key_len = gcry_cipher_get_algo_keylen(algo);
    err = gcry_cipher_setkey(*hd, key, key_len);
    GCRYPT_CHECK(err)

    if(iv_len == 0) iv_len = gcry_cipher_get_algo_blklen(algo);
    err = gcry_cipher_setiv(*hd, iv, iv_len);
    GCRYPT_CHECK(err)
    return err;
}

void
vmess_decoder_free(VMessDecoder *decoder) {
    g_byte_array_free(decoder->write_iv, TRUE);
    g_free((void *)decoder->cipher_suite);
    gcry_cipher_close(decoder->evp);

    g_free(decoder);
}

gcry_error_t
vmess_byte_encryption(VMessDecoder * encoder, guchar *in, gsize inl, guchar *out, gsize outl, const guchar *ad,
                 gsize ad_len) {
    gcry_error_t err = 0;
    if(ad){
        err = gcry_cipher_authenticate(encoder->evp, ad, ad_len);
        GCRYPT_CHECK(err)
    }
    guint tag_len;

    switch (encoder->cipher_suite->mode) {
        case GCRY_CIPHER_MODE_GCM:
        case GCRY_CIPHER_MODE_POLY1305:
            tag_len = 16;
            break;
        default:
            tag_len = -1;
            /* Unsupported encryption mode. */
            return gcry_error(GPG_ERR_NOT_IMPLEMENTED);
    }
    gsize ciphertext_len = outl - tag_len;
    err = gcry_cipher_encrypt(encoder->evp, out, ciphertext_len, in, inl);
    GCRYPT_CHECK(err)

    err = gcry_cipher_final(encoder->evp);
    GCRYPT_CHECK(err)

    err = gcry_cipher_gettag(encoder->evp, out + ciphertext_len, tag_len);
    return err;
}

gcry_error_t
vmess_byte_decryption(VMessDecoder *decoder, guchar *in, gsize inl, guchar *out, gsize outl, const guchar *ad,
                      gsize ad_len) {
    gcry_error_t err = 0;
    if(ad){
        err = gcry_cipher_authenticate(decoder->evp, ad, ad_len);
        GCRYPT_CHECK(err)
    }
    guint tag_len;
    switch (decoder->cipher_suite->mode) {
        case GCRY_CIPHER_MODE_GCM:
        case GCRY_CIPHER_MODE_POLY1305:
            tag_len = 16;
            break;
        default:
            tag_len = -1;
            /* Unsupported encryption mode. */
            return gcry_error(GPG_ERR_NOT_IMPLEMENTED);
    }
    gsize ciphertext_len = inl - tag_len;
    err = gcry_cipher_decrypt(decoder->evp, out, outl, in, ciphertext_len);
    GCRYPT_CHECK(err)

    guchar calc_tag[tag_len];
    err = gcry_cipher_final(decoder->evp);
    GCRYPT_CHECK(err)

    err = gcry_cipher_gettag(decoder->evp, calc_tag, tag_len);
    if(memcmp(calc_tag, in+ciphertext_len, tag_len) != 0)
        return gcry_error(GPG_ERR_DECRYPT_FAILED);

    return err;
}

HMACCreator *
hmac_creator_new(HMACCreator *parent, const guchar *value, gsize value_len) {
    HMACCreator *creator = malloc(sizeof(HMACCreator));
    creator->parent = parent;
    creator->h_in = malloc(sizeof(gcry_md_hd_t));
    creator->h_out = malloc(sizeof(gcry_md_hd_t));

    creator->value_len = value_len;
    creator->value = malloc(value_len);
    memcpy(creator->value, value, creator->value_len);

    return creator;
}

void
hmac_creator_free(HMACCreator *creator) {
    if (creator->parent)
        hmac_creator_free(creator->parent);

    gcry_md_close(*creator->h_in);
    gcry_md_close(*creator->h_out);
    g_free(creator->value);
    g_free(creator->h_in);
    g_free(creator->h_out);
    g_free(creator);
}

gcry_error_t
hmac_create(const HMACCreator *creator) {
    gcry_error_t err = 0;
    if (creator->parent == NULL) {
        /* No HMAC flags are set since we handle HMAC by our implementation. */
        gcry_md_open(creator->h_in, GCRY_MD_SHA256, 0);
        gcry_md_open(creator->h_out, GCRY_MD_SHA256, 0);
        /* If the length of key is smaller than block size, pad it with 0's */
        guchar block_key[SHA_256_BLOCK_SIZE] = { 0 };
        guchar key_ipad[SHA_256_BLOCK_SIZE], key_opad[SHA_256_BLOCK_SIZE];
        /*
         * HMAC use the key following the rules below:
         * If value_len > block_size, key = HASH(value);
         * Otherwise, key = value
         */
        if(creator->value_len > SHA_256_BLOCK_SIZE){
            gcry_md_hd_t h_copy;
            err = gcry_md_copy(&h_copy, *creator->h_out);
            GCRYPT_CHECK(err)
            gcry_md_write(h_copy, creator->value, creator->value_len);
            memcpy(block_key, gcry_md_read(h_copy, gcry_md_get_algo(h_copy)), gcry_md_get_algo_dlen(GCRY_MD_SHA256));
            gcry_md_close(h_copy);
        }else{
            memcpy(block_key, creator->value, creator->value_len);
        }
        /* Create key_ipad and key_opad */
        for(guint i = 0; i < SHA_256_BLOCK_SIZE; i++){
            key_ipad[i] = 0x36 ^ block_key[i];
            key_opad[i] = 0x5c ^ block_key[i];
        }
        gcry_md_write(*creator->h_in, key_ipad, SHA_256_BLOCK_SIZE);
        gcry_md_write(*creator->h_out, key_opad, SHA_256_BLOCK_SIZE);
    } else {
        err = hmac_create(creator->parent);
        GCRYPT_CHECK(err)
        gcry_md_copy(creator->h_in, *creator->parent->h_in);
        gcry_md_copy(creator->h_out, *creator->parent->h_in);
        guchar block_key[SHA_256_BLOCK_SIZE] = { 0 };
        guchar key_ipad[SHA_256_BLOCK_SIZE], key_opad[SHA_256_BLOCK_SIZE];
        if(creator->value_len > SHA_256_BLOCK_SIZE){
            /* For KDF functions, this subroutine should NOT be hit. */
            /* NOT IMPLEMENTED */
        }else{
            memcpy(block_key, creator->value, creator->value_len);
        }
        /* Create key_ipad and key_opad */
        for(guint i = 0; i < SHA_256_BLOCK_SIZE; i++){
            key_ipad[i] = 0x36 ^ block_key[i];
            key_opad[i] = 0x5c ^ block_key[i];
        }
        gcry_md_write(*creator->h_in, key_ipad, SHA_256_BLOCK_SIZE);
        gcry_md_write(*creator->h_out, key_opad, SHA_256_BLOCK_SIZE);
    }
    return 0;
}

HMACDigester *hmac_digester_new(HMACCreator *creator) {
    if(!creator) return NULL;

    /* Create handler array */
    HMACDigester *digester = malloc(sizeof(HMACDigester));
    int size = 1; // creator->h_in
    for(HMACCreator *p = creator; p; p=p->parent)
        size++; // All other hash handles needed are p->h_out

    digester->size = size;
    digester->head = malloc(size*sizeof(gcry_md_hd_t*));

    digester->head[0] = malloc(sizeof(gcry_md_hd_t));
    gcry_md_copy(digester->head[0], *creator->h_in);

    HMACCreator *p = creator;
    for(guint i = 1; i < size; i++){
        digester->head[i] = malloc(sizeof(gcry_md_hd_t));
        gcry_md_copy(digester->head[i], *p->h_out);
        p = p->parent;
    }

    /* Create hash request order */
    digester->order = request_order(size);
    return digester;
}

void
hmac_digester_free(HMACDigester *digester){
    for(int i = 0; i < digester->size; i++){
        gcry_md_close(*digester->head[i]);
        g_free(digester->head[i]);
    }
    g_free(digester->head);
    g_free(digester->order);
    g_free(digester);
}

gcry_error_t
hmac_digest(HMACDigester *digester, const guchar *msg, gssize msg_len, guchar* digest) {
    gcry_error_t err = 0;
    /* Initializer */
    err = hmac_digest_on_copy(*digester->head[0], msg, msg_len, digest);
    GCRYPT_CHECK(err)

    for(int i = 1; i < 1<<(digester->size - 1); i++){
        guint cur_hd_order = digester->order[i];
        err = hmac_digest_on_copy(*digester->head[cur_hd_order], digest,
                                  gcry_md_get_algo_dlen(GCRY_MD_SHA256), digest);
        GCRYPT_CHECK(err)
    }
    return err;
}

gcry_error_t
hmac_digest_on_copy(gcry_md_hd_t hd, const guchar *msg, gssize msg_len, guchar* digest){
    gcry_error_t err = 0;
    guint digest_size = gcry_md_get_algo_dlen(GCRY_MD_SHA256);
    gcry_md_hd_t hd_copy;
    err = gcry_md_copy(&hd_copy, hd);
    GCRYPT_CHECK(err)
    gcry_md_write(hd_copy, msg, msg_len);
    memcpy(digest, gcry_md_read(hd_copy, GCRY_MD_SHA256), digest_size);
    gcry_md_close(hd_copy);
    return err;
}

/*
 * Create the request order based on the size. The hash requests are
 * performed on the array, so only numeric order is needed.
 */
guint *request_order(int size){
    if(size < 2) return NULL; /* This should not happen since HMAC requires at least 2 hash handles. */
    guint *tmp, *result;
    result = malloc((1<<(size-1)) * sizeof(guint));
    result[0] = 0, result[1] = 1; /* Initializer */

    for(int i = 3; i <= size; i++){
        int tmp_size = 1 << (i-1);
        tmp = g_malloc(tmp_size * sizeof(guint));
        for(int j = 0; j < tmp_size; j += 2){
            tmp[j] = result[j/2];
            tmp[j+1] = i - 1;
        }
        memcpy(result, tmp, tmp_size * sizeof(guint));
        g_free(tmp);
    }

    return result;
}

guchar* vmess_kdf(const guchar *key, guint key_len, guint num, ...) {

    HMACCreator *creator = hmac_creator_new(NULL,
                                            (const guchar*)kdfSaltConstVMessAEADKDF,
                                            strlen(kdfSaltConstVMessAEADKDF));
    va_list valist;
    va_start(valist, num);
    for(guint i = 0; i < num; i++){
        const char* path = va_arg(valist, const char*);
        creator = hmac_creator_new(creator, (const guchar*)path, strlen(path));
    }
    va_end(valist);

    hmac_create(creator);

    guchar* digest = malloc( gcry_md_get_algo_dlen(GCRY_MD_SHA256));
    HMACDigester *digester = hmac_digester_new(creator);
    hmac_digest(digester, key, key_len, digest);

    hmac_creator_free(creator);
    hmac_digester_free(digester);

    return digest;
}

//gcry_error_t
//sealVMessAEADHeader(const char *key, const char *nonce, const char* generatedAuthID,
//                    guchar *in, guint in_len, guchar *out, guint out_len) {
//    gcry_error_t err = 0;
//    guint16 aeadPayloadLengthSerializedByte = in_len;
//
//    guchar *payloadHeaderLengthAEADKey = malloc(16);
//    guchar *payloadHeaderLengthAEADNonce = malloc(12);
//
//    {
//        memcpy(payloadHeaderLengthAEADKey,
//               vmess_kdf(key, strlen(key), 3, kdfSaltConstVMessHeaderPayloadLengthAEADKey, generatedAuthID, nonce),
//               16);
//        memcpy(payloadHeaderLengthAEADNonce,
//               vmess_kdf(key, strlen(key), 3, kdfSaltConstVMessHeaderPayloadLengthAEADKey, generatedAuthID, nonce),
//               12);
//
//    }
//
//    guchar *payloadHeaderAEADKey = malloc(16);
//    guchar *payloadHeaderAEADNonce = malloc(12);
//
//    return err;
//}













//gcry_error_t
//file_encryption(gcry_cipher_hd_t *hd, FILE **in, FILE **out, const guchar *ad, gsize ad_len) {
//    gcry_error_t err = 0;
//    /* Attach association data */
//    if(ad){
//        err = gcry_cipher_authenticate(*hd, ad, ad_len);
//        GCRYPT_CHECK(err)
//    }
//
//    /* Read in the file block by block, and write encrypted byte stream into a new file */
//    for(;;){
//        unsigned char in_buf[AES_BLOCK_SIZE], out_buf[AES_BLOCK_SIZE];
//        size_t cnt;
//        if((cnt = fread(in_buf, 1, AES_BLOCK_SIZE, *in)) > 0){
//            err = gcry_cipher_encrypt(*hd, out_buf, AES_BLOCK_SIZE, in_buf, cnt);
//            GCRYPT_CHECK(err)
//            fwrite(out_buf, 1, cnt, *out);
//        }else if(feof(*in)){
//            /* cnt == 0 indicates an EOF. */
//            clearerr(*in);
//            break;
//        }else if(ferror(*in)){
//            /* Something is wrong with the file */
//            fprintf(stderr, "Error in reading the file.\n");
//            fclose(*in);
//            in = NULL;
//            break;
//        }
//    }
//    return err;
//}