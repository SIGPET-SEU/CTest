//
// Created by lxyu on 24-10-20.
//

#include "ws_encrypt_vmess.h"

gcry_error_t
vmess_cipher_init(gcry_cipher_hd_t* hd, int algo, int mode, guchar * key, gsize key_len, guchar * iv, gsize iv_len, guint flag) {
    /*
     * As the libgcrypt manual indicates (Sec 3.2.1), the gcry_error_t consists of code and source
     * components. However, when set to 0, the error itself represents a success.
     */
    gcry_error_t err = 0;
    err = gcry_cipher_open(hd, algo, mode, flag);
    GCRYPT_CHECK(err)

    if(key_len == 0) key_len = gcry_cipher_get_algo_keylen(algo);
    err = gcry_cipher_setkey(*hd, key, key_len);
    GCRYPT_CHECK(err)

    if(iv_len == 0) iv_len = gcry_cipher_get_algo_blklen(algo);
    err = gcry_cipher_setiv(*hd, iv, iv_len);
    GCRYPT_CHECK(err)
    return err;
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
        case MODE_GCM:
        case MODE_POLY1305:
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
        case MODE_GCM:
        case MODE_POLY1305:
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

    creator->value_len = value_len;
    creator->value = malloc(value_len);
    memcpy(creator->value, value, creator->value_len);

    return creator;
}

void hmac_creator_free(HMACCreator *creator) {
    if (creator->parent)
        hmac_creator_free(creator->parent);

    g_free(creator->value);
    g_free(creator);
}


gcry_error_t
hmac_create(const HMACCreator *creator, gcry_md_hd_t* hd) {
    gcry_error_t err = 0;
    if (creator->parent == NULL) {
        err = gcry_md_open(hd, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
        GCRYPT_CHECK(err)
        err = gcry_md_setkey(*hd, creator->value, creator->value_len);
        GCRYPT_CHECK(err)
    } else {
        gcry_md_hd_t parent_hmac;
        err = hmac_create(creator->parent, &parent_hmac);
        GCRYPT_CHECK(err)
//        err = gcry_md_open(hd, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
//        GCRYPT_CHECK(err)
//        err = gcry_md_setkey(*hd, gcry_md_read(parent_hmac, GCRY_MD_SHA256), gcry_md_get_algo_dlen(GCRY_MD_SHA256));
        err = gcry_md_setkey(parent_hmac, creator->value, creator->value_len);
        GCRYPT_CHECK(err)
//        gcry_md_close(parent_hmac);
        *hd = parent_hmac;
    }
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

    gcry_md_hd_t hd;
    hmac_create(creator, &hd);
    gcry_md_write(hd, key, key_len);

    guchar* digest = malloc( gcry_md_get_algo_dlen(GCRY_MD_SHA256));
    memcpy(digest, gcry_md_read(hd, GCRY_MD_SHA256), gcry_md_get_algo_dlen(GCRY_MD_SHA256));

    gcry_md_close(hd);
    hmac_creator_free(creator);

    return digest;
}













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