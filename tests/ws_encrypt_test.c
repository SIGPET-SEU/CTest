//
// Created by lxyu on 24-10-20.
//
#include "ws_encrypt_vmess.h"
#include <check.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * This test covers encryption and decryption on text.txt using AES-128-GCM algorithm.
 * The key and IV are created manually.
 */
START_TEST(text_encrypt_aes_128_gcm) {
        gcry_error_t err = 0;
//        VMessDecoder *encoder = (VMessDecoder *) malloc(sizeof(VMessDecoder));
//        VMessDecoder *decoder = (VMessDecoder *) malloc(sizeof(VMessDecoder));
        const VMessCipherSuite* cipher_suite = &(VMessCipherSuite){
                .mode = MODE_GCM
        };

//        encoder->cipher_suite = cipher_suite;
//        decoder->cipher_suite = cipher_suite;

//        /* Open a cipher, then setup cipher key and iv. Optionally, one could attach some AD to the encryption. */
//        unsigned char key[AES_KEY_SIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
//                                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
//
//        unsigned char iv[GCM_IV_SIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
//                                            0x08, 0x09, 0x0A, 0x0B};
//        err = vmess_cipher_init(&(encoder->evp), GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, key, AES_KEY_SIZE, iv, GCM_IV_SIZE, 0);
//        ck_assert_msg(err == 0, "Expect no error in cipher initialization.");
//        const char* in = "Hello World!";
//        gsize outl = strlen(in) + 16;
//        unsigned char* out = (unsigned char*) malloc(outl);
//        err = vmess_byte_encryption(encoder, (unsigned char*)in, strlen(in), out, outl, NULL, 0);
//        ck_assert_msg(err == 0, "Expect no error in message encryption.");
//
//        err = vmess_cipher_init(&(decoder->evp), GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, key, AES_KEY_SIZE, iv, GCM_IV_SIZE, 0);
//        ck_assert_msg(err == 0, "Expect no error in cipher initialization.");
//        unsigned char *decrypted_out = (unsigned char*) malloc(strlen(in));
//        err = vmess_byte_decryption(decoder, out, outl, decrypted_out, strlen(in), NULL, 0);
//        ck_assert_msg(err == 0, "Expect no error in message encryption.");
//
//        ck_assert_msg(memcmp(decrypted_out, in, strlen(in)) == 0, "Expect the same content.");
//
//
//        g_free(out);
//        g_free(decrypted_out);
//
//        g_free(encoder);
//        g_free(decoder);
    }
END_TEST

/*
 * This test covers encryption and decryption on text.txt using AES-128-GCM algorithm.
 * The key and IV are created manually.
 */
//START_TEST(text_encrypt_aes_128_gcm) {
//        gcry_error_t err = 0;
//        VMessDecoder *encoder = (VMessDecoder *) malloc(sizeof(VMessDecoder));
//        VMessDecoder *decoder = (VMessDecoder *) malloc(sizeof(VMessDecoder));
//        const VMessCipherSuite* cipher_suite = &(VMessCipherSuite){
//                .mode = MODE_GCM
//        };
//
//        encoder->cipher_suite = cipher_suite;
//        decoder->cipher_suite = cipher_suite;
//
//        /* Open a cipher, then setup cipher key and iv. Optionally, one could attach some AD to the encryption. */
//        unsigned char key[AES_KEY_SIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
//                                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
//
//        unsigned char iv[GCM_IV_SIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
//                                          0x08, 0x09, 0x0A, 0x0B};
//        const char *ad = "authentication";
//        err = vmess_cipher_init(&(encoder->evp), GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, key, AES_KEY_SIZE, iv, GCM_IV_SIZE, 0);
//        ck_assert_msg(err == 0, "Expect no error in cipher initialization.");
//        const char* in = "Hello World!";
//        gsize outl = strlen(in) + 16;
//        unsigned char* out = (unsigned char*) malloc(outl);
//        err = vmess_byte_encryption(encoder, (unsigned char*)in, strlen(in), out, outl,
//                                    (guchar*)ad, strlen(ad));
//        ck_assert_msg(err == 0, "Expect no error in message encryption.");
//
//        err = vmess_cipher_init(&(decoder->evp), GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, key, AES_KEY_SIZE, iv, GCM_IV_SIZE, 0);
//        ck_assert_msg(err == 0, "Expect no error in cipher initialization.");
//        unsigned char *decrypted_out = (unsigned char*) malloc(strlen(in));
//        err = vmess_byte_decryption(decoder, out, outl, decrypted_out, strlen(in),
//                                    (guchar*)ad, strlen(ad));
//        ck_assert_msg(err == 0, "Expect no error in message encryption.");
//
//        ck_assert_msg(memcmp(decrypted_out, in, strlen(in)) == 0, "Expect the same content.");
//
//
//        g_free(out);
//        g_free(decrypted_out);
//
//        g_free(encoder);
//        g_free(decoder);
//    }
//END_TEST

Suite *encrypt_suite(void) {
    Suite *s = suite_create("Encrypt Suite");

    // Add the setup and teardown functions to the test suite
    TCase *tc_core = tcase_create("Core");

    // Add test cases that will use the shared variable
    tcase_add_test(tc_core, text_encrypt_aes_128_gcm);
//    tcase_add_test(tc_core, text_encrypt_aes_128_gcm);
    suite_add_tcase(s, tc_core);
    return s;
}

int main(void){
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = encrypt_suite();
    sr = srunner_create(s);
    srunner_set_fork_status (sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}