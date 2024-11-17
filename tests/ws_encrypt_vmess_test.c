//
// Created by lxyu on 24-10-20.
//
#include "ws_encrypt_vmess.h"
#include <check.h>
#include <stdlib.h>
#include <unistd.h>
#include "ws_bytearray.h"

/*
 * This test covers encryption and decryption on text.txt using AES-128-GCM algorithm.
 * The key and IV are created manually.
 */
START_TEST(text_encrypt_aes_128_gcm_no_ad) {
        gcry_error_t err = 0;

        /* Open a cipher, then setup cipher key and iv. Optionally, one could attach some AD to the encryption. */
        unsigned char key[AES_128_KEY_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                               0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

        unsigned char iv[GCM_IV_SIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                          0x08, 0x09, 0x0A, 0x0B};
        VMessDecoder *encoder = vmess_decoder_new(GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, key, iv, 0);
        VMessDecoder *decoder = vmess_decoder_new(GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, key, iv, 0);
        const char* in = "Hello World!";
        gsize outl = strlen(in) + 16;
        unsigned char* out = (unsigned char*) malloc(outl);
        err = vmess_byte_encryption(encoder, (unsigned char*)in, strlen(in), out, outl, NULL, 0);
        ck_assert_msg(err == 0, "Expect no error in message encryption.");

        unsigned char *decrypted_out = (unsigned char*) malloc(strlen(in));
        err = vmess_byte_decryption(decoder, out, outl, decrypted_out, strlen(in), NULL, 0);
        ck_assert_msg(err == 0, "Expect no error in message decryption.");

        ck_assert_msg(memcmp(decrypted_out, in, strlen(in)) == 0, "Expect the same content.");


        g_free(out);
        g_free(decrypted_out);
        vmess_decoder_free(encoder);
        vmess_decoder_free(decoder);
    }
END_TEST

/*
 * This test covers encryption and decryption on text.txt using AES-128-GCM algorithm.
 * The key and IV are created manually.
 */
START_TEST(text_encrypt_aes_128_gcm) {
        gcry_error_t err = 0;

        /* Open a cipher, then setup cipher key and iv. Optionally, one could attach some AD to the encryption. */
        unsigned char key[AES_128_KEY_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                               0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

        unsigned char iv[GCM_IV_SIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                          0x08, 0x09, 0x0A, 0x0B};
        VMessDecoder *encoder = vmess_decoder_new(GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, key, iv, 0);
        VMessDecoder *decoder = vmess_decoder_new(GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, key, iv, 0);

        const char *ad = "authentication";
        const char* in = "Hello World!";
        gsize outl = strlen(in) + 16;
        unsigned char* out = (unsigned char*) malloc(outl);
        err = vmess_byte_encryption(encoder, (unsigned char*)in, strlen(in), out, outl,
                                    (guchar*)ad, strlen(ad));
        ck_assert_msg(err == 0, "Expect no error in message encryption.");

        unsigned char *decrypted_out = (unsigned char*) malloc(strlen(in));
        err = vmess_byte_decryption(decoder, out, outl, decrypted_out, strlen(in),
                                    (guchar*)ad, strlen(ad));
        ck_assert_msg(err == 0, "Expect no error in message dncryption.");

        ck_assert_msg(memcmp(decrypted_out, in, strlen(in)) == 0, "Expect the same content.");


        g_free(out);
        g_free(decrypted_out);
        vmess_decoder_free(encoder);
        vmess_decoder_free(decoder);
    }
END_TEST

START_TEST(test_request_order){
        guint expect[16] = {0, 4, 3, 4, 2, 4, 3, 4, 1, 4, 3, 4, 2, 4, 3, 4};
        guint *actual = request_order(5);
        ck_assert_msg(memcmp(expect, actual, 16*sizeof(guint)) == 0,
                      "Expect expect == actual.");

        g_free(actual);
    }
END_TEST

START_TEST(test_hmac_digest_on_copy){
        const char *msg = "I think hashing is a great technique for data integrity check.";
        const char *salt = "Salt";
        guchar *actual = malloc(gcry_md_get_algo_dlen(GCRY_MD_SHA256));
        gcry_md_hd_t hd;
        gcry_md_open(&hd, GCRY_MD_SHA256, 0);
        gcry_md_write(hd, salt, strlen(salt));

        hmac_digest_on_copy(hd, msg, strlen(msg), actual);
        gcry_md_write(hd, msg, strlen(msg));
        guchar *expect = gcry_md_read(hd, GCRY_MD_SHA256);

        ck_assert_msg(memcmp(expect, actual, gcry_md_get_algo_dlen(GCRY_MD_SHA256)) == 0,
                      "Expect expect == actual.");

        gcry_md_close(hd);
        g_free(actual);
    }
END_TEST

/*
 * This test covers a simple HMAC with only SHA-256 component, the expected
 * value is drawn from its Golang implementation.
 *
 * Since we only wrap one layer hash in this test, it should have equivalent
 * effect as direct SHA-256 computing.
 */
START_TEST(test_hmac_creator_simple) {
        gcry_md_hd_t sha_hd;
        gcry_error_t err = 0;

        HMACCreator* creator = hmac_creator_new(NULL, (const guchar*)kdfSaltConstVMessAEADKDF, strlen(kdfSaltConstVMessAEADKDF));
        /* Setup keys for the HMAC */
        err = hmac_create(creator);
        ck_assert_msg(err == 0, "Expect no error in creating HMAC function, error: %s", gcry_strerror(err));

        const char* msg = "I think hashing is a great technique for data integrity check.";

        HMACDigester *digester = hmac_digester_new(creator);
        guchar* actual = malloc(gcry_md_get_algo_dlen(GCRY_MD_SHA256));
        err = hmac_digest(digester, msg, strlen(msg), actual);
        ck_assert_msg(err == 0, "Expect no error in creating HMAC function, error: %s", gcry_strerror(err));

        gcry_md_open(&sha_hd, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
        gcry_md_setkey(sha_hd, kdfSaltConstVMessAEADKDF, strlen(kdfSaltConstVMessAEADKDF));
        gcry_md_write(sha_hd, (const guchar*)msg, strlen(msg));
        unsigned char* expect = gcry_md_read(sha_hd, GCRY_MD_SHA256);

        char expect_msg[512], actual_msg[512];
        to_hex(expect, gcry_md_get_algo_dlen(GCRY_MD_SHA256),expect_msg);
        to_hex(actual, gcry_md_get_algo_dlen(GCRY_MD_SHA256),actual_msg);
        ck_assert_msg(strcmp(expect_msg, actual_msg) == 0,
                      "Expect expect == actual, but got\n"
                      "Expect: %s\n"
                      "Actual: %s", expect_msg, actual_msg);

        const char* golang_msg = "40FFA23BFDF4542C77BBCB2B56E98E04B33E417DB208914D58AEE8FA4CA65857";
        ck_assert_msg(strcmp(golang_msg, actual_msg) == 0,
                      "Expect expect == actual, but got\n"
                      "Expect: %s\n"
                      "Actual: %s", golang_msg, actual_msg);

        gcry_md_close(sha_hd);
        g_free(actual);
        hmac_creator_free(creator);
        hmac_digester_free(digester);
    }
END_TEST

/*
 * This test covers a chained HMAC with 2 layers with only SHA-256 component,
 * the expected value is drawn from its Golang implementation.
 */
START_TEST(test_hmac_creator_1) {
        gcry_error_t err = 0;
        const char* salt = "Child Salt";
        HMACCreator* creator_parent = hmac_creator_new(NULL, (const guchar*)kdfSaltConstVMessAEADKDF, strlen(kdfSaltConstVMessAEADKDF));
        HMACCreator* creator = hmac_creator_new(creator_parent, (const guchar*)salt, strlen(salt));
        /* Setup keys for the HMAC */
        err = hmac_create(creator);
        ck_assert_msg(err == 0, "Expect no error in creating HMAC function, error: %s", gcry_strerror(err));

        const char* msg = "I think hashing is a great technique for data integrity check.";

        HMACDigester *digester = hmac_digester_new(creator);
        guchar* actual = malloc(gcry_md_get_algo_dlen(GCRY_MD_SHA256));
        err = hmac_digest(digester, msg, strlen(msg), actual);
        ck_assert_msg(err == 0, "Expect no error in creating HMAC function, error: %s", gcry_strerror(err));

        char actual_msg[512];
        to_hex(actual, gcry_md_get_algo_dlen(GCRY_MD_SHA256),actual_msg);
        const char* golang_msg = "5B656DE5A1E8973C08CD151D2C13A5641581775FA56FCBF6A086D673B654108E";
        ck_assert_msg(strcmp(golang_msg, actual_msg) == 0,
                      "Expect expect == actual, but got\n"
                      "Expect: %s\n"
                      "Actual: %s", golang_msg, actual_msg);

        g_free(actual);
        hmac_creator_free(creator);
        hmac_digester_free(digester);
    }
END_TEST

/*
 * This test covers a chained HMAC with 3 layers with only SHA-256 component,
 * the expected value is drawn from its Golang implementation.
 *
 * This case is the same as the KDF used for VMess key derivation, but we manually
 * create it for validation.
 */
START_TEST(test_hmac_creator_2) {
        gcry_error_t err = 0;
        const char* child_salt = "Child Salt";
        const char* child_child_salt = "Child Child Salt";
        HMACCreator* creator_parent_parent = hmac_creator_new(NULL, (const guchar*)kdfSaltConstVMessAEADKDF, strlen(kdfSaltConstVMessAEADKDF));
        HMACCreator* creator_parent = hmac_creator_new(creator_parent_parent, (const guchar*)child_salt, strlen(child_salt));
        HMACCreator* creator = hmac_creator_new(creator_parent, (const guchar*)child_child_salt, strlen(child_child_salt));
        /* Setup keys for the HMAC */
        err = hmac_create(creator);
        ck_assert_msg(err == 0, "Expect no error in creating HMAC function, error: %s", gcry_strerror(err));

        const char* msg = "I think hashing is a great technique for data integrity check.";

        HMACDigester *digester = hmac_digester_new(creator);
        guchar* actual = malloc(gcry_md_get_algo_dlen(GCRY_MD_SHA256));
        err = hmac_digest(digester, msg, strlen(msg), actual);
        ck_assert_msg(err == 0, "Expect no error in creating HMAC function, error: %s", gcry_strerror(err));

        char actual_msg[512];
        to_hex(actual, gcry_md_get_algo_dlen(GCRY_MD_SHA256),actual_msg);
        const char* golang_msg = "AF1FBE053F3B85CD6F342EFE430142467397E826FEB4DEB8C418135A7512158B";
        ck_assert_msg(strcmp(golang_msg, actual_msg) == 0,
                      "Expect expect == actual, but got\n"
                      "Expect: %s\n"
                      "Actual: %s", golang_msg, actual_msg);

        g_free(actual);
        hmac_creator_free(creator);
        hmac_digester_free(digester);
    }
END_TEST


/*
 * This test should be equivalent to test test_hmac_creator_simple
 */
START_TEST(test_kdf_simple) {
        const char* key = "I think hashing is a great technique for data integrity check.";

        guchar* actual = vmess_kdf((const guchar*)key, strlen(key), 0);
        char actual_msg[512];
        to_hex(actual, gcry_md_get_algo_dlen(GCRY_MD_SHA256),actual_msg);

        /* As a further validation, compare the kdf result of C implementation with that of the Golang version. */
        const char* golang_msg = "40FFA23BFDF4542C77BBCB2B56E98E04B33E417DB208914D58AEE8FA4CA65857";
        ck_assert_msg(strcmp(golang_msg, actual_msg) == 0,
                      "Expect expect == actual, but got\n"
                      "Expect: %s\n"
                      "Actual: %s", golang_msg, actual_msg);
        g_free(actual);
}
END_TEST

/*
 * This test covers KDF with multiple keys, which should be equivalent to the digest of
 * nested HMAC.
 */
START_TEST(test_kdf){
        /* Note that key here is the message written to HMAC, the name 'key' is a convention for kdf */
        const char* key = "I think hashing is a great technique for data integrity check.";

        /* Fetch the result of kdf */
        guchar* kdf_result = vmess_kdf((const guchar*)key, strlen(key), 3,
                                       "Child Salt",
                                       "Child Child Salt",
                                       "Child Child Child Salt");
        char kdf_msg[512];
        to_hex(kdf_result, gcry_md_get_algo_dlen(GCRY_MD_SHA256),kdf_msg);

        /* As a further validation, compare the kdf result of C implementation with that of the Golang version. */
        const char* golang_result_msg = "89F3D50BAB3EE05B6A7F4C1EE1007CDC4527B940B01F747E970F187C640D7516";
        ck_assert_msg(strcmp(golang_result_msg, kdf_msg) == 0,
                      "Expect expect == actual, but got\n"
                      "Expect: %s\n"
                      "Actual: %s", golang_result_msg, kdf_msg);

        g_free(kdf_result);
    }
END_TEST

/*
 * This test covers the entire encryption and decryption processes of VMess,
 * including key derive, AEAD encryption/decryption and tag validation.
 */
START_TEST(test_vmess_aead_encryption_for_length){
        /*************************** Data Preparation *****************************/
        const char* key = "I think hashing is a great technique for data integrity check.";

        const char* data = "This is the data to be protected by VMess protocol, we make "
                           "it longer for generic encryption purpose. "
                           "In this test, AEAD is enabled since it is required by the "
                           "specification by default. After decryption, the decrypted data "
                           "should be correspondent with that before encryption.";

        /* generated ID should be 16 bytes long */
        const char* generatedAuthID = "1145141919810AAA";
        /* Connection nonce should be 8 bytes long */
        const char* connectionNonce = "HengHeng";
        /************************* Data Preparation Ends **************************/

        /********************** Key Derivation *********************/
        guint aeadPayloadLengthSize = 2;
        guchar *aeadPayloadLengthSerializedByte = malloc(aeadPayloadLengthSize);
        guint16 aeadPayloadLength = strlen(data);
        /* Clash implementation put integer into bytes using Big Endian order */
        put_uint16_be(aeadPayloadLength, aeadPayloadLengthSerializedByte);

        guint out_len = aeadPayloadLengthSize + GCM_TAG_SIZE;
        guchar *out = malloc(out_len);

        guchar *payloadHeaderLengthAEADKey = malloc(AES_128_KEY_SIZE);
        guchar *payloadHeaderLengthAEADNonce = malloc(GCM_IV_SIZE);
        guchar *tmp_derived_key;

        {
            tmp_derived_key = vmess_kdf(key, strlen(key), 3,
                                        kdfSaltConstVMessHeaderPayloadLengthAEADKey, generatedAuthID, connectionNonce);
            memcpy(payloadHeaderLengthAEADKey, tmp_derived_key, AES_128_KEY_SIZE);
            g_free(tmp_derived_key);

            tmp_derived_key = vmess_kdf(key, strlen(key), 3,
                      kdfSaltConstVMessHeaderPayloadLengthAEADIV, generatedAuthID, connectionNonce);
            memcpy(payloadHeaderLengthAEADNonce, tmp_derived_key, GCM_IV_SIZE);
            g_free(tmp_derived_key);
        }

        VMessDecoder *payloadHeaderLengthAEADEncoder = vmess_decoder_new(GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM,
                                                                         payloadHeaderLengthAEADKey,
                                                                         payloadHeaderLengthAEADNonce,
                                                                         0);

        vmess_byte_encryption(payloadHeaderLengthAEADEncoder,
                              aeadPayloadLengthSerializedByte, aeadPayloadLengthSize,
                              out, out_len,
                              generatedAuthID, strlen(generatedAuthID));

        /******************** Key Derivation Ends ******************/

        char out_msg[2 * out_len];
        to_hex(out, out_len,out_msg);
        /* As a further validation, compare the kdf result of C implementation with that of the Golang version. */
        const char* golang_result_msg = "54CFCD4EC10A284B56B35F8D49BFC6C8EA13";
        ck_assert_msg(strcmp(golang_result_msg, out_msg) == 0,
                      "Expect expect == actual, but got\n"
                      "Expect: %s\n"
                      "Actual: %s", golang_result_msg, out_msg);

        g_free(out);
        g_free(aeadPayloadLengthSerializedByte);
        g_free(payloadHeaderLengthAEADKey);
        g_free(payloadHeaderLengthAEADNonce);
        vmess_decoder_free(payloadHeaderLengthAEADEncoder);
    }
END_TEST

Suite *encrypt_suite(void) {
    Suite *s = suite_create("Encrypt Suite");

    // Add the setup and teardown functions to the test suite
    TCase *tc_core = tcase_create("Core");

    // Add test cases that will use the shared variable
    tcase_add_test(tc_core, text_encrypt_aes_128_gcm_no_ad);
    tcase_add_test(tc_core, text_encrypt_aes_128_gcm);
    tcase_add_test(tc_core, test_hmac_creator_simple);
    tcase_add_test(tc_core, test_hmac_creator_1);
    tcase_add_test(tc_core, test_hmac_creator_2);
    tcase_add_test(tc_core, test_request_order);
    tcase_add_test(tc_core, test_hmac_digest_on_copy);
    tcase_add_test(tc_core, test_kdf_simple);
    tcase_add_test(tc_core, test_kdf);
    tcase_add_test(tc_core, test_vmess_aead_encryption_for_length);

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