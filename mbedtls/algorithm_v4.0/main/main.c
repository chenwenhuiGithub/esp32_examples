#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "psa/crypto.h"
#include "mbedtls/base64.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/x509_crt.h"


typedef enum {
    ALG_RSA_PKCS1V15_CRYPT,
    ALG_RSA_PKCS1V15_SIGN,
    ALG_RSA_PKCS1V21_CRYPT,
    ALG_RSA_PKCS1V21_SIGN,
    ALG_ECC_SIGN
} alg_usage_t;

#define CONFIG_USE_MULTIPART_API                0
#define CONFIG_USE_FORMAT_PEM                   1
#define CONFIG_AES_KEY_LEN                      16
#define CONFIG_AES_AEAD_NONCE_LEN               12
#define CONFIG_AES_AEAD_TAG_LEN                 16
#define CONFIG_RSA_KEY_BITS                     2048
#define CONFIG_RSA_CIPHER_LEN                   (CONFIG_RSA_KEY_BITS / 8)
#define CONFIG_ECC_KEY_BITS                     256


static const char *TAG = "algorithm";

void gen_random(uint8_t *data, uint32_t len) {
    psa_generate_random(data, len);
}

void calc_md5(uint8_t *input, uint32_t input_len, uint8_t *hash, uint32_t hash_size, uint32_t *hash_len) {
#if CONFIG_USE_MULTIPART_API == 1
    psa_hash_operation_t hash_op = PSA_HASH_OPERATION_INIT;

    psa_hash_setup(&hash_op, PSA_ALG_MD5);
    psa_hash_update(&hash_op, input, input_len);
    psa_hash_finish(&hash_op, hash, hash_size, (size_t *)hash_len); // PSA_HASH_LENGTH(PSA_ALG_MD5) = 16B
    psa_hash_abort(&hash_op);
#else
    psa_hash_compute(PSA_ALG_MD5, input, input_len, hash, hash_size, (size_t *)hash_len);
#endif
}

void calc_sha1(uint8_t *input, uint32_t input_len, uint8_t *hash, uint32_t hash_size, uint32_t *hash_len) {
#if CONFIG_USE_MULTIPART_API == 1
    psa_hash_operation_t hash_op = PSA_HASH_OPERATION_INIT;

    psa_hash_setup(&hash_op, PSA_ALG_SHA_1);
    psa_hash_update(&hash_op, input, input_len);
    psa_hash_finish(&hash_op, hash, hash_size, (size_t *)hash_len); // PSA_HASH_LENGTH(PSA_ALG_SHA_1) = 20B
    psa_hash_abort(&hash_op);
#else
    psa_hash_compute(PSA_ALG_SHA_1, input, input_len, hash, hash_size, (size_t *)hash_len);
#endif
}

void calc_sha256(uint8_t *input, uint32_t input_len, uint8_t *hash, uint32_t hash_size, uint32_t *hash_len) {
#if CONFIG_USE_MULTIPART_API == 1
    psa_hash_operation_t hash_op = PSA_HASH_OPERATION_INIT;

    psa_hash_setup(&hash_op, PSA_ALG_SHA_256);
    psa_hash_update(&hash_op, input, input_len);
    psa_hash_finish(&hash_op, hash, hash_size, (size_t *)hash_len); // PSA_HASH_LENGTH(PSA_ALG_SHA_256) = 32B
    psa_hash_abort(&hash_op);
#else
    psa_hash_compute(PSA_ALG_SHA_256, input, input_len, hash, hash_size, (size_t *)hash_len);
#endif
}

void calc_hmac256(uint8_t *input, uint32_t input_len, uint8_t *key, uint32_t key_len, uint8_t *hmac, uint32_t hmac_size, uint32_t *hmac_len) {
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;

    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&key_attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&key_attr, key_len * 8);
    psa_import_key(&key_attr, key, key_len, &key_id); // variable length

#if CONFIG_USE_MULTIPART_API == 1
    psa_mac_operation_t mac_op = PSA_MAC_OPERATION_INIT;

    psa_mac_sign_setup(&mac_op, key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_mac_update(&mac_op, input, input_len);
    psa_mac_sign_finish(&mac_op, hmac, hmac_size, (size_t *)hmac_len); // PSA_MAC_LENGTH(key_type, key_bits, alg) = 32B
    psa_mac_abort(&mac_op);
#else
    psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256), input, input_len, hmac, hmac_size, (size_t *)hmac_len);
#endif
    psa_destroy_key(key_id);
}

void calc_cmac(uint8_t *input, uint32_t input_len, uint8_t *key, uint32_t key_len, uint8_t *cmac, uint32_t cmac_size, uint32_t *cmac_len) {
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;

    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&key_attr, PSA_ALG_CMAC);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&key_attr, key_len * 8);
    psa_import_key(&key_attr, key, key_len, &key_id); // AES-128:16B, AES-256:32B

#if CONFIG_USE_MULTIPART_API == 1
    psa_mac_operation_t mac_op = PSA_MAC_OPERATION_INIT;

    psa_mac_sign_setup(&mac_op, key_id, PSA_ALG_CMAC);
    psa_mac_update(&mac_op, input, input_len);
    psa_mac_sign_finish(&mac_op, cmac, cmac_size, (size_t *)cmac_len); // PSA_MAC_LENGTH(key_type, key_bits, alg) = 16B
    psa_mac_abort(&mac_op);
#else
    psa_mac_compute(key_id, PSA_ALG_CMAC, input, input_len, cmac, cmac_size, (size_t *)cmac_len);
#endif
    psa_destroy_key(key_id);
}

void aes_cbc_encrypt(uint8_t *input, uint32_t input_len, uint8_t *key, uint32_t key_len, uint8_t *iv, uint32_t iv_len, uint8_t *output, uint32_t output_size, uint32_t *output_len) {
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;

    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&key_attr, PSA_ALG_CBC_PKCS7);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&key_attr, key_len * 8);
    psa_import_key(&key_attr, key, key_len, &key_id); // AES-128:16B, AES-256:32B

#if CONFIG_USE_MULTIPART_API == 1
    psa_cipher_operation_t cipher_op = PSA_CIPHER_OPERATION_INIT;
    size_t enc_len = 0, total_enc_len = 0;

    psa_cipher_encrypt_setup(&cipher_op, key_id, PSA_ALG_CBC_PKCS7);
    psa_cipher_set_iv(&cipher_op, iv, iv_len); // BLOCK_SIZE(16B)
    psa_cipher_update(&cipher_op, input, input_len, output, output_size, &enc_len); // process first input_len - (input_len % BLOCK_SIZE)
    total_enc_len = enc_len;
    psa_cipher_finish(&cipher_op, output + total_enc_len, output_size - total_enc_len, &enc_len); // process last input_len % BLOCK_SIZE
    total_enc_len += enc_len;
    psa_cipher_abort(&cipher_op);
    *output_len = total_enc_len; // [input_len / BLOCK_SIZE] * BLOCK_SIZE
#else
    (void)iv;
    (void)iv_len;
    psa_cipher_encrypt(key_id, PSA_ALG_CBC_PKCS7, input, input_len, output, output_size, (size_t *)output_len); // iv_len(random generate) + [input_len / BLOCK_SIZE] * BLOCK_SIZE
#endif
    psa_destroy_key(key_id);
}

void aes_cbc_decrypt(uint8_t *input, uint32_t input_len, uint8_t *key, uint32_t key_len, uint8_t *iv, uint32_t iv_len, uint8_t *output, uint32_t output_size, uint32_t *output_len) {
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;

    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&key_attr, PSA_ALG_CBC_PKCS7);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&key_attr, key_len * 8);
    psa_import_key(&key_attr, key, key_len, &key_id); // AES-128:16B, AES-256:32B

#if CONFIG_USE_MULTIPART_API == 1
    psa_cipher_operation_t cipher_op = PSA_CIPHER_OPERATION_INIT;
    size_t dec_len = 0, total_dec_len = 0;

    psa_cipher_decrypt_setup(&cipher_op, key_id, PSA_ALG_CBC_PKCS7);
    psa_cipher_set_iv(&cipher_op, iv, iv_len); // BLOCK_SIZE(16B)
    psa_cipher_update(&cipher_op, input, input_len, output, output_size, &dec_len); // process total N * BLOCK_SIZE
    total_dec_len = dec_len;
    psa_cipher_finish(&cipher_op, output + total_dec_len, output_size - total_dec_len, &dec_len); // process null
    total_dec_len += dec_len;
    psa_cipher_abort(&cipher_op);
    *output_len = total_dec_len; // plaintext length
#else
    (void)iv;
    (void)iv_len;
    psa_cipher_decrypt(key_id, PSA_ALG_CBC_PKCS7, input, input_len, output, output_size, (size_t *)output_len); // plaintext length
#endif
    psa_destroy_key(key_id);
}

void aes_ctr_encrypt(uint8_t *input, uint32_t input_len, uint8_t *key, uint32_t key_len, uint8_t *iv, uint32_t iv_len, uint8_t *output, uint32_t output_size, uint32_t *output_len) {
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;

    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&key_attr, PSA_ALG_CTR);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&key_attr, key_len * 8);
    psa_import_key(&key_attr, key, key_len, &key_id); // AES-128:16B, AES-256:32B

#if CONFIG_USE_MULTIPART_API == 1
    psa_cipher_operation_t cipher_op = PSA_CIPHER_OPERATION_INIT;
    size_t enc_len = 0, total_enc_len = 0;

    psa_cipher_encrypt_setup(&cipher_op, key_id, PSA_ALG_CTR);
    psa_cipher_set_iv(&cipher_op, iv, iv_len); // BLOCK_SIZE(16B)
    psa_cipher_update(&cipher_op, input, input_len, output, output_size, &enc_len); // process first input_len - (input_len % BLOCK_SIZE)
    total_enc_len = enc_len;
    psa_cipher_finish(&cipher_op, output + total_enc_len, output_size - total_enc_len, &enc_len); // process last input_len % BLOCK_SIZE
    total_enc_len += enc_len;
    psa_cipher_abort(&cipher_op);
    *output_len = total_enc_len; // no padding, plaintext length
#else
    (void)iv;
    (void)iv_len;
    psa_cipher_encrypt(key_id, PSA_ALG_CTR, input, input_len, output, output_size, (size_t *)output_len); // no padding, iv_len(random generate) + plaintext length
#endif    
    psa_destroy_key(key_id);
}

void aes_ctr_decrypt(uint8_t *input, uint32_t input_len, uint8_t *key, uint32_t key_len, uint8_t *iv, uint32_t iv_len, uint8_t *output, uint32_t output_size, uint32_t *output_len) {
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;

    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&key_attr, PSA_ALG_CTR);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&key_attr, key_len * 8);
    psa_import_key(&key_attr, key, key_len, &key_id); // AES-128:16B, AES-256:32B

#if CONFIG_USE_MULTIPART_API == 1
    psa_cipher_operation_t cipher_op = PSA_CIPHER_OPERATION_INIT;
    size_t dec_len = 0, total_dec_len = 0;

    psa_cipher_decrypt_setup(&cipher_op, key_id, PSA_ALG_CTR);
    psa_cipher_set_iv(&cipher_op, iv, iv_len); // BLOCK_SIZE(16B)
    psa_cipher_update(&cipher_op, input, input_len, output, output_size, &dec_len); // process first input_len - (input_len % BLOCK_SIZE)
    total_dec_len = dec_len;
    psa_cipher_finish(&cipher_op, output + total_dec_len, output_size - total_dec_len, &dec_len); // process last input_len % BLOCK_SIZE
    total_dec_len += dec_len;
    psa_cipher_abort(&cipher_op);
    *output_len = total_dec_len; // plaintext length
#else
    (void)iv;
    (void)iv_len;
    psa_cipher_decrypt(key_id, PSA_ALG_CTR, input, input_len, output, output_size, (size_t *)output_len); // plaintext length
#endif   
    psa_destroy_key(key_id);
}

#if CONFIG_USE_MULTIPART_API == 1
void aes_gcm_encrypt(uint8_t *input, uint32_t input_len, uint8_t *key, uint32_t key_len, uint8_t *nonce, uint32_t nonce_len, uint8_t *ad, uint32_t ad_len,
        uint8_t *output, uint32_t output_size, uint32_t *output_len, uint8_t *tag, uint32_t tag_size, uint32_t *tag_len) {
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_aead_operation_t aead_op = PSA_AEAD_OPERATION_INIT;
    size_t enc_len = 0, total_enc_len = 0;
    
    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&key_attr, PSA_ALG_GCM);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&key_attr, key_len * 8);
    psa_import_key(&key_attr, key, key_len, &key_id); // AES-128:16B, AES-256:32B

    psa_aead_encrypt_setup(&aead_op, key_id, PSA_ALG_GCM);
    psa_aead_set_nonce(&aead_op, nonce, nonce_len); // variable length
    psa_aead_update_ad(&aead_op, ad, ad_len); // BLOCK_SIZE(16B)
    psa_aead_update(&aead_op, input, input_len, output, output_size, &enc_len); // process first input_len - (input_len % BLOCK_SIZE)
    total_enc_len = enc_len;
    psa_aead_finish(&aead_op, output + total_enc_len, output_size - total_enc_len, &enc_len, tag, tag_size, (size_t *)tag_len); // process last input_len % BLOCK_SIZE
    total_enc_len += enc_len;
    psa_aead_abort(&aead_op);
    psa_destroy_key(key_id);

    *output_len = total_enc_len; // no padding, plaintext length
}
#else
void aes_gcm_encrypt(uint8_t *input, uint32_t input_len, uint8_t *key, uint32_t key_len, uint8_t *nonce, uint32_t nonce_len, uint8_t *ad, uint32_t ad_len,
        uint32_t tag_len, uint8_t *output, uint32_t output_size, uint32_t *output_len) {
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_algorithm_t alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, tag_len);
    
    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&key_attr, alg);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&key_attr, key_len * 8);
    psa_import_key(&key_attr, key, key_len, &key_id); // AES-128:16B, AES-256:32B

    psa_aead_encrypt(key_id, alg, nonce, nonce_len, ad, ad_len, input, input_len, output, output_size, (size_t *)output_len); // no padding, input_len + tag_len
    psa_destroy_key(key_id);
}
#endif 

#if CONFIG_USE_MULTIPART_API == 1
int aes_gcm_decrypt(uint8_t *input, uint32_t input_len, uint8_t *key, uint32_t key_len, uint8_t *nonce, uint32_t nonce_len, uint8_t *ad, uint32_t ad_len,
        uint8_t *tag, uint32_t tag_len, uint8_t *output, uint32_t output_size, uint32_t *output_len) {
    psa_status_t status = PSA_SUCCESS;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_aead_operation_t aead_op = PSA_AEAD_OPERATION_INIT;
    size_t dec_len = 0, total_dec_len = 0;
    
    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&key_attr, PSA_ALG_GCM);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&key_attr, key_len * 8);
    psa_import_key(&key_attr, key, key_len, &key_id); // AES-128:16B, AES-256:32B

    psa_aead_decrypt_setup(&aead_op, key_id, PSA_ALG_GCM);
    psa_aead_set_nonce(&aead_op, nonce, nonce_len); // variable length
    psa_aead_update_ad(&aead_op, ad, ad_len); // BLOCK_SIZE(16B)
    psa_aead_update(&aead_op, input, input_len, output, output_size, &dec_len); // process first input_len - (input_len % BLOCK_SIZE)
    total_dec_len = dec_len;
    status = psa_aead_verify(&aead_op, output + total_dec_len, output_size - total_dec_len, &dec_len, tag, tag_len); // process last input_len % BLOCK_SIZE
    total_dec_len += dec_len;
    psa_aead_abort(&aead_op);
    psa_destroy_key(key_id);

    *output_len = total_dec_len; // no padding, plaintext length
    return status;
}
#else
int aes_gcm_decrypt(uint8_t *input, uint32_t input_len, uint8_t *key, uint32_t key_len, uint8_t *nonce, uint32_t nonce_len, uint8_t *ad, uint32_t ad_len,
        uint32_t tag_len, uint8_t *output, uint32_t output_size, uint32_t *output_len) {
    psa_status_t status = PSA_SUCCESS;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_algorithm_t alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, tag_len);
    
    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&key_attr, alg);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&key_attr, key_len * 8);
    psa_import_key(&key_attr, key, key_len, &key_id); // AES-128:16B, AES-256:32B

    status = psa_aead_decrypt(key_id, alg, nonce, nonce_len, ad, ad_len, input, input_len, output, output_size, (size_t *)output_len); // no padding, input_len - tag_len
    psa_destroy_key(key_id);

    return status;
}
#endif 

#if CONFIG_USE_MULTIPART_API == 1
void aes_ccm_encrypt(uint8_t *input, uint32_t input_len, uint8_t *key, uint32_t key_len, uint8_t *nonce, uint32_t nonce_len, uint8_t *ad, uint32_t ad_len,
        uint8_t *output, uint32_t output_size, uint32_t *output_len, uint8_t *tag, uint32_t tag_size, uint32_t *tag_len) {
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_aead_operation_t aead_op = PSA_AEAD_OPERATION_INIT;
    size_t enc_len = 0, total_enc_len = 0;

    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&key_attr, PSA_ALG_CCM);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&key_attr, key_len * 8);
    psa_import_key(&key_attr, key, key_len, &key_id); // AES-128:16B, AES-256:32B

    psa_aead_encrypt_setup(&aead_op, key_id, PSA_ALG_CCM);
    psa_aead_set_lengths(&aead_op, ad_len, input_len); // PSA_ALG_CCM required	
    psa_aead_set_nonce(&aead_op, nonce, nonce_len); // variable length
    psa_aead_update_ad(&aead_op, ad, ad_len); // BLOCK_SIZE(16B)
    psa_aead_update(&aead_op, input, input_len, output, output_size, &enc_len); // process first input_len - (input_len % BLOCK_SIZE)
    total_enc_len = enc_len;
    psa_aead_finish(&aead_op, output + total_enc_len, output_size - total_enc_len, &enc_len, tag, tag_size, (size_t *)tag_len); // process last input_len % BLOCK_SIZE
    total_enc_len += enc_len;
    psa_aead_abort(&aead_op);
    psa_destroy_key(key_id);

    *output_len = total_enc_len; // no padding, plaintext length
}
#else
void aes_ccm_encrypt(uint8_t *input, uint32_t input_len, uint8_t *key, uint32_t key_len, uint8_t *nonce, uint32_t nonce_len, uint8_t *ad, uint32_t ad_len,
        uint32_t tag_len, uint8_t *output, uint32_t output_size, uint32_t *output_len) {
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_algorithm_t alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, tag_len);

    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&key_attr, alg);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&key_attr, key_len * 8);
    psa_import_key(&key_attr, key, key_len, &key_id); // AES-128:16B, AES-256:32B

    psa_aead_encrypt(key_id, alg, nonce, nonce_len, ad, ad_len, input, input_len, output, output_size, (size_t *)output_len); // no padding, input_len + tag_len
    psa_destroy_key(key_id);
}
#endif

#if CONFIG_USE_MULTIPART_API == 1
int aes_ccm_decrypt(uint8_t *input, uint32_t input_len, uint8_t *key, uint32_t key_len, uint8_t *nonce, uint32_t nonce_len, uint8_t *ad, uint32_t ad_len,
        uint8_t *tag, uint32_t tag_len, uint8_t *output, uint32_t output_size, uint32_t *output_len) {
    psa_status_t status = PSA_SUCCESS;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_aead_operation_t aead_op = PSA_AEAD_OPERATION_INIT;
    size_t dec_len = 0, total_dec_len = 0;

    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&key_attr, PSA_ALG_CCM);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&key_attr, key_len * 8);
    psa_import_key(&key_attr, key, key_len, &key_id); // AES-128:16B, AES-256:32B

    psa_aead_decrypt_setup(&aead_op, key_id, PSA_ALG_CCM);
    psa_aead_set_lengths(&aead_op, ad_len, input_len); // PSA_ALG_CCM required	
    psa_aead_set_nonce(&aead_op, nonce, nonce_len); // variable length
    psa_aead_update_ad(&aead_op, ad, ad_len); // BLOCK_SIZE(16B)
    psa_aead_update(&aead_op, input, input_len, output, output_size, &dec_len); // process first input_len - (input_len % BLOCK_SIZE)
    total_dec_len = dec_len;
    status = psa_aead_verify(&aead_op, output + total_dec_len, output_size - total_dec_len, &dec_len, tag, tag_len); // process last input_len % BLOCK_SIZE
    total_dec_len += dec_len;
    psa_aead_abort(&aead_op);
    psa_destroy_key(key_id);

    *output_len = total_dec_len; // no padding, plaintext length
    return status;
}
#else
int aes_ccm_decrypt(uint8_t *input, uint32_t input_len, uint8_t *key, uint32_t key_len, uint8_t *nonce, uint32_t nonce_len, uint8_t *ad, uint32_t ad_len,
        uint32_t tag_len, uint8_t *output, uint32_t output_size, uint32_t *output_len) {
    psa_status_t status = PSA_SUCCESS;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_algorithm_t alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, tag_len);

    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&key_attr, alg);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&key_attr, key_len * 8);
    psa_import_key(&key_attr, key, key_len, &key_id); // AES-128:16B, AES-256:32B

    status = psa_aead_decrypt(key_id, alg, nonce, nonce_len, ad, ad_len, input, input_len, output, output_size, (size_t *)output_len); // no padding, input_len - tag_len
    psa_destroy_key(key_id);

    return status;
}
#endif

void rsa_gen_keypair(alg_usage_t useage, uint8_t *pubkey, uint32_t pubkey_size, uint32_t *pubkey_len, uint8_t *privkey, uint32_t privkey_size, uint32_t *privkey_len) {
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_algorithm_t alg = 0;

    if (ALG_RSA_PKCS1V15_CRYPT == useage) {
        alg = PSA_ALG_RSA_PKCS1V15_CRYPT;
    } else if (ALG_RSA_PKCS1V15_SIGN == useage) {
        alg = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256);
    } else if (ALG_RSA_PKCS1V21_CRYPT == useage) {
        alg = PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256);
    } else if (ALG_RSA_PKCS1V21_SIGN == useage) {
        alg = PSA_ALG_RSA_PSS(PSA_ALG_SHA_256);
    }
    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&key_attr, alg);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&key_attr, CONFIG_RSA_KEY_BITS);
    psa_generate_key(&key_attr, &key_id);
    
    psa_export_public_key(key_id, pubkey, pubkey_size, (size_t *)pubkey_len); // der
    psa_export_key(key_id, privkey, privkey_size, (size_t *)privkey_len); // der
    psa_destroy_key(key_id);
}

void rsa_encrypt(alg_usage_t useage, uint8_t *input, uint32_t input_len, uint8_t *pubkey, uint32_t pubkey_len, uint8_t *output, uint32_t output_size, uint32_t *output_len) {
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_algorithm_t alg = 0;
    uint8_t aes_key[CONFIG_AES_KEY_LEN] = {0};
    uint8_t aes_nonce[CONFIG_AES_AEAD_NONCE_LEN] = {0};
    uint32_t aes_enc_len = 0, rsa_enc_len = 0;

    gen_random(aes_key, sizeof(aes_key));
    gen_random(aes_nonce, sizeof(aes_nonce));

    if (ALG_RSA_PKCS1V15_CRYPT == useage) {
        alg = PSA_ALG_RSA_PKCS1V15_CRYPT;
    } else if (ALG_RSA_PKCS1V21_CRYPT == useage) {
        alg = PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256);
    }
    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&key_attr, alg);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
    psa_set_key_bits(&key_attr, CONFIG_RSA_KEY_BITS);
    psa_import_key(&key_attr, pubkey, pubkey_len, &key_id); // der
    
    // PKCS1V15: input_len <= (KEY_BITS / 8) - 11B(padding)
    // PKCS1V21: input_len <= (KEY_BITS / 8) - 66B(padding)
    psa_asymmetric_encrypt(key_id, alg, aes_key, sizeof(aes_key), NULL, 0, output, CONFIG_RSA_CIPHER_LEN, (size_t *)&rsa_enc_len); // KEY_BITS / 8
    memcpy(output + CONFIG_RSA_CIPHER_LEN, aes_nonce, sizeof(aes_nonce));
    aes_ccm_encrypt(input, input_len, aes_key, sizeof(aes_key), aes_nonce, sizeof(aes_nonce), NULL, 0, CONFIG_AES_AEAD_TAG_LEN,
        output + CONFIG_RSA_CIPHER_LEN + CONFIG_AES_AEAD_NONCE_LEN, output_size - CONFIG_RSA_CIPHER_LEN - CONFIG_AES_AEAD_NONCE_LEN, &aes_enc_len);
    psa_destroy_key(key_id);

    *output_len = CONFIG_RSA_CIPHER_LEN + CONFIG_AES_AEAD_NONCE_LEN + aes_enc_len;
}

void rsa_decrypt(alg_usage_t useage, uint8_t *input, uint32_t input_len, uint8_t *privkey, uint32_t privkey_len, uint8_t *output, uint32_t output_size, uint32_t *output_len) {
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_algorithm_t alg = 0;
    uint8_t aes_key[CONFIG_AES_KEY_LEN] = {0};
    uint8_t aes_nonce[CONFIG_AES_AEAD_NONCE_LEN] = {0};
    uint32_t rsa_dec_len = 0;

    if (ALG_RSA_PKCS1V15_CRYPT == useage) {
        alg = PSA_ALG_RSA_PKCS1V15_CRYPT;
    } else if (ALG_RSA_PKCS1V21_CRYPT == useage) {
        alg = PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256);
    }
    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&key_attr, alg);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&key_attr, CONFIG_RSA_KEY_BITS);
    psa_import_key(&key_attr, privkey, privkey_len, &key_id); // der
    
    // input_len = KEY_BITS / 8
    psa_asymmetric_decrypt(key_id, alg, input, CONFIG_RSA_CIPHER_LEN, NULL, 0, aes_key, CONFIG_AES_KEY_LEN, (size_t *)&rsa_dec_len); // plaintext length
    memcpy(aes_nonce, input + CONFIG_RSA_CIPHER_LEN, CONFIG_AES_AEAD_NONCE_LEN);
    aes_ccm_decrypt(input + CONFIG_RSA_CIPHER_LEN + CONFIG_AES_AEAD_NONCE_LEN, input_len - CONFIG_RSA_CIPHER_LEN - CONFIG_AES_AEAD_NONCE_LEN,
        aes_key, sizeof(aes_key), aes_nonce, sizeof(aes_nonce), NULL, 0, CONFIG_AES_AEAD_TAG_LEN, output, output_size, output_len);
    psa_destroy_key(key_id);
}

void rsa_sign(alg_usage_t useage, uint8_t *hash, uint32_t hash_len, uint8_t *privkey, uint32_t privkey_len, uint8_t *output, uint32_t output_size, uint32_t *output_len) {
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_algorithm_t alg = 0;

    if (ALG_RSA_PKCS1V15_SIGN == useage) {
        alg = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256);
    } else if (ALG_RSA_PKCS1V21_SIGN == useage) {
        alg = PSA_ALG_RSA_PSS(PSA_ALG_SHA_256);
    }
    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&key_attr, alg);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&key_attr, CONFIG_RSA_KEY_BITS);
    psa_import_key(&key_attr, privkey, privkey_len, &key_id); // der

    psa_sign_hash(key_id, alg, hash, hash_len, output, output_size, (size_t *)output_len); // KEY_BITS / 8
    psa_destroy_key(key_id);
}

int rsa_verify(alg_usage_t useage, uint8_t *hash, uint32_t hash_len, uint8_t *pubkey, uint32_t pubkey_len, uint8_t *signature, uint32_t signature_len) {
    psa_status_t status = PSA_SUCCESS;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_algorithm_t alg = 0;

    if (ALG_RSA_PKCS1V15_SIGN == useage) {
        alg = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256);
    } else if (ALG_RSA_PKCS1V21_SIGN == useage) {
        alg = PSA_ALG_RSA_PSS(PSA_ALG_SHA_256);
    }
    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&key_attr, alg);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
    psa_set_key_bits(&key_attr, CONFIG_RSA_KEY_BITS);
    psa_import_key(&key_attr, pubkey, pubkey_len, &key_id); // der

    status = psa_verify_hash(key_id, alg, hash, hash_len, signature, signature_len);
    psa_destroy_key(key_id);

    return status;
}

void ecc_gen_keypair(uint8_t *pubkey, uint32_t pubkey_size, uint32_t *pubkey_len, uint8_t *privkey, uint32_t privkey_size, uint32_t *privkey_len) {
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;

    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&key_attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&key_attr, CONFIG_ECC_KEY_BITS);
    psa_generate_key(&key_attr, &key_id);
    
    psa_export_public_key(key_id, pubkey, pubkey_size, (size_t *)pubkey_len); // der
    psa_export_key(key_id, privkey, privkey_size, (size_t *)privkey_len); // der
    psa_destroy_key(key_id);
}

void ecc_sign(uint8_t *hash, uint32_t hash_len, uint8_t *privkey, uint32_t privkey_len, uint8_t *output, uint32_t output_size, uint32_t *output_len) {
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;

    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&key_attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&key_attr, CONFIG_ECC_KEY_BITS);
    psa_import_key(&key_attr, privkey, privkey_len, &key_id); // der

    psa_sign_hash(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash, hash_len, output, output_size, (size_t *)output_len); // 2 * KEY_BITS / 8
    psa_destroy_key(key_id);
}

int ecc_verify(uint8_t *hash, uint32_t hash_len, uint8_t *pubkey, uint32_t pubkey_len, uint8_t *signature, uint32_t signature_len) {
    psa_status_t status = PSA_SUCCESS;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;

    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&key_attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&key_attr, CONFIG_ECC_KEY_BITS);
    psa_import_key(&key_attr, pubkey, pubkey_len, &key_id); // der

    status = psa_verify_hash(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash, hash_len, signature, signature_len);
    psa_destroy_key(key_id);

    return status;
}

void crt_gen_csr(alg_usage_t useage, uint8_t *privkey, uint32_t privkey_len, char *subject_name, uint8_t *output, uint32_t output_size, uint32_t *output_len) {
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    mbedtls_x509write_csr x509w_csr;
    mbedtls_pk_context pk_ctx;

    if (ALG_RSA_PKCS1V15_SIGN == useage) {
        psa_set_key_algorithm(&key_attr, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256));
        psa_set_key_type(&key_attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
        psa_set_key_bits(&key_attr, CONFIG_RSA_KEY_BITS);
    } else if (ALG_RSA_PKCS1V21_SIGN == useage) {
        psa_set_key_algorithm(&key_attr, PSA_ALG_RSA_PSS(PSA_ALG_SHA_256));
        psa_set_key_type(&key_attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
        psa_set_key_bits(&key_attr, CONFIG_RSA_KEY_BITS);
    } else if (ALG_ECC_SIGN == useage) {
        psa_set_key_algorithm(&key_attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
        psa_set_key_type(&key_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(&key_attr, CONFIG_ECC_KEY_BITS);
    }
    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_SIGN_HASH);
    psa_import_key(&key_attr, privkey, privkey_len, &key_id); // der

    mbedtls_pk_init(&pk_ctx);
    mbedtls_pk_copy_from_psa(key_id, &pk_ctx);

    mbedtls_x509write_csr_init(&x509w_csr);
    mbedtls_x509write_csr_set_md_alg(&x509w_csr, MBEDTLS_MD_SHA256);
    mbedtls_x509write_csr_set_subject_name(&x509w_csr, subject_name);  
    mbedtls_x509write_csr_set_key_usage(&x509w_csr,
        MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_KEY_ENCIPHERMENT);
    mbedtls_x509write_csr_set_ns_cert_type(&x509w_csr,
        MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT | MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER | MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING);
    mbedtls_x509write_csr_set_key(&x509w_csr, &pk_ctx);
#if CONFIG_USE_FORMAT_PEM == 1
    mbedtls_x509write_csr_pem(&x509w_csr, output, output_size);
    *output_len = strlen((char *)output) + 1;
#else
    *output_len = mbedtls_x509write_csr_der(&x509w_csr, output, output_size); // write at the end of buffer
    memmove(output, output + (output_size - *output_len), *output_len);
#endif

    mbedtls_x509write_csr_free(&x509w_csr);
    mbedtls_pk_free(&pk_ctx);
    psa_destroy_key(key_id);
}

void crt_sign_csr(alg_usage_t useage, uint8_t *input, uint32_t input_len, uint8_t *privkey, uint32_t privkey_len, char *issuer_name,
                  char *not_before, char *not_after, uint8_t is_ca, uint8_t *output, uint32_t output_size, uint32_t *output_len) {
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    mbedtls_pk_context pk_ctx;
    mbedtls_x509_csr x509_csr;
    mbedtls_x509write_cert x509w_crt;
    char subject_name[128] = {0};
    uint8_t sn[MBEDTLS_X509_RFC5280_MAX_SERIAL_LEN] = {0};

    if (ALG_RSA_PKCS1V15_SIGN == useage) {
        psa_set_key_algorithm(&key_attr, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256));
        psa_set_key_type(&key_attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
        psa_set_key_bits(&key_attr, CONFIG_RSA_KEY_BITS);
    } else if (ALG_RSA_PKCS1V21_SIGN == useage) {
        psa_set_key_algorithm(&key_attr, PSA_ALG_RSA_PSS(PSA_ALG_SHA_256));
        psa_set_key_type(&key_attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
        psa_set_key_bits(&key_attr, CONFIG_RSA_KEY_BITS);
    } else if (ALG_ECC_SIGN == useage) {
        psa_set_key_algorithm(&key_attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
        psa_set_key_type(&key_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(&key_attr, CONFIG_ECC_KEY_BITS);
    }
    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_SIGN_HASH);
    psa_import_key(&key_attr, privkey, privkey_len, &key_id); // der

    mbedtls_pk_init(&pk_ctx);
    mbedtls_pk_copy_from_psa(key_id, &pk_ctx);

    mbedtls_x509_csr_init(&x509_csr);
    mbedtls_x509_csr_parse(&x509_csr, input, input_len);
    gen_random(sn, sizeof(sn));
    mbedtls_x509_dn_gets(subject_name, sizeof(subject_name), &(x509_csr.subject));

    mbedtls_x509write_crt_init(&x509w_crt);
    mbedtls_x509write_crt_set_version(&x509w_crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&x509w_crt, x509_csr.private_sig_md);
    mbedtls_x509write_crt_set_subject_key(&x509w_crt, &(x509_csr.pk));
    mbedtls_x509write_crt_set_ns_cert_type(&x509w_crt, x509_csr.ns_cert_type);
    mbedtls_x509write_crt_set_key_usage(&x509w_crt, x509_csr.key_usage);
    mbedtls_x509write_crt_set_subject_name(&x509w_crt, subject_name);
    mbedtls_x509write_crt_set_issuer_name(&x509w_crt, issuer_name);  
    mbedtls_x509write_crt_set_issuer_key(&x509w_crt, &pk_ctx);
    mbedtls_x509write_crt_set_serial_raw(&x509w_crt, sn, sizeof(sn));
    mbedtls_x509write_crt_set_validity(&x509w_crt, not_before, not_after);
    mbedtls_x509write_crt_set_basic_constraints(&x509w_crt, is_ca, -1);
    mbedtls_x509write_crt_set_subject_key_identifier(&x509w_crt);
    mbedtls_x509write_crt_set_authority_key_identifier(&x509w_crt);
#if CONFIG_USE_FORMAT_PEM == 1
    mbedtls_x509write_crt_pem(&x509w_crt, output, output_size);
    *output_len = strlen((char *)output) + 1;
#else
    *output_len = mbedtls_x509write_crt_der(&x509w_crt, output, output_size); // write at the end of buffer
    memmove(output, output + (output_size - *output_len), *output_len);
#endif

    mbedtls_x509write_crt_free(&x509w_crt);
    mbedtls_x509_csr_free(&x509_csr);
    mbedtls_pk_free(&pk_ctx);
    psa_destroy_key(key_id);
}

int crt_verify(uint8_t *subject_crt, uint32_t subject_crt_len, uint8_t *issuer_crt, uint32_t issuer_crt_len) {
    mbedtls_x509_crt subject_x509_crt;
    mbedtls_x509_crt issuer_x509_crt;
    uint32_t flags = 0;
    int ret = 0;

    mbedtls_x509_crt_init(&subject_x509_crt);
    mbedtls_x509_crt_init(&issuer_x509_crt);
    mbedtls_x509_crt_parse(&subject_x509_crt, subject_crt, subject_crt_len);
    mbedtls_x509_crt_parse(&issuer_x509_crt, issuer_crt, issuer_crt_len);
    ret = mbedtls_x509_crt_verify(&subject_x509_crt, &issuer_x509_crt, NULL, NULL, &flags, NULL, NULL);
    mbedtls_x509_crt_free(&subject_x509_crt);
    mbedtls_x509_crt_free(&issuer_x509_crt);

    return ret;
}


void test_random() {
    uint8_t data[32] = {0};

    gen_random(data, sizeof(data));
    ESP_LOGI(TAG, "random data, len:%u", sizeof(data));
    ESP_LOG_BUFFER_HEX(TAG, data, sizeof(data));
}

void test_base64() {
    uint8_t src_data[64] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00
    };
    char encode[128] = {0};
    uint8_t decode[128] = {0};
    size_t enc_len = 0, dec_len = 0;

    mbedtls_base64_encode((unsigned char *)encode, sizeof(encode), &enc_len, src_data, sizeof(src_data));
    ESP_LOGI(TAG, "base64 encode data, len:%u", enc_len);
    ESP_LOGI(TAG, "%s", encode);

    mbedtls_base64_decode(decode, sizeof(decode), &dec_len, (unsigned char *)encode, enc_len);
    ESP_LOGI(TAG, "base64 decode data, len:%u", dec_len);
    ESP_LOG_BUFFER_HEX(TAG, decode, dec_len);
}

void test_hash() {
    uint8_t src_data[296] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
        0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
        0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };
    uint8_t hash[128] = {0};
    uint32_t hash_len = 0;

    calc_md5(src_data, sizeof(src_data), hash, sizeof(hash), &hash_len);
    ESP_LOGI(TAG, "md5, len:%lu", hash_len);
    ESP_LOG_BUFFER_HEX(TAG, hash, hash_len);

    calc_sha1(src_data, sizeof(src_data), hash, sizeof(hash), &hash_len);
    ESP_LOGI(TAG, "sha1, len:%lu", hash_len);
    ESP_LOG_BUFFER_HEX(TAG, hash, hash_len);

    calc_sha256(src_data, sizeof(src_data), hash, sizeof(hash), &hash_len);
    ESP_LOGI(TAG, "sha256, len:%lu", hash_len);
    ESP_LOG_BUFFER_HEX(TAG, hash, hash_len);
}

void test_hmac() {
    uint8_t src_data[296] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
        0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
        0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };
    uint8_t key[40] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01
    };
    uint8_t hmac[128] = {0};
    uint32_t hmac_len = 0;
    
    calc_hmac256(src_data, sizeof(src_data), key, sizeof(key), hmac, sizeof(hmac), &hmac_len);
    ESP_LOGI(TAG, "hmac256, len:%lu", hmac_len);
    ESP_LOG_BUFFER_HEX(TAG, hmac, hmac_len);
}

void test_cmac() {
    uint8_t src_data[296] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
        0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
        0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };
    uint8_t key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t cmac[128] = {0};
    uint32_t cmac_len = 0;
    
    calc_cmac(src_data, sizeof(src_data), key, sizeof(key), cmac, sizeof(cmac), &cmac_len);
    ESP_LOGI(TAG, "cmac, len:%lu", cmac_len);
    ESP_LOG_BUFFER_HEX(TAG, cmac, cmac_len);
}

void test_aes_cbc() {
    uint8_t src_data[296] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
        0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
        0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };
    uint8_t key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t iv[16] = {0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00};
    uint8_t encode[512] = {0};
    uint8_t decode[512] = {0};
    uint32_t encode_len = 0, decode_len = 0;

    aes_cbc_encrypt(src_data, sizeof(src_data), key, sizeof(key), iv, sizeof(iv), encode, sizeof(encode), &encode_len);
    ESP_LOGI(TAG, "aes128_cbc encode, len:%lu", encode_len);
    ESP_LOG_BUFFER_HEX(TAG, encode, encode_len);

    aes_cbc_decrypt(encode, encode_len, key, sizeof(key), iv, sizeof(iv), decode, sizeof(decode), &decode_len);
    ESP_LOGI(TAG, "aes128_cbc decode, len:%lu", decode_len);
    ESP_LOG_BUFFER_HEX(TAG, decode, decode_len);
}

void test_aes_ctr() {
    uint8_t src_data[296] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
        0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
        0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };
    uint8_t key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t iv[16] = {0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00};
    uint8_t encode[512] = {0};
    uint8_t decode[512] = {0};
    uint32_t encode_len = 0, decode_len = 0;

    aes_ctr_encrypt(src_data, sizeof(src_data), key, sizeof(key), iv, sizeof(iv), encode, sizeof(encode), &encode_len);
    ESP_LOGI(TAG, "aes128_ctr encode, len:%lu", encode_len);
    ESP_LOG_BUFFER_HEX(TAG, encode, encode_len);

    aes_ctr_decrypt(encode, encode_len, key, sizeof(key), iv, sizeof(iv), decode, sizeof(decode), &decode_len);
    ESP_LOGI(TAG, "aes128_ctr decode, len:%lu", decode_len);
    ESP_LOG_BUFFER_HEX(TAG, decode, decode_len);
}

void test_aes_gcm() {
    uint8_t src_data[296] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
        0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
        0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };
    uint8_t key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t nonce[12] = {0x01, 0x23, 0x45, 0x67, 0x89, 0x98, 0x76, 0x54, 0x32, 0x10, 0x00, 0xff};
    uint8_t ad[16] = {0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00};
    uint8_t encode[512] = {0};
    uint8_t decode[512] = {0};
    uint32_t encode_len = 0, decode_len = 0;

#if CONFIG_USE_MULTIPART_API == 1
    uint8_t tag[16] = {0};
    uint32_t tag_len = 0;

    aes_gcm_encrypt(src_data, sizeof(src_data), key, sizeof(key), nonce, sizeof(nonce), ad, sizeof(ad), encode, sizeof(encode), &encode_len, tag, sizeof(tag), &tag_len);
    ESP_LOGI(TAG, "aes128_gcm encode, len:%lu", encode_len);
    ESP_LOG_BUFFER_HEX(TAG, encode, encode_len);
    ESP_LOGI(TAG, "aes128_gcm tag, len:%lu", tag_len);
    ESP_LOG_BUFFER_HEX(TAG, tag, tag_len);

    aes_gcm_decrypt(encode, encode_len, key, sizeof(key), nonce, sizeof(nonce), ad, sizeof(ad), tag, tag_len, decode, sizeof(decode), &decode_len);
    ESP_LOGI(TAG, "aes128_gcm decode, len:%lu", decode_len);
    ESP_LOG_BUFFER_HEX(TAG, decode, decode_len);
#else
    uint32_t tag_len = 16;

    aes_gcm_encrypt(src_data, sizeof(src_data), key, sizeof(key), nonce, sizeof(nonce), ad, sizeof(ad), tag_len, encode, sizeof(encode), &encode_len);
    ESP_LOGI(TAG, "aes128_gcm encode, len:%lu", encode_len);
    ESP_LOG_BUFFER_HEX(TAG, encode, encode_len);

    aes_gcm_decrypt(encode, encode_len, key, sizeof(key), nonce, sizeof(nonce), ad, sizeof(ad), tag_len, decode, sizeof(decode), &decode_len);
    ESP_LOGI(TAG, "aes128_gcm decode, len:%lu", decode_len);
    ESP_LOG_BUFFER_HEX(TAG, decode, decode_len);
#endif
}

void test_aes_ccm() {
    uint8_t src_data[296] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
        0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
        0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };
    uint8_t key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t nonce[12] = {0x01, 0x23, 0x45, 0x67, 0x89, 0x98, 0x76, 0x54, 0x32, 0x10, 0x00, 0xff};
    uint8_t ad[16] = {0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00};
    
    uint8_t encode[512] = {0};
    uint8_t decode[512] = {0};
    uint32_t encode_len = 0, decode_len = 0;

#if CONFIG_USE_MULTIPART_API == 1
    uint8_t tag[16] = {0};
    uint32_t tag_len = 0;

    aes_ccm_encrypt(src_data, sizeof(src_data), key, sizeof(key), nonce, sizeof(nonce), ad, sizeof(ad), encode, sizeof(encode), &encode_len, tag, sizeof(tag), &tag_len);
    ESP_LOGI(TAG, "aes128_ccm encode, len:%lu", encode_len);
    ESP_LOG_BUFFER_HEX(TAG, encode, encode_len);
    ESP_LOGI(TAG, "aes128_ccm tag, len:%lu", tag_len);
    ESP_LOG_BUFFER_HEX(TAG, tag, tag_len);

    aes_ccm_decrypt(encode, encode_len, key, sizeof(key), nonce, sizeof(nonce), ad, sizeof(ad), tag, tag_len, decode, sizeof(decode), &decode_len);
    ESP_LOGI(TAG, "aes128_ccm decode, len:%lu", decode_len);
    ESP_LOG_BUFFER_HEX(TAG, decode, decode_len);
#else
    uint32_t tag_len = 16;

    aes_ccm_encrypt(src_data, sizeof(src_data), key, sizeof(key), nonce, sizeof(nonce), ad, sizeof(ad), tag_len, encode, sizeof(encode), &encode_len);
    ESP_LOGI(TAG, "aes128_ccm encode, len:%lu", encode_len);
    ESP_LOG_BUFFER_HEX(TAG, encode, encode_len);

    aes_ccm_decrypt(encode, encode_len, key, sizeof(key), nonce, sizeof(nonce), ad, sizeof(ad), tag_len, decode, sizeof(decode), &decode_len);
    ESP_LOGI(TAG, "aes128_ccm decode, len:%lu", decode_len);
    ESP_LOG_BUFFER_HEX(TAG, decode, decode_len);
#endif
}

void test_rsa_crypt() {
    uint8_t src_data[296] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
        0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
        0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };
    uint8_t encode[1024] = {0};
    uint8_t decode[1024] = {0};
    uint32_t encode_len = 0, decode_len = 0;
    uint8_t *pubkey = NULL, *privkey = NULL;
    uint32_t pubkey_len = 0, privkey_len = 0;
    pubkey = pvPortMalloc(2048);
    privkey = pvPortMalloc(2048);

    rsa_gen_keypair(ALG_RSA_PKCS1V21_CRYPT, pubkey, 2048, &pubkey_len, privkey, 2048, &privkey_len);
    ESP_LOGI(TAG, "rsa pubkey, len:%lu", pubkey_len);
    ESP_LOG_BUFFER_HEX(TAG, pubkey, pubkey_len);
    ESP_LOGI(TAG, "rsa privkey, len:%lu", privkey_len);
    ESP_LOG_BUFFER_HEX(TAG, privkey, privkey_len);

    rsa_encrypt(ALG_RSA_PKCS1V21_CRYPT, src_data, sizeof(src_data), pubkey, pubkey_len, encode, sizeof(encode), &encode_len);
    ESP_LOGI(TAG, "rsa encode, len:%lu", encode_len);
    ESP_LOG_BUFFER_HEX(TAG, encode, encode_len);

    rsa_decrypt(ALG_RSA_PKCS1V21_CRYPT, encode, encode_len, privkey, privkey_len, decode, sizeof(decode), &decode_len);
    ESP_LOGI(TAG, "rsa decode, len:%lu", decode_len);
    ESP_LOG_BUFFER_HEX(TAG, decode, decode_len);

    vPortFree(pubkey);
    vPortFree(privkey);
}

void test_rsa_sign() {
    uint8_t src_data[296] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
        0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
        0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };
    uint8_t hash[128] = {0};
    uint32_t hash_len = 0;
    uint8_t sign[512] = {0};
    uint32_t sign_len = 0;
    int ret = -1;
    uint8_t *pubkey = NULL, *privkey = NULL;
    uint32_t pubkey_len = 0, privkey_len = 0;
    pubkey = pvPortMalloc(2048);
    privkey = pvPortMalloc(2048);

    rsa_gen_keypair(ALG_RSA_PKCS1V21_SIGN, pubkey, 2048, &pubkey_len, privkey, 2048, &privkey_len);
    ESP_LOGI(TAG, "rsa pubkey, len:%lu", pubkey_len);
    ESP_LOG_BUFFER_HEX(TAG, pubkey, pubkey_len);
    ESP_LOGI(TAG, "rsa privkey, len:%lu", privkey_len);
    ESP_LOG_BUFFER_HEX(TAG, privkey, privkey_len);

    calc_sha256(src_data, sizeof(src_data), hash, sizeof(hash), &hash_len);
    ESP_LOGI(TAG, "sha256, len:%lu", hash_len);
    ESP_LOG_BUFFER_HEX(TAG, hash, hash_len);

    rsa_sign(ALG_RSA_PKCS1V21_SIGN, hash, hash_len, privkey, privkey_len, sign, sizeof(sign), &sign_len);
    ESP_LOGI(TAG, "rsa sign, len:%lu", sign_len);
    ESP_LOG_BUFFER_HEX(TAG, sign, sign_len);

    ret = rsa_verify(ALG_RSA_PKCS1V21_SIGN, hash, hash_len, pubkey, pubkey_len, sign, sign_len);
    ESP_LOGI(TAG, "rsa verify ret:%d", ret);

    vPortFree(pubkey);
    vPortFree(privkey);
}

void test_ecc_sign() {
    uint8_t src_data[296] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
        0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
        0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };
    uint8_t hash[128] = {0};
    uint32_t hash_len = 0;
    uint8_t signature[512] = {0};
    uint32_t signature_len = 0;
    int ret = -1;
    uint8_t *pubkey = NULL, *privkey = NULL;
    uint32_t pubkey_len = 0, privkey_len = 0;
    pubkey = pvPortMalloc(2048);
    privkey = pvPortMalloc(2048);

    ecc_gen_keypair(pubkey, 2048, &pubkey_len, privkey, 2048, &privkey_len);
    ESP_LOGI(TAG, "ecc pubkey, len:%lu", pubkey_len);
    ESP_LOG_BUFFER_HEX(TAG, pubkey, pubkey_len);
    ESP_LOGI(TAG, "ecc privkey, len:%lu", privkey_len);
    ESP_LOG_BUFFER_HEX(TAG, privkey, privkey_len);

    calc_sha256(src_data, sizeof(src_data), hash, sizeof(hash), &hash_len);
    ESP_LOGI(TAG, "sha256, len:%lu", hash_len);
    ESP_LOG_BUFFER_HEX(TAG, hash, hash_len);

    ecc_sign(hash, hash_len, privkey, privkey_len, signature, sizeof(signature), &signature_len);
    ESP_LOGI(TAG, "ecc sign, len:%lu", signature_len);
    ESP_LOG_BUFFER_HEX(TAG, signature, signature_len);

    ret = ecc_verify(hash, hash_len, pubkey, pubkey_len, signature, signature_len);
    ESP_LOGI(TAG, "ecc verify ret:%d", ret);

    vPortFree(pubkey);
    vPortFree(privkey);
}

void test_crt() {
    uint8_t *subject_pubkey = NULL, *subject_privkey = NULL, *subject_csr = NULL, *subject_crt = NULL;
    uint8_t *issuer_pubkey = NULL, *issuer_privkey = NULL, *issuer_csr = NULL, *issuer_crt = NULL;
    uint32_t subject_pubkey_len = 0, subject_privkey_len = 0, subject_csr_len = 0, subject_crt_len = 0;
    uint32_t issuer_pubkey_len = 0, issuer_privkey_len = 0, issuer_csr_len = 0, issuer_crt_len = 0;
    char *subject_name = "C=CN,ST=ZJ,L=HZ,O=esp32,OU=espressif,CN=*.subject.com";
    char *issuer_name  = "C=CN,ST=ZJ,L=HZ,O=esp32,OU=espressif,CN=*.issuer.com";
    char *not_before = "20250101000000";
    char *not_after = "20291231235959";
    int ret = 0;

    subject_pubkey = pvPortMalloc(2048);
    subject_privkey = pvPortMalloc(2048);
    subject_csr = pvPortMalloc(2048);
    subject_crt = pvPortMalloc(2048);
    issuer_pubkey = pvPortMalloc(2048);
    issuer_privkey = pvPortMalloc(2048);
    issuer_csr = pvPortMalloc(2048);
    issuer_crt = pvPortMalloc(2048);
    memset(subject_pubkey, 0, 2048);
    memset(subject_privkey, 0, 2048);
    memset(subject_csr, 0, 2048);
    memset(subject_crt, 0, 2048);
    memset(issuer_pubkey, 0, 2048);
    memset(issuer_privkey, 0, 2048);
    memset(issuer_csr, 0, 2048);
    memset(issuer_crt, 0, 2048);

    // generate issuer ecc keypair
    ecc_gen_keypair(issuer_pubkey, 2048, &issuer_pubkey_len, issuer_privkey, 2048, &issuer_privkey_len);
    ESP_LOGI(TAG, "issuer ecc pubkey, len:%lu", issuer_pubkey_len);
    ESP_LOG_BUFFER_HEX(TAG, issuer_pubkey, issuer_pubkey_len);
    ESP_LOGI(TAG, "issuer ecc privkey, len:%lu", issuer_privkey_len);
    ESP_LOG_BUFFER_HEX(TAG, issuer_privkey, issuer_privkey_len);

    // generate subject rsa keypair
    rsa_gen_keypair(ALG_RSA_PKCS1V21_SIGN, subject_pubkey, 2048, &subject_pubkey_len, subject_privkey, 2048, &subject_privkey_len);
    ESP_LOGI(TAG, "subject rsa pubkey, len:%lu", subject_pubkey_len);
    ESP_LOG_BUFFER_HEX(TAG, subject_pubkey, subject_pubkey_len);
    ESP_LOGI(TAG, "subject rsa privkey, len:%lu", subject_privkey_len);
    ESP_LOG_BUFFER_HEX(TAG, subject_privkey, subject_privkey_len);

    // generate issuer csr
    crt_gen_csr(ALG_ECC_SIGN, issuer_privkey, issuer_privkey_len, issuer_name, issuer_csr, 2048, &issuer_csr_len);
#if CONFIG_USE_FORMAT_PEM == 1
    ESP_LOGI(TAG, "issuer csr pem, len:%lu", issuer_csr_len);
    ESP_LOGI(TAG, "%s", issuer_csr);
#else
    ESP_LOGI(TAG, "issuer csr der, len:%lu", issuer_csr_len);
    ESP_LOG_BUFFER_HEX(TAG, issuer_csr, issuer_csr_len);
#endif

    // generate subject csr
    crt_gen_csr(ALG_RSA_PKCS1V21_SIGN, subject_privkey, subject_privkey_len, subject_name, subject_csr, 2048, &subject_csr_len);
#if CONFIG_USE_FORMAT_PEM == 1
    ESP_LOGI(TAG, "subject csr pem, len:%lu", subject_csr_len);
    ESP_LOGI(TAG, "%s", subject_csr);
#else
    ESP_LOGI(TAG, "subject csr der, len:%lu", subject_csr_len);
    ESP_LOG_BUFFER_HEX(TAG, subject_csr, subject_csr_len);
#endif

    // self-sign issuer crt
    crt_sign_csr(ALG_ECC_SIGN, issuer_csr, issuer_csr_len, issuer_privkey, issuer_privkey_len, issuer_name, not_before, not_after, 1, issuer_crt, 2048, &issuer_crt_len);
#if CONFIG_USE_FORMAT_PEM == 1
    ESP_LOGI(TAG, "issuer crt pem, len:%lu", issuer_crt_len);
    ESP_LOGI(TAG, "%s", issuer_crt);
#else
    ESP_LOGI(TAG, "issuer crt der, len:%lu", issuer_crt_len);
    ESP_LOG_BUFFER_HEX(TAG, issuer_crt, issuer_crt_len);
#endif

    // sign subject crt by issuer
    crt_sign_csr(ALG_ECC_SIGN, subject_csr, subject_csr_len, issuer_privkey, issuer_privkey_len, issuer_name, not_before, not_after, 0, subject_crt, 2048, &subject_crt_len);
#if CONFIG_USE_FORMAT_PEM == 1
    ESP_LOGI(TAG, "subject crt pem, len:%lu", subject_crt_len);
    ESP_LOGI(TAG, "%s", subject_crt);
#else
    ESP_LOGI(TAG, "subject crt der, len:%lu", subject_crt_len);
    ESP_LOG_BUFFER_HEX(TAG, subject_crt, subject_crt_len);
#endif

    // verify issuer crt, self-sign 
    ret = crt_verify(issuer_crt, issuer_crt_len, issuer_crt, issuer_crt_len);
    ESP_LOGI(TAG, "issuer crt verify:%d", ret);

    // verify subject crt, by issuer crt
    ret = crt_verify(subject_crt, subject_crt_len, issuer_crt, issuer_crt_len);
    ESP_LOGI(TAG, "subject crt verify:%d", ret);

    vPortFree(subject_pubkey);
    vPortFree(subject_privkey);
    vPortFree(subject_csr);
    vPortFree(subject_crt);
    vPortFree(issuer_pubkey);
    vPortFree(issuer_privkey);
    vPortFree(issuer_csr);
    vPortFree(issuer_crt);
}

void test_algorithm_cb(void *pvParameters) {
    ESP_LOGI(TAG, "test start");
    test_random();
    test_base64();
    test_hash();
    test_hmac();
    test_cmac();
    test_aes_cbc();
    test_aes_ctr();
    test_aes_gcm();
    test_aes_ccm();
    test_rsa_crypt();
    test_rsa_sign();
    test_ecc_sign();
    test_crt();
    ESP_LOGI(TAG, "test complete");
    
    vTaskDelete(NULL);
}


void app_main(void) {
    xTaskCreate(test_algorithm_cb, "test_algorithm", 8192, NULL, 1, NULL);

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
