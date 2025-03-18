#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "mbedtls/base64.h"
#include "mbedtls/md.h"
#include "mbedtls/cipher.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/bignum.h"
#include "mbedtls/rsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecp.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/x509_crt.h"


#define CONFIG_RSA_PADDING_PKCS1_V21        1
#define CONFIG_RSA_KEYPAIR_FORMAT_PEM       1
#define CONFIG_ECC_KEYPAIR_FORMAT_PEM       1
#define CONFIG_X509_CSR_FORMAT_PEM          1
#define CONFIG_X509_CRT_FORMAT_PEM          1


static const char *TAG = "algorithm";

void gen_random(uint8_t *data, uint32_t data_len) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    mbedtls_ctr_drbg_random(&ctr_drbg, data, data_len);

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

void calc_md5(uint8_t *data, uint32_t data_len, uint8_t *hash, uint32_t *hash_len) {
    const uint32_t BLOCK_SIZE = 128;
    uint32_t blocks = data_len / BLOCK_SIZE;
    uint32_t last_block_size = data_len % BLOCK_SIZE;
    uint32_t i = 0;
    mbedtls_md_context_t md_ctx;

    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_MD5), 0);
    mbedtls_md_starts(&md_ctx);
    while (i < blocks) {
        mbedtls_md_update(&md_ctx, data + (i * BLOCK_SIZE), BLOCK_SIZE);
        i++;
    }
    if (last_block_size) {
        mbedtls_md_update(&md_ctx, data + (i * BLOCK_SIZE), last_block_size);
    }
    mbedtls_md_finish(&md_ctx, hash);
    mbedtls_md_free(&md_ctx);

    *hash_len = mbedtls_md_get_size(mbedtls_md_info_from_type(MBEDTLS_MD_MD5)); // 16B
}

void calc_sha1(uint8_t *data, uint32_t data_len, uint8_t *hash, uint32_t *hash_len) {
    const uint32_t BLOCK_SIZE = 128;
    uint32_t blocks = data_len / BLOCK_SIZE;
    uint32_t last_block_size = data_len % BLOCK_SIZE;
    uint32_t i = 0;
    mbedtls_md_context_t md_ctx;

    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 0);
    mbedtls_md_starts(&md_ctx);
    while (i < blocks) {
        mbedtls_md_update(&md_ctx, data + (i * BLOCK_SIZE), BLOCK_SIZE);
        i++;
    }
    if (last_block_size) {
        mbedtls_md_update(&md_ctx, data + (i * BLOCK_SIZE), last_block_size);
    }
    mbedtls_md_finish(&md_ctx, hash);
    mbedtls_md_free(&md_ctx);

    *hash_len = mbedtls_md_get_size(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1)); // 20B
}

void calc_sha256(uint8_t *data, uint32_t data_len, uint8_t *hash, uint32_t *hash_len) {
    const uint32_t BLOCK_SIZE = 128;
    uint32_t blocks = data_len / BLOCK_SIZE;
    uint32_t last_block_size = data_len % BLOCK_SIZE;
    uint32_t i = 0;
    mbedtls_md_context_t md_ctx;

    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
    mbedtls_md_starts(&md_ctx);
    while (i < blocks) {
        mbedtls_md_update(&md_ctx, data + (i * BLOCK_SIZE), BLOCK_SIZE);
        i++;
    }
    if (last_block_size) {
        mbedtls_md_update(&md_ctx, data + (i * BLOCK_SIZE), last_block_size);
    }
    mbedtls_md_finish(&md_ctx, hash);
    mbedtls_md_free(&md_ctx);

    *hash_len = mbedtls_md_get_size(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256)); // 32B
}

void calc_hmac_sha256(uint8_t *data, uint32_t data_len, uint8_t *key, uint32_t key_len, uint8_t *hmac, uint32_t *hmac_len) {
    // HMAC(key, plaint)
    // 1. key xor ipad
    // 2. (key xor ipad) || plaint
    // 3. hash((key xor ipad) || plaint)
    // 4. (key xor opad) || hash((key xor ipad) || plaint))
    // 5. hash((key xor opad) || hash((key xor ipad) || plaint))
    const uint32_t BLOCK_SIZE = 128;
    uint32_t blocks = data_len / BLOCK_SIZE;
    uint32_t last_block_size = data_len % BLOCK_SIZE;
    uint32_t i = 0;
    mbedtls_md_context_t md_ctx;

    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&md_ctx, key, key_len); // key length not restricted
    while (i < blocks) {
        mbedtls_md_hmac_update(&md_ctx, data + (i * BLOCK_SIZE), BLOCK_SIZE);
        i++;
    }
    if (last_block_size) {
        mbedtls_md_hmac_update(&md_ctx, data + (i * BLOCK_SIZE), last_block_size);
    }
    mbedtls_md_hmac_finish(&md_ctx, hmac);
    mbedtls_md_free(&md_ctx);

    *hmac_len = mbedtls_md_get_size(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256)); // 32B
}

void aes_cbc_encrypt(uint8_t *plaintext, uint32_t plaintext_len, uint8_t *key, uint32_t key_len, uint8_t *iv, uint32_t iv_len, uint8_t *ciphertext, uint32_t *ciphertext_len) {
    const uint32_t BLOCK_SIZE = 16; // must be 16B
    uint32_t blocks = plaintext_len / BLOCK_SIZE;
    uint32_t remainder = plaintext_len % BLOCK_SIZE;
    uint32_t i = 0;
    size_t enc_len = 0, total_enc_len = 0;
    mbedtls_cipher_context_t cipher_ctx;

    mbedtls_cipher_init(&cipher_ctx);
    mbedtls_cipher_setup(&cipher_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC));
    mbedtls_cipher_setkey(&cipher_ctx, key, key_len * 8, MBEDTLS_ENCRYPT); // AES-128:16B, AES-192:24B, AES-256:32B
    mbedtls_cipher_set_iv(&cipher_ctx, iv, iv_len); // BLOCK_SIZE
    mbedtls_cipher_set_padding_mode(&cipher_ctx, MBEDTLS_PADDING_PKCS7);
    while (i < blocks) {
        mbedtls_cipher_update(&cipher_ctx, plaintext + (i * BLOCK_SIZE), BLOCK_SIZE, ciphertext + total_enc_len, &enc_len);
        total_enc_len += enc_len; // enc_len = BLOCK_SIZE
        i++;
    }
    if (remainder) {
        mbedtls_cipher_update(&cipher_ctx, plaintext + (i * BLOCK_SIZE), remainder, ciphertext + total_enc_len, &enc_len);
        total_enc_len += enc_len; // enc_len = BLOCK_SIZE
    }
    mbedtls_cipher_finish(&cipher_ctx, ciphertext + total_enc_len, &enc_len);
    total_enc_len += enc_len; // total_enc_len = multiple(blocks + 1) of BLOCK_SIZE
    mbedtls_cipher_free(&cipher_ctx);

    *ciphertext_len = total_enc_len;
}

void aes_cbc_decrypt(uint8_t *ciphertext, uint32_t ciphertext_len, uint8_t *key, uint32_t key_len, uint8_t *iv, uint32_t iv_len, uint8_t *plaintext, uint32_t *plaintext_len) {
    const uint32_t BLOCK_SIZE = 16; // must be 16B
    uint32_t blocks = ciphertext_len / BLOCK_SIZE; // multiple of BLOCK_SIZE
    // uint32_t remainder = ciphertext_len % BLOCK_SIZE; // = 0
    uint32_t i = 0;
    size_t dec_len = 0, total_dec_len = 0;
    mbedtls_cipher_context_t cipher_ctx;

    mbedtls_cipher_init(&cipher_ctx);
    mbedtls_cipher_setup(&cipher_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC));    
    mbedtls_cipher_setkey(&cipher_ctx, key, key_len * 8, MBEDTLS_DECRYPT); // AES-128:16B, AES-192:24B, AES-256:32B
    mbedtls_cipher_set_iv(&cipher_ctx, iv, iv_len); // BLOCK_SIZE
    mbedtls_cipher_set_padding_mode(&cipher_ctx, MBEDTLS_PADDING_PKCS7);
    while (i < blocks) {
        mbedtls_cipher_update(&cipher_ctx, ciphertext + (i * BLOCK_SIZE), BLOCK_SIZE, plaintext + total_dec_len, &dec_len);
        total_dec_len += dec_len; // dec_len = BLOCK_SIZE/.../BLOCK_SIZE/remainder
        i++;
    }
    // if (remainder) {
    //     mbedtls_cipher_update(&cipher_ctx, src + (i * BLOCK_SIZE), remainder, plaintext + total_dec_len, &dec_len);
    //     total_dec_len += dec_len;
    // }
    mbedtls_cipher_finish(&cipher_ctx, plaintext + total_dec_len, &dec_len);
    total_dec_len += dec_len;  // total_dec_len = ciphertext_len
    mbedtls_cipher_free(&cipher_ctx);

    *plaintext_len = total_dec_len;
}

void aes_ctr_encrypt(uint8_t *plaintext, uint32_t plaintext_len, uint8_t *key, uint32_t key_len, uint8_t *iv, uint32_t iv_len, uint8_t *ciphertext, uint32_t *ciphertext_len) {
    const uint32_t BLOCK_SIZE = 16; // must be 16B
    uint32_t blocks = plaintext_len / BLOCK_SIZE;
    uint32_t remainder = plaintext_len % BLOCK_SIZE;
    uint32_t i = 0;
    size_t enc_len = 0, total_enc_len = 0;
    mbedtls_cipher_context_t cipher_ctx;

    mbedtls_cipher_init(&cipher_ctx);
    mbedtls_cipher_setup(&cipher_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CTR));
    mbedtls_cipher_setkey(&cipher_ctx, key, key_len * 8, MBEDTLS_ENCRYPT); // AES-128:16B, AES-192:24B, AES-256:32B
    mbedtls_cipher_set_iv(&cipher_ctx, iv, iv_len); // BLOCK_SIZE
    while (i < blocks) {
        mbedtls_cipher_update(&cipher_ctx, plaintext + (i * BLOCK_SIZE), BLOCK_SIZE, ciphertext + total_enc_len, &enc_len);
        total_enc_len += enc_len; // enc_len = BLOCK_SIZE
        i++;
    }
    if (remainder) {
        mbedtls_cipher_update(&cipher_ctx, plaintext + (i * BLOCK_SIZE), remainder, ciphertext + total_enc_len, &enc_len);
        total_enc_len += enc_len; // enc_len = remainder
    }
    mbedtls_cipher_finish(&cipher_ctx, ciphertext + total_enc_len, &enc_len);
    total_enc_len += enc_len; // no padding, total_enc_len = plaintext_len
    mbedtls_cipher_free(&cipher_ctx);

    *ciphertext_len = total_enc_len;
}

void aes_ctr_decrypt(uint8_t *ciphertext, uint32_t ciphertext_len, uint8_t *key, uint32_t key_len, uint8_t *iv, uint32_t iv_len, uint8_t *plaintext, uint32_t *plaintext_len) {
    const uint32_t BLOCK_SIZE = 16; // must be 16B
    uint32_t blocks = ciphertext_len / BLOCK_SIZE;
    uint32_t remainder = ciphertext_len % BLOCK_SIZE;
    uint32_t i = 0;
    size_t dec_len = 0, total_dec_len = 0;
    mbedtls_cipher_context_t cipher_ctx;

    mbedtls_cipher_init(&cipher_ctx);
    mbedtls_cipher_setup(&cipher_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CTR));    
    mbedtls_cipher_setkey(&cipher_ctx, key, key_len * 8, MBEDTLS_DECRYPT); // AES-128:16B, AES-192:24B, AES-256:32B
    mbedtls_cipher_set_iv(&cipher_ctx, iv, iv_len); // BLOCK_SIZE
    while (i < blocks) {
        mbedtls_cipher_update(&cipher_ctx, ciphertext + (i * BLOCK_SIZE), BLOCK_SIZE, plaintext + total_dec_len, &dec_len);
        total_dec_len += dec_len; // dec_len = BLOCK_SIZE
        i++;
    }
    if (remainder) {
        mbedtls_cipher_update(&cipher_ctx, ciphertext + (i * BLOCK_SIZE), remainder, plaintext + total_dec_len, &dec_len);
        total_dec_len += dec_len; // dec_len = remainder
    }
    mbedtls_cipher_finish(&cipher_ctx, plaintext + total_dec_len, &dec_len);
    total_dec_len += dec_len; // total_dec_len = ciphertext_len
    mbedtls_cipher_free(&cipher_ctx);

    *plaintext_len = total_dec_len;
}

void rsa_gen_keypair(mbedtls_mpi *N, mbedtls_mpi *P, mbedtls_mpi *Q, mbedtls_mpi *D, mbedtls_mpi *E) {
    const uint32_t KEY_SIZE = 2048;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_rsa_context rsa_ctx;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    mbedtls_rsa_init(&rsa_ctx);
    mbedtls_rsa_gen_key(&rsa_ctx, mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE, 65537);
    mbedtls_rsa_export(&rsa_ctx, N, P, Q, D, E); // pub_key:N,E priv_key:N,E,P,Q,D
    mbedtls_rsa_free(&rsa_ctx);

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

void rsa_encrypt(uint8_t *plaintext, uint32_t plaintext_len, mbedtls_mpi *N, mbedtls_mpi *E, uint8_t *ciphertext, uint32_t *ciphertext_len) {
    const uint32_t KEY_SIZE = 2048;
#if CONFIG_RSA_PADDING_PKCS1_V21 == 1
    const uint32_t BLOCK_SIZE = (KEY_SIZE / 8) - 66; // PKCS#1_v2.1 padding size = 66(2 * sizeof(hash) + 2)
#else
    const uint32_t BLOCK_SIZE = (KEY_SIZE / 8) - 11; // PKCS#1_v1.5 padding size = 11
#endif
    uint32_t i = 0;
    uint32_t blocks = plaintext_len / BLOCK_SIZE;
    uint32_t remainder = plaintext_len % BLOCK_SIZE;
    size_t enc_len = 0;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_rsa_context rsa_ctx;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    mbedtls_rsa_init(&rsa_ctx);
    mbedtls_rsa_import(&rsa_ctx, N, NULL, NULL, NULL, E); // import pubkey
    mbedtls_rsa_complete(&rsa_ctx);
#if CONFIG_RSA_PADDING_PKCS1_V21 == 1
    mbedtls_rsa_set_padding(&rsa_ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
#endif
    while (i < blocks) {
        mbedtls_rsa_pkcs1_encrypt(&rsa_ctx, mbedtls_ctr_drbg_random, &ctr_drbg, BLOCK_SIZE, plaintext + (i * BLOCK_SIZE), ciphertext + enc_len);
        enc_len += (KEY_SIZE / 8); // enc_len = KEY_SIZE / 8
        i++;
    }
    if (remainder) {
        mbedtls_rsa_pkcs1_encrypt(&rsa_ctx, mbedtls_ctr_drbg_random, &ctr_drbg, remainder, plaintext + (i * BLOCK_SIZE), ciphertext + enc_len);
        enc_len += (KEY_SIZE / 8); // enc_len = KEY_SIZE / 8
    }
    mbedtls_rsa_free(&rsa_ctx);

    *ciphertext_len = enc_len; // enc_len = multiple(blocks or blocks + 1) of KEY_SIZE / 8
    
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

void rsa_decrypt(uint8_t *ciphertext, uint32_t ciphertext_len, mbedtls_mpi *N, mbedtls_mpi *P, mbedtls_mpi *Q, mbedtls_mpi *D, mbedtls_mpi *E, uint8_t *plaintext, uint32_t plaintext_size, uint32_t *plaintext_len) {
    const uint32_t KEY_SIZE = 2048;
    uint32_t i = 0;
    uint32_t blocks = ciphertext_len / (KEY_SIZE / 8); // multiple of KEY_SIZE / 8
    // uint32_t remainder = ciphertext_len % (KEY_SIZE / 8); // = 0
    size_t dec_len = 0, total_dec_len = 0;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_rsa_context rsa_ctx;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    mbedtls_rsa_init(&rsa_ctx);
    mbedtls_rsa_import(&rsa_ctx, N, P, Q, D, E); // import privkey
    mbedtls_rsa_complete(&rsa_ctx);
#if CONFIG_RSA_PADDING_PKCS1_V21 == 1
    mbedtls_rsa_set_padding(&rsa_ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
#endif
    while (i < blocks) {
        mbedtls_rsa_pkcs1_decrypt(&rsa_ctx, mbedtls_ctr_drbg_random, &ctr_drbg, &dec_len, ciphertext + (i * (KEY_SIZE / 8)), plaintext + total_dec_len, plaintext_size - total_dec_len);
        total_dec_len += dec_len; // dec_len = BLOCK_SIZE/.../BLOCK_SIZE/remainder
        i++;
    }
    // if (remainder) {
    //     mbedtls_rsa_pkcs1_decrypt(&rsa_ctx, mbedtls_ctr_drbg_random, &ctr_drbg, &dec_len, ciphertext + (i * (KEY_SIZE / 8)), plaintext + total_dec_len, plaintext_size - total_dec_len);
    //     total_dec_len += dec_len;
    // }
    mbedtls_rsa_free(&rsa_ctx);

    *plaintext_len = total_dec_len; // total_dec_len = src_len

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

void rsa_sign(uint8_t *hash, uint32_t hash_len, mbedtls_mpi *N, mbedtls_mpi *P, mbedtls_mpi *Q, mbedtls_mpi *D, mbedtls_mpi *E, uint8_t *sign, uint32_t *sign_len) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_rsa_context rsa_ctx;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    mbedtls_rsa_init(&rsa_ctx);
    mbedtls_rsa_import(&rsa_ctx, N, P, Q, D, E); // import privkey
    mbedtls_rsa_complete(&rsa_ctx);
#if CONFIG_RSA_PADDING_PKCS1_V21 == 1
    mbedtls_rsa_set_padding(&rsa_ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
#endif
    mbedtls_rsa_pkcs1_sign(&rsa_ctx, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_MD_SHA256, hash_len, hash, sign);
    *sign_len = mbedtls_rsa_get_len(&rsa_ctx); // KEY_SIZE / 8
    mbedtls_rsa_free(&rsa_ctx);

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

int rsa_verify(uint8_t *hash, uint32_t hash_len, mbedtls_mpi *N, mbedtls_mpi *E, uint8_t *sign) {
    int ret = -1;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_rsa_context rsa_ctx;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    mbedtls_rsa_init(&rsa_ctx);
    mbedtls_rsa_import(&rsa_ctx, N, NULL, NULL, NULL, E); // import pubkey
    mbedtls_rsa_complete(&rsa_ctx);
#if CONFIG_RSA_PADDING_PKCS1_V21 == 1
    mbedtls_rsa_set_padding(&rsa_ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
#endif
    ret = mbedtls_rsa_pkcs1_verify(&rsa_ctx, MBEDTLS_MD_SHA256, hash_len, hash, sign);
    mbedtls_rsa_free(&rsa_ctx);
    
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

void rsa_pk_gen_keypair(uint8_t *pubkey, uint32_t pubkey_size, uint32_t *pubkey_len, uint8_t *privkey, uint32_t privkey_size, uint32_t *privkey_len) {
    const uint32_t KEY_SIZE = 2048;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context pk_ctx;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    mbedtls_pk_init(&pk_ctx);
    mbedtls_pk_setup(&pk_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk_ctx), mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE, 65537);
#if CONFIG_RSA_KEYPAIR_FORMAT_PEM == 1
    mbedtls_pk_write_pubkey_pem(&pk_ctx, pubkey, pubkey_size); // output include \0 byte, call mbedtls_rsa_write_pubkey();
    mbedtls_pk_write_key_pem(&pk_ctx, privkey, privkey_size);  // output include \0 byte, call mbedtls_rsa_write_key();
    mbedtls_pk_free(&pk_ctx);
    *pubkey_len = strlen((char *)pubkey) + 1;
    *privkey_len = strlen((char *)privkey) + 1;
#else
    *pubkey_len = mbedtls_pk_write_pubkey_der(&pk_ctx, pubkey, pubkey_size); // write at the end of buffer, call mbedtls_rsa_write_pubkey();
    *privkey_len = mbedtls_pk_write_key_der(&pk_ctx, privkey, privkey_size); // write at the end of buffer, call mbedtls_rsa_write_key();
    mbedtls_pk_free(&pk_ctx);
    memmove(pubkey, pubkey + (pubkey_size - *pubkey_len), *pubkey_len);
    memmove(privkey, privkey + (privkey_size - *privkey_len), *privkey_len);
#endif

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

void rsa_pk_encrypt(uint8_t *plaintext, uint32_t plaintext_len, uint8_t *pubkey, uint32_t pubkey_len, uint8_t *ciphertext, uint32_t ciphertext_size, uint32_t *ciphertext_len) {
    const uint32_t KEY_SIZE = 2048;
#if CONFIG_RSA_PADDING_PKCS1_V21 == 1
    const uint32_t BLOCK_SIZE = (KEY_SIZE / 8) - 66; // PKCS#1_v2.1 padding size = 66(2 * sizeof(hash) + 2)
#else
    const uint32_t BLOCK_SIZE = (KEY_SIZE / 8) - 11; // PKCS#1_v1.5 padding size = 11
#endif
    uint32_t i = 0;
    uint32_t blocks = plaintext_len / BLOCK_SIZE;
    uint32_t remainder = plaintext_len % BLOCK_SIZE;
    size_t enc_len = 0, total_enc_len = 0;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context pk_ctx;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    mbedtls_pk_init(&pk_ctx);
    mbedtls_pk_parse_public_key(&pk_ctx, pubkey, pubkey_len); // parse pem/der pubkey, call mbedtls_rsa_parse_pubkey();
#if CONFIG_RSA_PADDING_PKCS1_V21 == 1
    mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk_ctx), MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
#endif
    while (i < blocks) {
        mbedtls_pk_encrypt(&pk_ctx, plaintext + (i * BLOCK_SIZE), BLOCK_SIZE, ciphertext + total_enc_len, &enc_len, ciphertext_size - total_enc_len, mbedtls_ctr_drbg_random, &ctr_drbg);
        total_enc_len += enc_len; // enc_len = KEY_SIZE / 8
        i++;
    }
    if (remainder) {
        mbedtls_pk_encrypt(&pk_ctx, plaintext + (i * BLOCK_SIZE), remainder, ciphertext + total_enc_len, &enc_len, ciphertext_size - total_enc_len, mbedtls_ctr_drbg_random, &ctr_drbg);
        total_enc_len += enc_len; // enc_len = KEY_SIZE / 8
    }
    mbedtls_pk_free(&pk_ctx);

    *ciphertext_len = total_enc_len; // total_enc_len = multiple(blocks or blocks + 1) of KEY_SIZE / 8

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

void rsa_pk_decrypt(uint8_t *ciphertext, uint32_t ciphertext_len, uint8_t *privkey, uint32_t privkey_len, uint8_t *plaintext, uint32_t plaintext_size, uint32_t *plaintext_len) {
    const uint32_t KEY_SIZE = 2048;
    uint32_t i = 0;
    uint32_t blocks = ciphertext_len / (KEY_SIZE / 8); // multiple of KEY_SIZE / 8
    // uint32_t remainder = ciphertext_len % (KEY_SIZE / 8); // = 0
    size_t dec_len = 0, total_dec_len = 0;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context pk_ctx;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    mbedtls_pk_init(&pk_ctx);
    mbedtls_pk_parse_key(&pk_ctx, privkey, privkey_len, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg); // parse pem/der privkey, call mbedtls_rsa_parse_key();
#if CONFIG_RSA_PADDING_PKCS1_V21 == 1
    mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk_ctx), MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
#endif
    while (i < blocks) {
        mbedtls_pk_decrypt(&pk_ctx, ciphertext + (i * (KEY_SIZE / 8)), KEY_SIZE / 8, plaintext + total_dec_len, &dec_len, plaintext_size - total_dec_len, mbedtls_ctr_drbg_random, &ctr_drbg);
        total_dec_len += dec_len; // dec_len = BLOCK_SIZE/.../BLOCK_SIZE/remainder
        i++;
    }
    // if (remainder) {
    //     mbedtls_pk_decrypt(&pk_ctx, ciphertext + (i * (KEY_SIZE / 8)), KEY_SIZE / 8, plaintext + total_dec_len, &dec_len, plaintext_size - total_dec_len, mbedtls_ctr_drbg_random, &ctr_drbg);
    //     total_dec_len += dec_len;
    // }
    mbedtls_pk_free(&pk_ctx);

    *plaintext_len = total_dec_len; // total_dec_len = ciphertext_len

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

void rsa_pk_sign(uint8_t *hash, uint32_t hash_len, uint8_t *privkey, uint32_t privkey_len, uint8_t *sign, uint32_t sign_size, uint32_t *sign_len) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;    
    mbedtls_pk_context pk_ctx;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    mbedtls_pk_init(&pk_ctx);
    mbedtls_pk_parse_key(&pk_ctx, privkey, privkey_len, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg); // parse pem/der privkey, call mbedtls_rsa_parse_key();
#if CONFIG_RSA_PADDING_PKCS1_V21 == 1
    mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk_ctx), MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
#endif
    mbedtls_pk_sign(&pk_ctx, MBEDTLS_MD_SHA256, hash, hash_len, sign, sign_size, (size_t *)sign_len, mbedtls_ctr_drbg_random, &ctr_drbg); // KEY_SIZE / 8
    mbedtls_pk_free(&pk_ctx);

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

int rsa_pk_verify(uint8_t *hash, uint32_t hash_len, uint8_t *pubkey, uint32_t pubkey_len, uint8_t *sign, uint32_t sign_len) {
    int ret = -1;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context pk_ctx;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    mbedtls_pk_init(&pk_ctx);
    mbedtls_pk_parse_public_key(&pk_ctx, pubkey, pubkey_len); // parse pem/der pubkey, call mbedtls_rsa_parse_pubkey();
#if CONFIG_RSA_PADDING_PKCS1_V21 == 1
    mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk_ctx), MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
#endif    
    ret = mbedtls_pk_verify(&pk_ctx, MBEDTLS_MD_SHA256, hash, hash_len, sign, sign_len);
    mbedtls_pk_free(&pk_ctx);

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

void ecc_gen_keypair(mbedtls_mpi *d, mbedtls_ecp_point *Q) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ecp_group grp;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    mbedtls_ecp_gen_keypair(&grp, d, Q, mbedtls_ctr_drbg_random, &ctr_drbg);
    // ESP_LOGI(TAG, "ecc secp256r1 param:");
    // mbedtls_mpi_write_file("a = ", &grp.A, 16, NULL);
    // mbedtls_mpi_write_file("b = ", &grp.B, 16, NULL);
    // mbedtls_mpi_write_file("p = ", &grp.P, 16, NULL);
    // mbedtls_mpi_write_file("G.X = ", &grp.G.private_X, 16, NULL);
    // mbedtls_mpi_write_file("G.Y = ", &grp.G.private_Y, 16, NULL);
    // mbedtls_mpi_write_file("n = ", &grp.N, 16, NULL);
    mbedtls_ecp_group_free(&grp);

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

void ecc_sign(uint8_t *hash, uint32_t hash_len, mbedtls_mpi *d, mbedtls_mpi *r, mbedtls_mpi *s) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ecp_group grp;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    mbedtls_ecdsa_sign(&grp, r, s, d, hash, hash_len, mbedtls_ctr_drbg_random, &ctr_drbg); // r/s = grp.bit_size / 8
    mbedtls_ecp_group_free(&grp);

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

int ecc_verify(uint8_t *hash, uint32_t hash_len, mbedtls_ecp_point *Q, mbedtls_mpi *r, mbedtls_mpi *s) {
    int ret = -1;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ecp_group grp;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    ret = mbedtls_ecdsa_verify(&grp, hash, hash_len, Q, r, s);
    mbedtls_ecp_group_free(&grp);

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

void ecc_pk_gen_keypair(uint8_t *pubkey, uint32_t pubkey_size, uint32_t *pubkey_len, uint8_t *privkey, uint32_t privkey_size, uint32_t *privkey_len) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context pk_ctx;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    mbedtls_pk_init(&pk_ctx);
    mbedtls_pk_setup(&pk_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(pk_ctx), mbedtls_ctr_drbg_random, &ctr_drbg);
#if CONFIG_ECC_KEYPAIR_FORMAT_PEM == 1
    mbedtls_pk_write_pubkey_pem(&pk_ctx, pubkey, pubkey_size); // output include \0 byte, call mbedtls_ecp_point_write_binary();
    mbedtls_pk_write_key_pem(&pk_ctx, privkey, privkey_size);  // output include \0 byte, call mbedtls_ecp_write_key_ext();
    mbedtls_pk_free(&pk_ctx);
    *pubkey_len = strlen((char *)pubkey) + 1;
    *privkey_len = strlen((char *)privkey) + 1;
#else
    *pubkey_len = mbedtls_pk_write_pubkey_der(&pk_ctx, pubkey, pubkey_size); // write at the end of buffer, call mbedtls_ecp_point_write_binary();
    *privkey_len = mbedtls_pk_write_key_der(&pk_ctx, privkey, privkey_size); // write at the end of buffer, call mbedtls_ecp_write_key_ext();
    mbedtls_pk_free(&pk_ctx);
    memmove(pubkey, pubkey + (pubkey_size - *pubkey_len), *pubkey_len);
    memmove(privkey, privkey + (privkey_size - *privkey_len), *privkey_len);
#endif

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

void ecc_pk_sign(uint8_t *hash, uint32_t hash_len, uint8_t *privkey, uint32_t privkey_len, uint8_t *sign, uint32_t sign_size, uint32_t *sign_len) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context pk_ctx;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    mbedtls_pk_init(&pk_ctx);
    mbedtls_pk_parse_key(&pk_ctx, privkey, privkey_len, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg); // call mbedtls_ecp_read_key();
    mbedtls_pk_sign(&pk_ctx, MBEDTLS_MD_SHA256, hash, hash_len, sign, sign_size, (size_t *)sign_len, mbedtls_ctr_drbg_random, &ctr_drbg); // der_header + 2 * grp.bit_size / 8
    mbedtls_pk_free(&pk_ctx);

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

int ecc_pk_verify(uint8_t *hash, uint32_t hash_len, uint8_t *pubkey, uint32_t pubkey_len, uint8_t *sign, uint32_t sign_len) {
    int ret = -1;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context pk_ctx;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    mbedtls_pk_init(&pk_ctx);
    mbedtls_pk_parse_public_key(&pk_ctx, pubkey, pubkey_len); // call mbedtls_ecp_point_read_binary();
    ret = mbedtls_pk_verify(&pk_ctx, MBEDTLS_MD_SHA256, hash, hash_len, sign, sign_len);
    mbedtls_pk_free(&pk_ctx);

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

void x509_crt_csr(uint8_t *subject_privkey, uint32_t subject_privkey_len, char *subject_name, uint8_t *csr, uint32_t size, uint32_t *csr_len) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509write_csr x509_csr;
    mbedtls_pk_context pk_ctx;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    mbedtls_x509write_csr_init(&x509_csr);
    mbedtls_pk_init(&pk_ctx);
    mbedtls_pk_parse_key(&pk_ctx, subject_privkey, subject_privkey_len, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_x509write_csr_set_md_alg(&x509_csr, MBEDTLS_MD_SHA256);
    mbedtls_x509write_csr_set_subject_name(&x509_csr, subject_name);  
    mbedtls_x509write_csr_set_key_usage(&x509_csr, MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_KEY_ENCIPHERMENT);
    mbedtls_x509write_csr_set_ns_cert_type(&x509_csr, MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT | MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER | MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING);
    mbedtls_x509write_csr_set_key(&x509_csr, &pk_ctx);

#if CONFIG_X509_CSR_FORMAT_PEM == 1
    mbedtls_x509write_csr_pem(&x509_csr, csr, size, mbedtls_ctr_drbg_random, &ctr_drbg); // hardcode version:0
    *csr_len = strlen((char *)csr) + 1;
#else
    *csr_len = mbedtls_x509write_csr_der(&x509_csr, csr, size, mbedtls_ctr_drbg_random, &ctr_drbg); // write at the end of buffer
    memmove(csr, csr + (size - *csr_len), *csr_len);
#endif
    mbedtls_x509write_csr_free(&x509_csr);
    mbedtls_pk_free(&pk_ctx);

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

void x509_crt_sign(uint8_t *csr, uint32_t csr_len, uint8_t *issuer_privkey, uint32_t issuer_privkey_len, char *issuer_name,
                   char *not_before, char *not_after,uint8_t is_ca, uint8_t *crt, uint32_t size, uint32_t *crt_len) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context subject_pk_ctx;
    mbedtls_pk_context issuer_pk_ctx;
    mbedtls_x509_csr x509_csr;
    mbedtls_x509write_cert x509_crt;
    char subject_name[128] = {0};
    uint8_t sn[MBEDTLS_X509_RFC5280_MAX_SERIAL_LEN] = {0};

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    mbedtls_pk_init(&subject_pk_ctx);
    mbedtls_pk_init(&issuer_pk_ctx);
    mbedtls_x509_csr_init(&x509_csr);
    mbedtls_x509write_crt_init(&x509_crt);

    mbedtls_x509_csr_parse(&x509_csr, csr, csr_len); // hardcode x509_csr.version = 1
    mbedtls_pk_parse_key(&issuer_pk_ctx, issuer_privkey, issuer_privkey_len, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
    gen_random(sn, sizeof(sn));
    mbedtls_x509_dn_gets(subject_name, sizeof(subject_name), &(x509_csr.subject));
    // mbedtls_x509write_crt_set_version(&x509_crt, x509_csr.version);
    mbedtls_x509write_crt_set_version(&x509_crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&x509_crt, x509_csr.private_sig_md);
    mbedtls_x509write_crt_set_subject_key(&x509_crt, &(x509_csr.pk));
    mbedtls_x509write_crt_set_ns_cert_type(&x509_crt, x509_csr.ns_cert_type);
    mbedtls_x509write_crt_set_key_usage(&x509_crt, x509_csr.key_usage);
    mbedtls_x509write_crt_set_subject_name(&x509_crt, subject_name);
    mbedtls_x509write_crt_set_issuer_name(&x509_crt, issuer_name);  
    mbedtls_x509write_crt_set_issuer_key(&x509_crt, &issuer_pk_ctx);
    mbedtls_x509write_crt_set_serial_raw(&x509_crt, sn, sizeof(sn));
    mbedtls_x509write_crt_set_validity(&x509_crt, not_before, not_after);
    mbedtls_x509write_crt_set_basic_constraints(&x509_crt, is_ca, -1);
    mbedtls_x509write_crt_set_subject_key_identifier(&x509_crt);
    mbedtls_x509write_crt_set_authority_key_identifier(&x509_crt);

#if CONFIG_X509_CRT_FORMAT_PEM == 1
    mbedtls_x509write_crt_pem(&x509_crt, crt, size, mbedtls_entropy_func, &entropy);
    *crt_len = strlen((char *)crt) + 1;
#else
    *crt_len = mbedtls_x509write_crt_der(&x509_crt, crt, size, mbedtls_entropy_func, &entropy); // write at the end of buffer
    memmove(crt, crt + (size - *crt_len), *crt_len);
#endif
    mbedtls_x509write_crt_free(&x509_crt);
    mbedtls_x509_csr_free(&x509_csr);
    mbedtls_pk_free(&subject_pk_ctx);
    mbedtls_pk_free(&issuer_pk_ctx);

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

int x509_crt_verify(uint8_t *subject_crt, uint32_t subject_crt_len, uint8_t *issuer_crt, uint32_t issuer_crt_len, uint32_t *flags) {
    int ret = -1;
    mbedtls_x509_crt subject_x509_crt;
    mbedtls_x509_crt issuer_x509_crt;

    mbedtls_x509_crt_init(&subject_x509_crt);
    mbedtls_x509_crt_init(&issuer_x509_crt);
    mbedtls_x509_crt_parse(&subject_x509_crt, subject_crt, subject_crt_len);
    mbedtls_x509_crt_parse(&issuer_x509_crt, issuer_crt, issuer_crt_len);
    ret = mbedtls_x509_crt_verify(&subject_x509_crt, &issuer_x509_crt, NULL, NULL, flags, NULL, NULL);
    mbedtls_x509_crt_free(&subject_x509_crt);
    mbedtls_x509_crt_free(&issuer_x509_crt);

    return ret;
}


void test_random() {
    uint8_t data[128] = {0};

    gen_random(data, sizeof(data));
    ESP_LOGI(TAG, "random data, len:%u", sizeof(data));
    ESP_LOG_BUFFER_HEX(TAG, data, sizeof(data));
}

void test_base64() {
    size_t len = 0;
    uint8_t src_bin[64] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00
    };
    char src_base64[] = "AAECAwQFBgcICQoLDA0OD/Dx8vP09fb3+Pn6+/z9/v8AESIzRFVmd4iZqrvM3e7//+7dzLuqmYh3ZlVEMyIRAA==";
    char encode[128] = {0};
    uint8_t decode[128] = {0};

    mbedtls_base64_encode((unsigned char *)encode, sizeof(encode), &len, src_bin, sizeof(src_bin));
    ESP_LOGI(TAG, "base64 encode data, len:%u", len);
    ESP_LOGI(TAG, "%s", encode);

    mbedtls_base64_decode(decode, sizeof(decode), &len, (unsigned char *)src_base64, strlen(src_base64));
    ESP_LOGI(TAG, "base64 decode data, len:%u", len);
    ESP_LOG_BUFFER_HEX(TAG, decode, len);
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
    const int *list = NULL;
    const mbedtls_md_info_t *md_info = NULL;

    ESP_LOGI(TAG, "supported hash list:");
    list = mbedtls_md_list();
    while (*list) {
        md_info = mbedtls_md_info_from_type(*list);
        ESP_LOGI(TAG, "0x%04X %02uB %s", (*list), mbedtls_md_get_size(md_info), mbedtls_md_get_name(md_info));
        list++;
    }

    calc_md5(src_data, sizeof(src_data), hash, &hash_len);
    ESP_LOGI(TAG, "md5 data, len:%lu", hash_len);
    ESP_LOG_BUFFER_HEX(TAG, hash, hash_len);

    calc_sha1(src_data, sizeof(src_data), hash, &hash_len);
    ESP_LOGI(TAG, "sha1 data, len:%lu", hash_len);
    ESP_LOG_BUFFER_HEX(TAG, hash, hash_len);

    calc_sha256(src_data, sizeof(src_data), hash, &hash_len);
    ESP_LOGI(TAG, "sha256 data, len:%lu", hash_len);
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
    
    calc_hmac_sha256(src_data, sizeof(src_data), key, sizeof(key), hmac, &hmac_len);
    ESP_LOGI(TAG, "hmac sha256 data, len:%lu", hmac_len);
    ESP_LOG_BUFFER_HEX(TAG, hmac, hmac_len);
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
    uint8_t key[16] = {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F};
    uint8_t iv[16] = {0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF};
    uint8_t encode[512] = {0};
    uint8_t decode[512] = {0};
    uint32_t encode_len = 0, decode_len = 0;
    const mbedtls_cipher_info_t *cipher_info = NULL;
    const int *list = NULL;

    ESP_LOGI(TAG, "supported cipher list:");
    list = mbedtls_cipher_list();
    while (*list) {
        cipher_info = mbedtls_cipher_info_from_type(*list);
        ESP_LOGI(TAG, "0x%04X %02uB %03ub %s", (*list),
                                                mbedtls_cipher_info_get_block_size(cipher_info),
                                                mbedtls_cipher_info_get_key_bitlen(cipher_info),
                                                mbedtls_cipher_info_get_name(cipher_info));
        list++;
    }

    aes_cbc_encrypt(src_data, sizeof(src_data), key, sizeof(key), iv, sizeof(iv), encode, &encode_len);
    ESP_LOGI(TAG, "aes-128_cbc encode data, len:%lu", encode_len); // multiple(blocks + 1) of BLOCK_SIZE
    ESP_LOG_BUFFER_HEX(TAG, encode, encode_len);

    aes_cbc_decrypt(encode, encode_len, key, sizeof(key), iv, sizeof(iv), decode, &decode_len);
    ESP_LOGI(TAG, "aes-128_cbc decode data, len:%lu", decode_len); // src_len
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
    uint8_t key[16] = {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F};
    uint8_t iv[16] = {0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF};
    uint8_t encode[512] = {0};
    uint8_t decode[512] = {0};
    uint32_t encode_len = 0, decode_len = 0;
    const mbedtls_cipher_info_t *cipher_info = NULL;
    const int *list = NULL;

    ESP_LOGI(TAG, "supported cipher list:");
    list = mbedtls_cipher_list();
    while (*list) {
        cipher_info = mbedtls_cipher_info_from_type(*list);
        ESP_LOGI(TAG, "0x%04X %02uB %03ub %s", (*list),
                                                mbedtls_cipher_info_get_block_size(cipher_info),
                                                mbedtls_cipher_info_get_key_bitlen(cipher_info),
                                                mbedtls_cipher_info_get_name(cipher_info));
        list++;
    }

    aes_ctr_encrypt(src_data, sizeof(src_data), key, sizeof(key), iv, sizeof(iv), encode, &encode_len);
    ESP_LOGI(TAG, "aes-128_ctr encode data, len:%lu", encode_len); // src_len
    ESP_LOG_BUFFER_HEX(TAG, encode, encode_len);

    aes_ctr_decrypt(encode, encode_len, key, sizeof(key), iv, sizeof(iv), decode, &decode_len);
    ESP_LOGI(TAG, "aes-128_ctr decode data, len:%lu", decode_len); // src_len
    ESP_LOG_BUFFER_HEX(TAG, decode, decode_len);
}

void test_mpi() {
    mbedtls_mpi E, P, Q, N, H, D, M, C, Z;

    mbedtls_mpi_init(&E); mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&N); mbedtls_mpi_init(&H); mbedtls_mpi_init(&D);
    mbedtls_mpi_init(&M); mbedtls_mpi_init(&C);mbedtls_mpi_init(&Z);

    mbedtls_mpi_read_string(&P, 10, "2789");
    mbedtls_mpi_read_string(&Q, 10, "3203");
    mbedtls_mpi_mul_mpi(&N, &P, &Q); // N = P * Q

    mbedtls_mpi_sub_int(&P, &P, 1);
    mbedtls_mpi_sub_int(&Q, &Q, 1);
    mbedtls_mpi_mul_mpi(&H, &P, &Q); // H = (P-1) * (Q-1)

    mbedtls_mpi_read_string(&E, 10, "257"); // E
    mbedtls_mpi_inv_mod(&D, &E, &H);        // D = E^-1 mod H

    mbedtls_mpi_read_string(&M, 10, "12345");   // M, src_data
    mbedtls_mpi_exp_mod(&C, &M, &E, &N, NULL);  // C = M^E mod N, encrypt 
    mbedtls_mpi_exp_mod(&Z, &C, &D, &N, NULL);  // Z = C^D mod N, decrypt

    ESP_LOGI(TAG, "mpi_data:");
    mbedtls_mpi_write_file("src_data   = ", &M, 10, NULL);
    mbedtls_mpi_write_file("ciphertext = 0x", &C, 16, NULL);
    mbedtls_mpi_write_file("plaintext  = ", &Z, 10, NULL);

    mbedtls_mpi_free(&E); mbedtls_mpi_free(&P); mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&N); mbedtls_mpi_free(&H); mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&M); mbedtls_mpi_free(&C); mbedtls_mpi_free(&Z);
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
    mbedtls_mpi N, P, Q, D, E;

    mbedtls_mpi_init(&N); mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D); mbedtls_mpi_init(&E);

    rsa_gen_keypair(&N, &P, &Q, &D, &E);
    ESP_LOGI(TAG, "rsa pubkey:");
    mbedtls_mpi_write_file("N = ", &N, 16, NULL);
    mbedtls_mpi_write_file("E = ", &E, 16, NULL);
    ESP_LOGI(TAG, "rsa privkey:");
    mbedtls_mpi_write_file("N = ", &N, 16, NULL);
    mbedtls_mpi_write_file("E = ", &E, 16, NULL);
    mbedtls_mpi_write_file("D = ", &D, 16, NULL);
    mbedtls_mpi_write_file("P = ", &P, 16, NULL);
    mbedtls_mpi_write_file("Q = ", &Q, 16, NULL);

    rsa_encrypt(src_data, sizeof(src_data), &N, &E, encode, &encode_len);
    ESP_LOGI(TAG, "rsa encode data, len:%lu", encode_len); // multiple(blocks or blocks + 1) of KEY_SIZE / 8
    ESP_LOG_BUFFER_HEX(TAG, encode, encode_len);

    rsa_decrypt(encode, encode_len, &N, &P, &Q, &D, &E, decode, sizeof(decode), &decode_len);
    ESP_LOGI(TAG, "rsa decode data, len:%lu", decode_len); // src_len
    ESP_LOG_BUFFER_HEX(TAG, decode, decode_len);

    mbedtls_mpi_free(&N); mbedtls_mpi_free(&P); mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D); mbedtls_mpi_free(&E);
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
    mbedtls_mpi N, P, Q, D, E;

    mbedtls_mpi_init(&N); mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D); mbedtls_mpi_init(&E);

    rsa_gen_keypair(&N, &P, &Q, &D, &E);
    ESP_LOGI(TAG, "rsa pubkey:");
    mbedtls_mpi_write_file("N = ", &N, 16, NULL);
    mbedtls_mpi_write_file("E = ", &E, 16, NULL);
    ESP_LOGI(TAG, "rsa privkey:");
    mbedtls_mpi_write_file("N = ", &N, 16, NULL);
    mbedtls_mpi_write_file("E = ", &E, 16, NULL);
    mbedtls_mpi_write_file("D = ", &D, 16, NULL);
    mbedtls_mpi_write_file("P = ", &P, 16, NULL);
    mbedtls_mpi_write_file("Q = ", &Q, 16, NULL);

    calc_sha256(src_data, sizeof(src_data), hash, &hash_len);
    ESP_LOGI(TAG, "sha256 data, len:%lu", hash_len); // 32B
    ESP_LOG_BUFFER_HEX(TAG, hash, hash_len);

    rsa_sign(hash, hash_len, &N, &P, &Q, &D, &E, sign, &sign_len);
    ESP_LOGI(TAG, "rsa sign data, len:%lu", sign_len); // KEY_SIZE / 8
    ESP_LOG_BUFFER_HEX(TAG, sign, sign_len);

    ret = rsa_verify(hash, hash_len, &N, &E, sign);
    ESP_LOGI(TAG, "rsa verify ret:%d", ret);

    mbedtls_mpi_free(&N); mbedtls_mpi_free(&P); mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D); mbedtls_mpi_free(&E);
}

void test_rsa_pk_crypt()
{
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

    rsa_pk_gen_keypair(pubkey, 2048, &pubkey_len, privkey, 2048, &privkey_len);
#if CONFIG_RSA_KEYPAIR_FORMAT_PEM == 1
    ESP_LOGI(TAG, "rsa pubkey pem, len:%lu", pubkey_len);
    ESP_LOGI(TAG, "%s", pubkey);
    ESP_LOGI(TAG, "rsa privkey pem, len:%lu", privkey_len);
    ESP_LOGI(TAG, "%s", privkey);
#else
    ESP_LOGI(TAG, "rsa pubkey der, len:%lu", pubkey_len);
    ESP_LOG_BUFFER_HEX(TAG, pubkey, pubkey_len);
    ESP_LOGI(TAG, "rsa privkey der, len:%lu", privkey_len);
    ESP_LOG_BUFFER_HEX(TAG, privkey, privkey_len);
#endif

    rsa_pk_encrypt(src_data, sizeof(src_data), pubkey, pubkey_len, encode, sizeof(encode), &encode_len);
    ESP_LOGI(TAG, "rsa encode data, len:%lu", encode_len); // multiple(blocks or blocks + 1) of KEY_SIZE / 8
    ESP_LOG_BUFFER_HEX(TAG, encode, encode_len);

    rsa_pk_decrypt(encode, encode_len, privkey, privkey_len, decode, sizeof(decode), &decode_len);
    ESP_LOGI(TAG, "rsa decode data, len:%lu", decode_len); // src_len
    ESP_LOG_BUFFER_HEX(TAG, decode, decode_len);

    vPortFree(pubkey);
    vPortFree(privkey);
}

void test_rsa_pk_sign() {
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

    rsa_pk_gen_keypair(pubkey, 2048, &pubkey_len, privkey, 2048, &privkey_len);
#if CONFIG_RSA_KEYPAIR_FORMAT_PEM == 1
    ESP_LOGI(TAG, "rsa pubkey pem, len:%lu", pubkey_len);
    ESP_LOGI(TAG, "%s", pubkey);
    ESP_LOGI(TAG, "rsa privkey pem, len:%lu", privkey_len);
    ESP_LOGI(TAG, "%s", privkey);
#else
    ESP_LOGI(TAG, "rsa pubkey der, len:%lu", pubkey_len);
    ESP_LOG_BUFFER_HEX(TAG, pubkey, pubkey_len);
    ESP_LOGI(TAG, "rsa privkey der, len:%lu", privkey_len);
    ESP_LOG_BUFFER_HEX(TAG, privkey, privkey_len);
#endif

    calc_sha256(src_data, sizeof(src_data), hash, &hash_len);
    ESP_LOGI(TAG, "sha256 data, len:%lu", hash_len); // 32B
    ESP_LOG_BUFFER_HEX(TAG, hash, hash_len);

    rsa_pk_sign(hash, hash_len, privkey, privkey_len, sign, sizeof(sign), &sign_len);
    ESP_LOGI(TAG, "rsa sign data, len:%lu", sign_len); // KEY_SIZE / 8
    ESP_LOG_BUFFER_HEX(TAG, sign, sign_len);

    ret = rsa_pk_verify(hash, hash_len, pubkey, pubkey_len, sign, sign_len);
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
    mbedtls_mpi r;       // sign part 1
    mbedtls_mpi s;       // sign part 2
    int ret = -1;
    mbedtls_mpi d;       // privkey
    mbedtls_ecp_point Q; // pubkey
    const mbedtls_ecp_curve_info *curve_info = NULL;

    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    mbedtls_ecp_point_init(&Q);
    
    ESP_LOGI(TAG, "supported ecc curve list:");
    curve_info = mbedtls_ecp_curve_list();
    while (curve_info->name) {
        ESP_LOGI(TAG, "0x%04X 0x%04X %03u %s", curve_info->grp_id, curve_info->tls_id, curve_info->bit_size, curve_info->name);
        curve_info++;
    }

    ecc_gen_keypair(&d, &Q);
    ESP_LOGI(TAG, "ecc pubkey:");
    mbedtls_mpi_write_file("Q.X = ", &Q.private_X, 16, NULL);
    mbedtls_mpi_write_file("Q.Y = ", &Q.private_Y, 16, NULL);
    ESP_LOGI(TAG, "ecc privkey:");
    mbedtls_mpi_write_file("d = ", &d, 16, NULL);

    calc_sha256(src_data, sizeof(src_data), hash, &hash_len);
    ESP_LOGI(TAG, "sha256 data, len:%lu", hash_len); // 32B
    ESP_LOG_BUFFER_HEX(TAG, hash, hash_len);

    ecc_sign(hash, hash_len, &d, &r, &s);
    ESP_LOGI(TAG, "ecc sign data:");
    mbedtls_mpi_write_file("r = ", &r, 16, NULL); // grp.bit_size / 8
    mbedtls_mpi_write_file("s = ", &s, 16, NULL); // grp.bit_size / 8

    ret = ecc_verify(hash, hash_len, &Q, &r, &s);
    ESP_LOGI(TAG, "ecc verify ret:%d", ret);

    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_point_free(&Q);
}

void test_ecc_pk_sign() {
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

    ecc_pk_gen_keypair(pubkey, 2048, &pubkey_len, privkey, 2048, &privkey_len);
#if CONFIG_ECC_KEYPAIR_FORMAT_PEM == 1
    ESP_LOGI(TAG, "ecc pubkey pem, len:%lu", pubkey_len);
    ESP_LOGI(TAG, "%s", pubkey);
    ESP_LOGI(TAG, "ecc privkey pem, len:%lu", privkey_len);
    ESP_LOGI(TAG, "%s", privkey);
#else
    ESP_LOGI(TAG, "ecc pubkey der, len:%lu", pubkey_len);
    ESP_LOG_BUFFER_HEX(TAG, pubkey, pubkey_len);
    ESP_LOGI(TAG, "ecc privkey der, len:%lu", privkey_len);
    ESP_LOG_BUFFER_HEX(TAG, privkey, privkey_len);
#endif

    calc_sha256(src_data, sizeof(src_data), hash, &hash_len);
    ESP_LOGI(TAG, "sha256 data, len:%lu", hash_len); // 32B
    ESP_LOG_BUFFER_HEX(TAG, hash, hash_len);

    ecc_pk_sign(hash, hash_len, privkey, privkey_len, sign, sizeof(sign), &sign_len);
    ESP_LOGI(TAG, "ecc sign data, len:%lu", sign_len); // der_header + 2 * grp.bit_size / 8
    ESP_LOG_BUFFER_HEX(TAG, sign, sign_len);

    ret = ecc_pk_verify(hash, hash_len, pubkey, pubkey_len, sign, sign_len);
    ESP_LOGI(TAG, "ecc verify ret:%d", ret);

    vPortFree(pubkey);
    vPortFree(privkey);
}

void test_x509_crt() {
    uint8_t *subject_pubkey = NULL, *subject_privkey = NULL, *subject_csr = NULL, *subject_crt = NULL;
    uint8_t *issuer_pubkey = NULL, *issuer_privkey = NULL, *issuer_csr = NULL, *issuer_crt = NULL;
    uint32_t subject_pubkey_len = 0, subject_privkey_len = 0, subject_csr_len = 0, subject_crt_len = 0;
    uint32_t issuer_pubkey_len = 0, issuer_privkey_len = 0, issuer_csr_len = 0, issuer_crt_len = 0;
    subject_pubkey = pvPortMalloc(2048);
    subject_privkey = pvPortMalloc(2048);
    subject_csr = pvPortMalloc(2048);
    subject_crt = pvPortMalloc(2048);
    issuer_pubkey = pvPortMalloc(2048);
    issuer_privkey = pvPortMalloc(2048);
    issuer_csr = pvPortMalloc(2048);
    issuer_crt = pvPortMalloc(2048);
    int ret = -1;
    uint32_t flags = 0;
    char verify_info[128] = {0};
    char *subject_name = "C=CN,ST=ZJ,L=HZ,O=esp32,OU=espressif,CN=*.subject.com";
    char *issuer_name  = "C=CN,ST=ZJ,L=HZ,O=esp32,OU=espressif,CN=*.issuer.com";
    char *not_before = "20250101000000";
    char *not_after = "20291231235959";

    // generate issuer ecc keypair
    ecc_pk_gen_keypair(issuer_pubkey, 2048, &issuer_pubkey_len, issuer_privkey, 2048, &issuer_privkey_len);
#if CONFIG_ECC_KEYPAIR_FORMAT_PEM == 1
    ESP_LOGI(TAG, "issuer ecc pubkey pem, len:%lu", issuer_pubkey_len);
    ESP_LOGI(TAG, "%s", issuer_pubkey);
    ESP_LOGI(TAG, "issuer ecc privkey pem, len:%lu", issuer_privkey_len);
    ESP_LOGI(TAG, "%s", issuer_privkey);
#else
    ESP_LOGI(TAG, "issuer ecc pubkey der, len:%lu", issuer_pubkey_len);
    ESP_LOG_BUFFER_HEX(TAG, issuer_pubkey, issuer_pubkey_len);
    ESP_LOGI(TAG, "issuer ecc privkey der, len:%lu", issuer_privkey_len);
    ESP_LOG_BUFFER_HEX(TAG, issuer_privkey, issuer_privkey_len);
#endif

    // generate subject rsa keypair
    rsa_pk_gen_keypair(subject_pubkey, 2048, &subject_pubkey_len, subject_privkey, 2048, &subject_privkey_len);
#if CONFIG_ECC_KEYPAIR_FORMAT_PEM == 1
    ESP_LOGI(TAG, "subject rsa pubkey pem, len:%lu", subject_pubkey_len);
    ESP_LOGI(TAG, "%s", subject_pubkey);
    ESP_LOGI(TAG, "subject rsa privkey pem, len:%lu", subject_privkey_len);
    ESP_LOGI(TAG, "%s", subject_privkey);
#else
    ESP_LOGI(TAG, "subject rsa pubkey der, len:%lu", subject_pubkey_len);
    ESP_LOG_BUFFER_HEX(TAG, subject_pubkey, subject_pubkey_len);
    ESP_LOGI(TAG, "subject rsa privkey der, len:%lu", subject_privkey_len);
    ESP_LOG_BUFFER_HEX(TAG, subject_privkey, subject_privkey_len);
#endif

    // generate issuer csr
    x509_crt_csr(issuer_privkey, issuer_privkey_len, issuer_name, issuer_csr, 2048, &issuer_csr_len);
#if CONFIG_X509_CSR_FORMAT_PEM == 1
    ESP_LOGI(TAG, "issuer csr pem, len:%lu", issuer_csr_len);
    ESP_LOGI(TAG, "%s", issuer_csr);
#else
    ESP_LOGI(TAG, "issuer csr der, len:%lu", issuer_csr_len);
    ESP_LOG_BUFFER_HEX(TAG, issuer_csr, issuer_csr_len);
#endif

    // generate subject csr
    x509_crt_csr(subject_privkey, subject_privkey_len, subject_name, subject_csr, 2048, &subject_csr_len);
#if CONFIG_X509_CSR_FORMAT_PEM == 1
    ESP_LOGI(TAG, "subject csr pem, len:%lu", subject_csr_len);
    ESP_LOGI(TAG, "%s", subject_csr);
#else
    ESP_LOGI(TAG, "subject csr der, len:%lu", subject_csr_len);
    ESP_LOG_BUFFER_HEX(TAG, subject_csr, subject_csr_len);
#endif

    // self-sign issuer crt
    x509_crt_sign(issuer_csr, issuer_csr_len, issuer_privkey, issuer_privkey_len, issuer_name, not_before, not_after, 1, issuer_crt, 2048, &issuer_crt_len);
#if CONFIG_X509_CRT_FORMAT_PEM == 1
    ESP_LOGI(TAG, "issuer crt pem, len:%lu", issuer_crt_len);
    ESP_LOGI(TAG, "%s", issuer_crt);
#else
    ESP_LOGI(TAG, "issuer crt der, len:%lu", issuer_crt_len);
    ESP_LOG_BUFFER_HEX(TAG, issuer_crt, issuer_crt_len);
#endif

    // sign subject crt by issuer
    x509_crt_sign(subject_csr, subject_csr_len, issuer_privkey, issuer_privkey_len, issuer_name, not_before, not_after, 0, subject_crt, 2048, &subject_crt_len);
#if CONFIG_X509_CRT_FORMAT_PEM == 1
    ESP_LOGI(TAG, "subject crt pem, len:%lu", subject_crt_len);
    ESP_LOGI(TAG, "%s", subject_crt);
#else
    ESP_LOGI(TAG, "subject crt der, len:%lu", subject_crt_len);
    ESP_LOG_BUFFER_HEX(TAG, subject_crt, subject_crt_len);
#endif

    // verify self-sign issuer crt
    ret = x509_crt_verify(issuer_crt, issuer_crt_len, issuer_crt, issuer_crt_len, &flags);
    ESP_LOGI(TAG, "issuer crt verify:%d", ret);
    if (ret) {
        mbedtls_x509_crt_verify_info(verify_info, sizeof(verify_info), " ", flags);
        ESP_LOGE(TAG, "issuer crt verify failed:%s", verify_info);
    }

    // verify subject crt by issuer crt
    ret = x509_crt_verify(subject_crt, subject_crt_len, issuer_crt, issuer_crt_len, &flags);
    ESP_LOGI(TAG, "subject crt verify:%d", ret);
    if (ret) {
        mbedtls_x509_crt_verify_info(verify_info, sizeof(verify_info), " ", flags);
        ESP_LOGE(TAG, "subject crt verify failed:%s", verify_info);
    }

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
    test_aes_cbc();
    test_aes_ctr();
    test_mpi();
    test_rsa_crypt();
    test_rsa_sign();
    test_rsa_pk_crypt();
    test_rsa_pk_sign();
    test_ecc_sign();
    test_ecc_pk_sign();
    test_x509_crt();
    ESP_LOGI(TAG, "test complete");
    
    vTaskDelete(NULL);
}


void app_main(void) {
    xTaskCreate(test_algorithm_cb, "test_algorithm", 8192, NULL, 1, NULL);

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
