#ifndef _CRYPTO_INIT_H
#define _CRYPTO_INIT_H

#include <openssl/evp.h>
#include <sgx_key_exchange.h>

#define KEY_PUBLIC	0
#define KEY_PRIVATE	1

#ifdef __cplusplus
extern "C" {
#endif

/* General */
void crypto_init();
void crypto_destroy();

void crypto_perror (const char *prefix);

/*  AES-CMAC */

int cmac128(unsigned char key[16], unsigned char *message, size_t mlen,
	unsigned char mac[16]);

/* EC key operations */

int key_load_file (EVP_PKEY **key, const char *filename, int type);

EVP_PKEY *key_from_sgx_ec256 (sgx_ec256_public_t *k);
int key_to_sgx_ec256 (sgx_ec256_public_t *k, EVP_PKEY *key);

unsigned char *key_shared_secret (EVP_PKEY *key, EVP_PKEY *peerkey, size_t *slen);
EVP_PKEY *key_generate();

/* ECDSA signature */

int ecdsa_sign(unsigned char *msg, size_t mlen, EVP_PKEY *key,
	unsigned char hash[64]);

#ifdef __cplusplus
};
#endif

#endif

