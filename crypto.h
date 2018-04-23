#ifndef _CRYPTO_INIT_H
#define _CRYPTO_INIT_H

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

int key_load_file (EC_KEY **eckey, const char *filename);
EC_KEY *key_from_sgx_ec256 (sgx_ec256_public_t k);
unsigned char *key_shared_secret (EC_KEY *g_a, size_t *slen);

/* ECDSA signature */

int ecdsa_sign(unsigned char *msg, size_t mlen, unsigned char hash[64]);

#ifdef __cplusplus
};
#endif

#endif

