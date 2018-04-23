#ifndef __ECKEY__H
#define __ECKEY__H

#include <openssl/ec.h>
#include <sgx_key_exchange.h>
#include <sgx_tcrypto.h>

#ifdef __cplusplus
extern "C" {
#endif

int key_load_file (EC_KEY **eckey, const char *filename);
EC_KEY *key_from_sgx_ec256 (sgx_ec256_public_t k);
unsigned char *key_shared_secret (EC_KEY *g_a, size_t *slen);

void key_perror (const char *prefix);


#ifdef __cplusplus
};
#endif

#endif
