#ifndef __ECKEY__H
#define __ECKEY__H

#include <openssl/ec.h>
#include <sgx_key_exchange.h>

#ifdef __cplusplus
extern "C" {
#endif

int key_load_file (EC_KEY **eckey, const char *filename);
int key_shared_secret (unsigned char **secret, sgx_ec256_public_t *g_a);
void key_perror (const char *prefix);

#ifdef __cplusplus
};
#endif

#endif
