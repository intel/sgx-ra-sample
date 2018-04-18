#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <stdio.h>
#include "eckey.h"

static enum _error_type {
	e_none,
	e_crypto,
	e_system
} error_type= e_none;

static const char *ep= NULL;

/* Load an EC key from a file in PEM format */

int key_load_file (EC_KEY **eckey, const char *filename)
{
	EVP_PKEY *key;
	FILE *fp;

	error_type= e_none;

	key= EVP_PKEY_new();

	if ( (fp= fopen(filename, "r")) == NULL ) {
		error_type= e_system;
		ep= filename;
		return 0;
	}
	PEM_read_PrivateKey(fp, &key, NULL, NULL);
	fclose(fp);

	*eckey= EVP_PKEY_get1_EC_KEY(key);
	if ( *eckey == NULL ) {
		error_type= e_crypto;
		return 0;
	}

	return 1;
}

int key_from_sgx_ec256 (sgx_ec256_public_t *k)
{
	error_type= e_none;

	BIGNUM gx, gy;

	/* Get gx and gy as BIGNUMs */

	if ( BN_lebin2bn((unsigned char *) k->gx, 32, &gx) == NULL ) {
		error_type= e_crypto;
		return 0;
	}

	if ( BN_lebin2bn((unsigned char *) k->gy, 32, &gy) == NULL ) {
		error_type= e_crypto;
		return 0;
	}

	return 1;
}

/* Compute a shared secret using the peer's public key and a generated key */

int key_shared_secret (unsigned char **secret, sgx_ec256_public_t *g_a)
{
	EVP_PKEY_CTX *pctx= NULL;
	EVP_PKEY_CTX *kctx= NULL;
	EVP_PKEY_CTX *sctx= NULL;
	EVP_PKEY *params= NULL;
	EVP_PKEY *key;

	error_type= e_none;

	/* Generate a new EC key. */

	/* Set up the parameter context first */
	pctx= EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if ( pctx == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	/* Generate parameters for the P-256 curve */

	if ( ! EVP_PKEY_paramgen_init(pctx) ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! EVP_PKEY_paramgen(pctx, &params) ) {
		error_type= e_crypto;
		goto cleanup;
	}

	/* Generate the key */

	kctx= EVP_PKEY_CTX_new(params, NULL);
	if ( kctx == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! EVP_PKEY_keygen_init(kctx) ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! EVP_PKEY_keygen(kctx, &key) ) {
		error_type= e_crypto;
		goto cleanup;
	}

cleanup:
	if ( key != NULL ) EVP_PKEY_free(key);
	if ( kctx != NULL ) EVP_PKEY_CTX_free(kctx);
	if ( params != NULL ) EVP_PKEY_free(params);
	if ( pctx != NULL ) EVP_PKEY_CTX_free(pctx);

	return (error_type == e_none);
}

/* Print the error */

void key_perror (const char *prefix)
{
	fprintf(stderr, "%s: ", prefix);
	if ( error_type == e_none ) fprintf(stderr, "no error\n");
	else if ( error_type == e_system ) perror(ep);
	else if ( error_type == e_crypto ) ERR_print_errors_fp(stderr);
}

