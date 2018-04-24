#include <openssl/cmac.h>
#include <openssl/conf.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <stdio.h>
#include <sgx_key_exchange.h>
#include "crypto.h"

static enum _error_type {
	e_none,
	e_crypto,
	e_system
} error_type= e_none;

static const char *ep= NULL;

void crypto_init ()
{
	/* Load error strings for libcrypto */
	ERR_load_crypto_strings();

	/* Load digest and ciphers */
	OpenSSL_add_all_algorithms();
}

void crypto_destroy ()
{
	EVP_cleanup();

	CRYPTO_cleanup_all_ex_data();

	ERR_free_strings();
}

/* Print the error */

void crypto_perror (const char *prefix)
{
	fprintf(stderr, "%s: ", prefix);
	if ( error_type == e_none ) fprintf(stderr, "no error\n");
	else if ( error_type == e_system ) perror(ep);
	else if ( error_type == e_crypto ) ERR_print_errors_fp(stderr);
}

/*============================================================================
 * EC key functions 
 *============================================================================ */

/* Load an EC key from a file in PEM format */

int key_load_file (EVP_PKEY **key, const char *filename)
{
	FILE *fp;

	error_type= e_none;

	*key= EVP_PKEY_new();

	if ( (fp= fopen(filename, "r")) == NULL ) {
		error_type= e_system;
		ep= filename;
		return 0;
	}
	PEM_read_PrivateKey(fp, key, NULL, NULL);
	fclose(fp);

	return 1;
}

int key_to_sgx_ec256 (sgx_ec256_public_t *k, EVP_PKEY *key)
{
	EC_KEY *eckey= NULL;
	const EC_POINT *ecpt= NULL;
	EC_GROUP *ecgroup= NULL;
	BIGNUM *gx= NULL;
	BIGNUM *gy= NULL;

	error_type= e_none;

	eckey= EVP_PKEY_get1_EC_KEY(key);
	if ( key == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	ecgroup= EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	if ( ecgroup == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	ecpt= EC_KEY_get0_public_key(eckey);

	gx= BN_new();
	if ( gx == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	gy= BN_new();
	if ( gy == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! EC_POINT_get_affine_coordinates_GFp(ecgroup, ecpt, gx, gy, NULL) ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! BN_bn2lebinpad(gx, k->gx, sizeof(k->gx)) ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! BN_bn2lebinpad(gy, k->gy, sizeof(k->gy)) ) {
		error_type= e_crypto;
		goto cleanup;
	}

cleanup:
	if ( gy != NULL ) BN_free(gy);
	if ( gx != NULL ) BN_free(gx);
	if ( ecgroup != NULL ) EC_GROUP_free(ecgroup);
	return (error_type == e_none);
}

EVP_PKEY *key_from_sgx_ec256 (sgx_ec256_public_t *k)
{
	EC_KEY *key= NULL;
	EVP_PKEY *pkey= NULL;

	error_type= e_none;

	BIGNUM *gx= NULL;
	BIGNUM *gy= NULL;

	/* Get gx and gy as BIGNUMs */

	if ( (gx= BN_lebin2bn((unsigned char *) k->gx, sizeof(k->gx), NULL)) == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( (gy= BN_lebin2bn((unsigned char *) k->gy, sizeof(k->gy), NULL)) == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	key= EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if ( key == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! EC_KEY_set_public_key_affine_coordinates(key, gx, gy) ) {
		EC_KEY_free(key);
		key= NULL;
		error_type= e_crypto;
		goto cleanup;
	}

	/* Get the peer key as an EVP_PKEY object */

	pkey= EVP_PKEY_new();
	if ( pkey == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! EVP_PKEY_set1_EC_KEY(pkey, key) ) {
		error_type= e_crypto;
		EVP_PKEY_free(pkey);
		pkey= NULL;
	}

cleanup:
	if ( key != NULL ) EC_KEY_free(key);
	if ( gy != NULL ) BN_free(gy);
	if ( gx != NULL ) BN_free(gx);

	return pkey;
}

/* Generate a new EC key. */

EVP_PKEY *key_generate()
{
	EVP_PKEY *key= NULL;
	EVP_PKEY_CTX *pctx= NULL;
	EVP_PKEY_CTX *kctx= NULL;
	EVP_PKEY *params= NULL;

	error_type= e_none;

	/* Set up the parameter context */
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
		EVP_PKEY_free(key);
		key= NULL;
	}

cleanup:
	if ( kctx != NULL ) EVP_PKEY_CTX_free(kctx);
	if ( params != NULL ) EVP_PKEY_free(params);
	if ( pctx != NULL ) EVP_PKEY_CTX_free(pctx);

	return key;
}

/* Compute a shared secret using the peer's public key and a generated key */

unsigned char *key_shared_secret (EVP_PKEY *key, EVP_PKEY *peerkey, size_t *slen)
{
	EVP_PKEY_CTX *sctx= NULL;
	unsigned char *secret= NULL;

	*slen= 0;
	error_type= e_none;

	/* Set up the shared secret derivation */

	sctx= EVP_PKEY_CTX_new(key, NULL);
	if ( sctx == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! EVP_PKEY_derive_init(sctx) ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! EVP_PKEY_derive_set_peer(sctx, peerkey) ) {
		error_type= e_crypto;
		goto cleanup;
	}

	/* Get the secret length */

	if ( ! EVP_PKEY_derive(sctx, NULL, slen) ) {
		error_type= e_crypto;
		goto cleanup;
	}

	secret= OPENSSL_malloc(*slen);
	if ( secret == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	/* Derive the shared secret */

	if ( ! EVP_PKEY_derive(sctx, secret, slen) ) {
		error_type= e_crypto;
		OPENSSL_free(secret);
		secret= NULL;
	}

cleanup:
	if ( sctx != NULL ) EVP_PKEY_CTX_free(sctx);

	return secret;
}

/*============================================================================
 * AES-CMAC
 *============================================================================ */

int cmac128(unsigned char key[16], unsigned char *message, size_t mlen,
	unsigned char mac[16])
{
	size_t maclen;
	error_type= e_none;


	CMAC_CTX *ctx= CMAC_CTX_new();
	if ( ctx == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL) ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! CMAC_Update(ctx, message, mlen) ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! CMAC_Final(ctx, mac, &maclen) ) error_type= e_crypto;

cleanup:
	if ( ctx != NULL ) CMAC_CTX_free(ctx);
	return (error_type == e_none);
}

/*============================================================================
 * ECDSA
 *============================================================================ */

int ecdsa_sign(unsigned char *msg, size_t mlen, EVP_PKEY *key,
	unsigned char hash[64])
{
	ECDSA_SIG *sig;
	EC_KEY *eckey;
	BIGNUM *r, *s;

	error_type= e_none;

	eckey= EVP_PKEY_get1_EC_KEY(key);
	if ( eckey == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	sig= ECDSA_do_sign(msg, mlen, eckey);
	
	/* 
	 * OpenSSL represents ECDSA_SIG as two BIGNUMs, r and s. Turn these into
	 * byte streams, in little endian format, assuming 32-byte integers.
	 */

	if ( ! ECDSA_SIG_set0(sig, r, s) ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! BN_bn2lebinpad(r, hash, 32) ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! BN_bn2lebinpad(s, &hash[32], 32) ) {
		error_type= e_crypto;
		goto cleanup;
	}

cleanup:
	if ( sig != NULL ) ECDSA_SIG_free(sig);
	if ( eckey != NULL ) EC_KEY_free(eckey);
	return (error_type == e_none);
}

