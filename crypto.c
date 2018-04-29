#include <openssl/cmac.h>
#include <openssl/conf.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <string.h>
#include <stdio.h>
#include <sgx_key_exchange.h>
#include "crypto.h"

static enum _error_type {
	e_none,
	e_crypto,
	e_system,
	e_api
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
	else if ( error_type == e_api ) fprintf(stderr, "invalid parameter\n");
	else fprintf(stderr, "unknown error\n");
}

/*==========================================================================
 * EC key functions 
 *========================================================================== */

/* Load an EC key from a file in PEM format */

int key_load (EVP_PKEY **pkey, const char *hexstring, int keytype)
{
	EC_KEY *eckey= NULL;
	BIGNUM *gx= NULL;
	BIGNUM *gy= NULL;
	size_t slen, reqlen;

	error_type= e_none;

	/* Make sure we were sent a proper hex string for a key */
	if ( hexstring == NULL ) {
		error_type= e_api;
		return 0;
	}

	slen= strlen(hexstring);
	if ( keytype == KEY_PRIVATE ) reqlen=64;
	else if ( keytype == KEY_PUBLIC ) reqlen= 128;
	else {
		error_type= e_api;
		return 0;
	}
	if ( slen != reqlen ) {
		error_type= e_api;
		return 0;
	}

	eckey= EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if ( eckey == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( keytype == KEY_PRIVATE ) {
		EC_POINT *pubpt= NULL;
		const EC_GROUP *group= NULL;
		BN_CTX *ctx;

		ctx= BN_CTX_new();

		/* hexstring is the private key; we'll use gx even though that's
		 * not technically what it is. :)  */

		if ( ! BN_hex2bn(&gx, hexstring) ) {
			error_type= e_crypto;
			goto cleanup;
		}

		if ( ! EC_KEY_set_private_key(eckey, gx) ) {
			error_type= e_crypto;
			goto cleanup;
		}

		/* Set the public key from the private key */

		group= EC_KEY_get0_group(eckey);

		pubpt= EC_POINT_new(group);
		if ( pubpt == NULL ) {
			BN_CTX_free(ctx);
			error_type= e_crypto;
			goto cleanup;
		}

		if ( ! EC_POINT_mul(group, pubpt, gx, NULL, NULL,
			NULL) ) {

			BN_CTX_free(ctx);
			EC_POINT_free(pubpt);

			error_type= e_crypto;
			goto cleanup;
		}

		BN_CTX_free(ctx);

		if ( ! EC_KEY_set_public_key(eckey, pubpt) ) {
			EC_POINT_free(pubpt);

			EC_POINT_free(pubpt);

			error_type= e_crypto;
			goto cleanup;
		}

		EC_POINT_free(pubpt);
	} else if ( keytype == KEY_PUBLIC ) {
		/*
		 * hex2bn expects a NULL terminated string, so need to 
		 * pull out the x component
		 */

		char cx[65];

		memcpy(cx, hexstring, 64);
		cx[64]= 0;

		if ( ! BN_hex2bn(&gx, cx) ) {
			error_type= e_crypto;
			goto cleanup;
		}

		if ( ! BN_hex2bn(&gy, &hexstring[64]) ) {
			error_type= e_crypto;
			goto cleanup;
		}

		if ( ! EC_KEY_set_public_key_affine_coordinates(eckey, gx, gy) ) {
			error_type= e_crypto;
			goto cleanup;
		}
		
	} else {
		error_type= e_api;
		goto cleanup;
	}

	*pkey= EVP_PKEY_new();
	if ( *pkey == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! EVP_PKEY_set1_EC_KEY(*pkey, eckey) ) {
		error_type= e_crypto;
		*pkey= NULL;
	}

cleanup:
	if ( gy != NULL ) BN_free(gy);
	if ( gx != NULL ) BN_free(gx);
	/* if ( eckey != NULL ) EC_KEY_free(eckey); */

	return (error_type == e_none);
}

int key_load_file (EVP_PKEY **key, const char *filename, int keytype)
{
	FILE *fp;

	error_type= e_none;

	*key= EVP_PKEY_new();

	if ( (fp= fopen(filename, "r")) == NULL ) {
		error_type= e_system;
		ep= filename;
		return 0;
	}
	if ( keytype == KEY_PRIVATE ) PEM_read_PrivateKey(fp, key, NULL, NULL);
	else if ( keytype == KEY_PUBLIC ) PEM_read_PUBKEY(fp, key, NULL, NULL);
	else {
		error_type= e_api;
	}

	fclose(fp);

	return (error_type == e_none);
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
	if ( eckey == NULL ) {
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

EVP_PKEY *key_private_from_bytes (const unsigned char buf[32])
{
	
	EC_KEY *key= NULL;
	EVP_PKEY *pkey= NULL;
	BIGNUM *prv= NULL;

	error_type= e_none;

	key= EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if ( key == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( (prv= BN_lebin2bn((unsigned char *) buf, 32, NULL)) == NULL) {
		error_type= e_crypto;
		goto cleanup;
	}


	if ( ! EC_KEY_set_private_key(key, prv) ) {
		error_type= e_crypto;
		goto cleanup;
	}

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
	if ( prv != NULL ) BN_free(prv);
	if ( key != NULL ) EC_KEY_free(key);

	return pkey;
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

/*==========================================================================
 * AES-CMAC
 *========================================================================== */

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

/*==========================================================================
 * SHA
 *========================================================================== */

int sha256_digest(unsigned char *msg, size_t mlen, unsigned char digest[32])
{
	EVP_MD_CTX *ctx;

	error_type= e_none;

	memset(digest, 0, 32);

	ctx= EVP_MD_CTX_new();
	if ( ctx == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( EVP_DigestInit(ctx, EVP_sha256()) != 1 ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( EVP_DigestUpdate(ctx, msg, mlen) != 1 ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( EVP_DigestFinal(ctx, digest, NULL) != 1 ) {
		error_type= e_crypto;
		goto cleanup;
	}

cleanup:
	if ( ctx != NULL ) EVP_MD_CTX_destroy(ctx);
	return ( error_type == e_none );
}

/*==========================================================================
 * ECDSA
 *========================================================================== */

int ecdsa_sign(unsigned char *msg, size_t mlen, EVP_PKEY *key,
	unsigned char r[32], unsigned char s[32], unsigned char digest[32])
{
	ECDSA_SIG *sig;
	EC_KEY *eckey;
	const BIGNUM *bnr= NULL;
	const BIGNUM *bns= NULL;

	error_type= e_none;

	eckey= EVP_PKEY_get1_EC_KEY(key);
	if ( eckey == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}  

	/* In ECDSA signing, we sign the sha256 digest of the message */

	if ( ! sha256_digest(msg, mlen, digest) ) {
		error_type= e_crypto;
		goto cleanup;
	}

	sig= ECDSA_do_sign(digest, 32, eckey);
	if ( sig == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	ECDSA_SIG_get0(sig, &bnr, &bns);

	if ( ! BN_bn2binpad(bnr, r, 32) ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! BN_bn2binpad(bns, s, 32) ) {
		error_type= e_crypto;
		goto cleanup;
	}

cleanup:
	if ( sig != NULL ) ECDSA_SIG_free(sig);
	if ( eckey != NULL ) EC_KEY_free(eckey);
	return (error_type == e_none);
}

