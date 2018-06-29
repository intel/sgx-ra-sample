/*

Copyright 2018 Intel Corporation

This software and the related documents are Intel copyrighted materials,
and your use of them is governed by the express license under which they
were provided to you (License). Unless the License provides otherwise,
you may not use, modify, copy, publish, distribute, disclose or transmit
this software or the related documents without Intel's prior written
permission.

This software and the related documents are provided as is, with no
express or implied warranties, other than those that are expressly stated
in the License.

*/

#include <openssl/cmac.h>
#include <openssl/conf.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string.h>
#include <stdio.h>
#include <sgx_key_exchange.h>
#include "crypto.h"
#include "hexutil.h"

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

#ifdef _WIN32
	if ((fopen_s(&fp, filename, "r")) != 0) {
		error_type = e_system;
		ep = filename;
		return 0;
	}
#else
	if ( (fp= fopen(filename, "r")) == NULL ) {
		error_type= e_system;
		ep= filename;
		return 0;
	}
#endif

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

int sha256_digest(const unsigned char *msg, size_t mlen, unsigned char digest[32])
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
 * HMAC
 *========================================================================== */

int sha256_verify(const unsigned char *msg, size_t mlen, unsigned char *sig,
    size_t sigsz, EVP_PKEY *pkey, int *result)
{
	EVP_MD_CTX *ctx;

	error_type= e_none;

	ctx= EVP_MD_CTX_new();
	if ( ctx == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1 ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( EVP_DigestVerifyUpdate(ctx, msg, mlen) != 1 ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( EVP_DigestVerifyFinal(ctx, sig, sigsz) != 1 ) error_type= e_crypto;

cleanup:
	if ( ctx != NULL ) EVP_MD_CTX_free(ctx);
	return (error_type == e_none);
}


/*==========================================================================
 * ECDSA
 *========================================================================== */

int ecdsa_sign(unsigned char *msg, size_t mlen, EVP_PKEY *key,
	unsigned char r[32], unsigned char s[32], unsigned char digest[32])
{
	ECDSA_SIG *sig = NULL;
	EC_KEY *eckey = NULL;
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

/*==========================================================================
 * Certificate verification
 *========================================================================== */

int cert_load_file (X509 **cert, const char *filename)
{
	FILE *fp;

	error_type= e_none;


#ifdef _WIN32
	if ((fopen_s(&fp, filename, "r")) != 0) {
		error_type = e_system;
		ep = filename;
		return 0;
	}
#else
	if ((fp = fopen(filename, "r")) == NULL) {
		error_type = e_system;
		ep = filename;
		return 0;
	}
#endif


	*cert= PEM_read_X509(fp, NULL, NULL, NULL);
	if ( *cert == NULL ) error_type= e_crypto;

	fclose(fp);

	return (error_type == e_none);
}

int cert_load (X509 **cert, const char *pemdata)
{
	return cert_load_size(cert, pemdata, strlen(pemdata));
}

int cert_load_size (X509 **cert, const char *pemdata, size_t sz)
{
	BIO * bmem;
	error_type= e_none;

	bmem= BIO_new(BIO_s_mem());
	if ( bmem == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( BIO_write(bmem, pemdata, (int) sz) != (int) sz ) {
		error_type= e_crypto;
		goto cleanup;
	}

	*cert= PEM_read_bio_X509(bmem, NULL, NULL, NULL);
	if ( *cert == NULL ) error_type= e_crypto;

cleanup:
	if ( bmem != NULL ) BIO_free(bmem);

	return (error_type == e_none);
}

X509_STORE *cert_init_ca(X509 *cert)
{
	X509_STORE *store;

	error_type= e_none;

	store= X509_STORE_new();
	if ( store == NULL ) {
		error_type= e_crypto;
		return NULL;
	}

	if ( X509_STORE_add_cert(store, cert) != 1 ) {
		X509_STORE_free(store);
		error_type= e_crypto;
		return NULL;
	}

	return store;
}

/*
 * Verify cert chain against our CA in store. Assume the first cert in
 * the chain is the one to validate. Note that a store context can only
 * be used for a single verification so we need to do this every time
 * we want to validate a cert.
 */

int cert_verify (X509_STORE *store, STACK_OF(X509) *chain)
{
	X509_STORE_CTX *ctx;
	X509 *cert= sk_X509_value(chain, 0);

	error_type= e_none;

	ctx= X509_STORE_CTX_new();
	if ( ctx == NULL ) {
		error_type= e_crypto;
		return 0;
	}

	if ( X509_STORE_CTX_init(ctx, store, cert, chain) != 1 ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( X509_verify_cert(ctx) != 1 ) error_type=e_crypto;

cleanup:
	if ( ctx != NULL ) X509_STORE_CTX_free(ctx);

	return (error_type == e_none);
}

/*
 * Take an array of certificate pointers and build a stack.
 */

STACK_OF(X509) *cert_stack_build (X509 **certs)
{
	X509 **pcert;
	STACK_OF(X509) *stack;

	error_type= e_none;

	stack= sk_X509_new_null();
	if ( stack == NULL ) {
		error_type= e_crypto;
		return NULL;
	}

	for ( pcert= certs; *pcert!= NULL; ++pcert ) sk_X509_push(stack, *pcert);

	return stack;
}

void cert_stack_free (STACK_OF(X509) *chain)
{
	sk_X509_free(chain);
}

