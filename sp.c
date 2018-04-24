/*

Copyright 2017 Intel Corporation

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#ifdef _WIN32
#pragma comment(lib, "crypt32.lib")
#else
#include "config.h"
#endif

#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/types.h>
#ifdef _WIN32
#include <intrin.h>
#include "getopt.h"
#else
#include <getopt.h>
#include <unistd.h>
#endif
#include <sgx_key_exchange.h>
#include <openssl/evp.h>
#include "hexutil.h"
#include "fileio.h"
#include "crypto.h"
#include "byteorder.h"

#define MAX_LEN 80
#define BUFFER_SZ 1024*1024*100

void usage();

int derive_kdk(EVP_PKEY *Gb, unsigned char kdk[16], sgx_ra_msg1_t *msg1);

void usage () 
{
	fprintf(stderr, "usage: sp [ options ]\n\n");
	fprintf(stderr, "Required:\n");
    fprintf(stderr, "  -K, --kdk-file=FILE      Read/write the KDK in FILE\n");
	fprintf(stderr, "  -P, --key-file=FILE      The private key file in PEM format\n");
	fprintf(stderr, "  -S, --spid-file=FILE     Set the SPID from a file containg a 32-byte\n");
	fprintf(stderr, "                              ASCII hex string\n");
	fprintf(stderr, "  -s, --spid=HEXSTRING     Set the SPID from a 32-byte ASCII hex string\n");
	fprintf(stderr, "  -2, --msg2               Read msg1 from stdin, print msg2\n");
	fprintf(stderr, "  -4, --msg4               Read msg3 from stdin, print msg4\n");
	fprintf(stderr, "\nOne of --spid OR --spid-file is required\n\n");
	fprintf(stderr, "\nOne of --msg2 OR --msg4 is required\n\n");
	fprintf(stderr, "Optional:\n");
	fprintf(stderr, "  -l, --linkable           Request a linkable quote (default: unlinkable)\n");
	fprintf(stderr, "  -r, --sigrl-file=FILE    Read the revocation list from FILE\n");
	exit(1);
}

int main (int argc, char *argv[])
{
	u_int32_t i;
	char flag_spid= 0;
	char flag_msg= 0;
	char flag_pubkey= 0;
	char *kdkfile= NULL;
	sgx_spid_t spid;
	EVP_PKEY *service_private_key= NULL;
	unsigned int linkable= SGX_UNLINKABLE_SIGNATURE;
	/* Use a fixed buffer which is much larger than we'll need */
	size_t blen= 0;
	unsigned char *bp, *buffer;

	static struct option long_opt[] =
	{
		{"msg2",		no_argument,		0, '2'},
		{"kdk-file",	required_argument,	0, 'K'},
		{"key-file",	required_argument,	0, 'P'},
		{"spid-file",	required_argument,	0, 'S'},
		{"help",		no_argument, 		0, 'h'},
		{"spid",		required_argument,	0, 's'},
		{"linkable",	no_argument,		0, 'l'},
		{ 0, 0, 0, 0 }
	};

	/* Parse our options */

	buffer= (unsigned char *) malloc(BUFFER_SZ);
	if ( buffer == NULL ) {
		perror("malloc");
		return 1;
	}

	while (1) {
		int c;
		int opt_index= 0;

		c= getopt_long(argc, argv, "1K:P:S:hls:", long_opt, &opt_index);
		if ( c == -1 ) break;

		switch(c) {
		case 0:
			break;
		case '1':
			flag_msg= 1;
			break;
		case 'K':
			kdkfile= strdup(optarg);
			break;
		case 'P':
			if ( ! key_load_file(&service_private_key, optarg, KEY_PRIVATE) ) {
				fprintf(stderr, "%s: could not load EC private key\n", optarg);
				exit(1);
			}
			break;
		case 'S':
			if ( ! from_hexstring_file((unsigned char *) &spid, optarg, 16)) {
				fprintf(stderr, "SPID must be 32-byte hex string\n");
				exit(1);
			}
			++flag_spid;

			break;
		case 'l':
			linkable= SGX_LINKABLE_SIGNATURE;
			break;
		case 's':
			if ( strlen(optarg) < 32 ) {
				fprintf(stderr, "SPID must be 32-byte hex string\n");
				exit(1);
			}
			if ( ! from_hexstring((unsigned char *) &spid, (unsigned char *) optarg, 16) ) {
				fprintf(stderr, "SPID must be 32-byte hex string\n");
				exit(1);
			}
			++flag_spid;
			break;
		case 'h':
		case '?':
		default:
			usage();
		}
	}

	if ( service_private_key == NULL ) {
		fprintf(stderr, "--key-file is required.\n");
		usage();
	}

	if ( kdkfile == NULL ) {
		fprintf(stderr, "--kdk-file is required.\n");
		usage();
	}

	if ( ! flag_spid ) {
		fprintf(stderr, "One of --spid or --spid-file is required.\n");
		exit(1);
	}

	/* Read the incoming message */

	blen= fread(buffer, 1, BUFFER_SZ, stdin);
	if ( blen == BUFFER_SZ ) {
		fprintf(stderr, "read exceeds buffer size of %u bytes\n", BUFFER_SZ);
		return 1;
	}
	if ( ferror(stdin) ) {
		fprintf(stderr, "error reading from stdin\n");
		return 1;
	}

	/* Remove trailing whitespace */

	bp= &buffer[blen-1];
	while ( *bp == '\n' || *bp == ' ' || *bp == '\t' || *bp == '\r' ) {
		*bp= 0;
		--bp;
		--blen;
	}

	/* Initialize OpenSSL */

	crypto_init();

	/* Process our message */

	if ( flag_msg == 1 ) {
		sgx_ra_msg1_t msg1;
		sgx_ra_msg2_t msg2;
		unsigned char kdk[16], smk[16], gb_ga[128];
		EVP_PKEY *Gb;
		mode_t fmode;

		if ( blen != 2*sizeof(msg1) ) {
			fprintf(stderr, "msg1 must be a %u byte hex string\n",
				sizeof(sgx_ra_msg1_t)*2);
			return 1;
		}
		if ( ! from_hexstring((unsigned char *) &msg1, buffer,
			sizeof(sgx_ra_msg1_t)) ) {
			fprintf(stderr, "msg1 not a valid hex string\n",
				sizeof(sgx_ra_msg1_t)*2);
			exit(1);
		}

		/* Generate our session key */

		Gb= key_generate();
		if ( Gb == NULL ) {
			fprintf(stderr, "Could not create a session key\n");
			exit(1);
		}

		/* Derive the KDK from the key (Ga) in msg1 and our session key */

		if ( ! derive_kdk(Gb, kdk, &msg1) ) {
			fprintf(stderr, "Could not derive the KDK\n");
			exit(1);
		}

		/*-------------------------------------------------------------------
         * WARNING! You would not normally save these keys to an unencrypted
         * file. This is a testing application, not a production one, and it
         * needs the ability to maintain state between executions. DO NOT 
         * TRY THIS AT HOME!
         * ------------------------------------------------------------------ */

		fmode= umask(077); /* At least don't create a world-readable file */
		if ( ! to_hexstring_file(kdk, kdkfile, 16) ) {
			fprintf(stderr, "Could not store the KDK\n");
			exit(1);
		}
		umask(fmode);

		/*
 		 * Derive the SMK from the KDK 
		 * SMK = AES_CMAC(KDK, 0x01 || "SMK" || 0x00 || 0x80 || 0x00) 
		 * */

		cmac128(kdk, "\x01SMK\x00\x80\x00", 7, smk);

		/*
		 * Build message 2
		 *
		 * A || CMACsmk(A) || SigRL
		 *
		 * where:
		 *
		 * A      = Gb || SPID || TYPE || KDF-ID || SigSP(Gb, Ga) 
		 * Ga     = Client enclave's session key
		 * Gb     = Service Provider's session key
		 * SPID   = The Service Provider ID, issued by Intel to the vendor
		 * TYPE   = Quote type (0= linkable, 1= linkable) (2 bytes)
		 * KDF-ID = (0x0001= CMAC entropy extraction and key derivation) (2 bytes)
		 * SigSP  = ECDSA signature of (Gb.x || Gb.y || Ga.x || Ga.y) as r || s
		 *          (signed with the Service Provider's private key)
		 * 
		 * || denotes concatenation
		 *
		 * Note that all key components (Ga.x, etc.) are in little endian 
		 * format, meaning the byte streams need to be reversed.
		 *
		 */

		key_to_sgx_ec256(&msg2.g_b, Gb);
		memcpy(&msg2.spid, &spid, sizeof(sgx_spid_t));
		msg2.quote_type= linkable;
		msg2.kdf_id= 1;

		/* For now */
		msg2.sig_rl_size= 0;

		memcpy(gb_ga, &msg2.g_b, 64);
		memcpy(&gb_ga[64], &msg1.g_a, 64);

		ecdsa_sign(gb_ga, 128, service_private_key, (unsigned char *) &msg2.sign_gb_ga);
		printf("Ga=");
		print_hexstring(stdout, &msg1.g_a, 64);
		printf("\n");

		printf("Gb=");
		print_hexstring(stdout, &msg2.g_b, 64);
		printf("\n");

		printf("SPID=");
		print_hexstring(stdout, &msg2.spid, 16);
		printf("\n");

		printf("Link type=");
		print_hexstring(stdout, &msg2.quote_type, 2);
		printf("\n");

		printf("KDF ID=");
		print_hexstring(stdout, &msg2.kdf_id, 2);
		printf("\n");

		printf("A=");
		print_hexstring(stdout, &msg2, 84);
		printf("\n");

		printf("message=");
		print_hexstring(stdout, gb_ga, 128);
		printf("\n");

		printf("SignSP=");
		print_hexstring(stdout, &msg2.sign_gb_ga, 64);
		printf("\n");

	}

	crypto_destroy();

	return 0;
}

/*
 * Process msg1 and produce msg2.
 */

int derive_kdk(EVP_PKEY *Gb, unsigned char kdk[16], sgx_ra_msg1_t *msg1)
{
	unsigned char *Gab_x;
	size_t slen;
	EVP_PKEY *Ga;
	unsigned char cmackey[16];

	memset(cmackey, 0, 16);

	/*
     * Compute the shared secret using the peer's public key and a generated
     * public/private key.
     */

	Ga= key_from_sgx_ec256(&msg1->g_a);
	if ( Ga == NULL ) {
		crypto_perror("key_from_sgx_ec256");
		return 0;
	}

	/* The shared secret in a DH exchange is the x-coordinate of Gab */
	Gab_x= key_shared_secret(Gb, Ga, &slen);
	if ( Gab_x == NULL ) {
		crypto_perror("key_shared_secret");
		return 0;
	}

	/* We need it in little endian order, so reverse the bytes. */
	/* We'll do this in-place. */

	reverse_bytes(Gab_x, Gab_x, slen);

	/* Now hash that to get our KDK (Key Definition Key) */

	/*
     * KDK = AES_CMAC(0x00000000000000000000000000000000, secret)
     */

	cmac128(cmackey, Gab_x, slen, kdk);

	return 1;
}

