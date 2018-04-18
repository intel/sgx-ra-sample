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
#include <openssl/ec.h>
#include "hexutil.h"
#include "fileio.h"
#include "crypto_init.h"

#define MAX_LEN 80

void usage();

int get_msg2(sgx_ra_msg2_t **msg2, sgx_ra_msg1_t *msg1);

void usage () 
{
	fprintf(stderr, "usage: sp [ options ]\n\n");
	fprintf(stderr, "Required:\n");
	fprintf(stderr, "  -S, --spid-file=FILE     Set the SPID from a file containg a 32-byte\n");
	fprintf(stderr, "                              ASCII hex string\n");
	fprintf(stderr, "  -s, --spid=HEXSTRING     Set the SPID from a 32-byte ASCII hex string\n");
	fprintf(stderr, "  -K, --key-file=FILE      The private key file in PEM format\n");
	fprintf(stderr, "  -2, --msg2=MSG1_HEX      Generate msg2 from msg1, supplied as a hex string\n");
	fprintf(stderr, "\nOne of --spid OR --spid-file is required\n\n");
	fprintf(stderr, "Optional:\n");
	fprintf(stderr, "  -l, --linkable           Request a linkable quote (default: unlinkable)\n");
	exit(1);
}

int main (int argc, char *argv[])
{
	u_int32_t i;
	char flag_spid= 0;
	char flag_msg2= 0;
	char flag_pubkey= 0;
	u_int32_t spid[16];
	sgx_ra_msg1_t msg1;
	EC_KEY *prkey;

	static struct option long_opt[] =
	{
		{"msg2",		required_argument,	0, '2'},
		{"key-file",	required_argument,	0, 'K'},
		{"spid-file",	required_argument,	0, 'S'},
		{"help",		no_argument, 		0, 'h'},
		{"spid",		required_argument,	0, 's'},
		{"linkable",	no_argument,		0, 'l'},
		{ 0, 0, 0, 0}
	};

	/* Parse our options */

	while (1) {
		int c;
		int opt_index= 0;

		c= getopt_long(argc, argv, "2:K:S:hs:l", long_opt, &opt_index);
		if ( c == -1 ) break;

		switch(c) {
		case 0:
			break;
		case '2':
			if ( strlen(optarg) != sizeof(sgx_ra_msg1_t)*2 ) {
				fprintf(stderr, "msg1 must be %d-byte hex string\n",
					sizeof(sgx_ra_msg1_t)*2);
				exit(1);
			}
			if ( ! from_hexstring((unsigned char *) &msg1, optarg,
				sizeof(sgx_ra_msg1_t)) ) {
				fprintf(stderr, "msg1 not a valid hex string\n",
					sizeof(sgx_ra_msg1_t)*2);
				exit(1);
			}
			++flag_msg2;
			break;
		case 'K':
			if ( ! key_load_file(&prkey, optarg) ) {
				fprintf(stderr, "%s: could not load EC private key\n", optarg);
				exit(1);
			}
			break;
		case 'l':
			//linkable= SGX_LINKABLE_SIGNATURE;
			break;
		case 'S':
			if ( ! from_hexstring_file((unsigned char *) &spid, optarg, 16)) {
				fprintf(stderr, "SPID must be 32-byte hex string\n");
				exit(1);
			}
			++flag_spid;

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

	if ( ! flag_spid ) {
		fprintf(stderr, "One of --spid or --spid-file is required.\n");
		exit(1);
	}

	crypto_init();

	if ( flag_msg2 ) {
		sgx_ra_msg2_t *msg2;
		get_msg2(&msg2, &msg1);
	}

	crypto_destroy();

	return 0;
}

/*
 * Process msg1 and produce msg2.
 */

int get_msg2(sgx_ra_msg2_t **msg2, sgx_ra_msg1_t *msg1)
{
	unsigned char *secret;

	/*
     * Compute the shared secret using the peer's public key and a generated
     * public/private key.
     */

	if ( ! key_shared_secret(&secret, msg1->g_a) ) {
		key_perror("key_shared_secret");
		return 0;
	}

	return 1;
}

