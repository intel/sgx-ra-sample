/*

Copyright 2019 Intel Corporation

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

/*
 * Read in a SIGSTRUCT dump file (from: sgx_sign dump -cssfile ...) and
 * produce the MRSIGNER hash.
 */

#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/types.h>
#ifdef _WIN32
#include <intrin.h>
#include <openssl/applink.c>
#include "win32/getopt.h"
#else
#include <getopt.h>
#include <unistd.h>
#endif
#include "crypto.h"
#include "hexutil.h"

/*
 * From the "Intel(r) 64 and IA-32 Architectures Software Developer 
 * Manual, Volume 3: System Programming Guide", Chapter 38, Section 13,
 * Table 38-19 "Layout of Enclave Signature Structure (SIGSTRUCT)"
 */

#define MODULUS_OFFSET	128
#define MODULUS_SIZE	384

void usage ();

int main(int argc, char *argv[])
{
	char *cssfile= NULL;
	char *sigstruct_raw= NULL;
	unsigned char modulus[MODULUS_SIZE];
	unsigned char mrsigner[32]; /* Size of SHA-256 hash */
	FILE *fp;
	size_t bread;

	/* Command line options */

	static struct option long_opt[] =
	{
		{"help",					no_argument, 		0, 'h'},
		{ 0, 0, 0, 0 }
	};

	/* Parse our options */

	while (1) {
		int c;
		int opt_index = 0;

		c = getopt_long(argc, argv, "h", long_opt, &opt_index);
		if (c == -1) break;

		switch (c) {

		case 'h':
		case '?':
		default:
			usage();
		}
	}

	/* We should have one command-line argument remaining */

	argc-= optind;
	if ( argc != 1 ) usage();

	/* The remaining argument is the sigstruct file to read */

	cssfile= argv[1];

#ifdef _WIN32
	if (fopen_s(&fp, cssfile, "rb") != 0) {
		fprintf(stderr, "fopen_s: ");
#else
	fp= fopen(cssfile, "r");
	if ( fp == NULL ) {
		fprintf(stderr, "%s: ", cssfile);
		perror("fopen");
#endif
		exit(1);
	}

	/* Seek to the location of the public key modulus */

	if ( fseek(fp, MODULUS_OFFSET, SEEK_SET) == -1 ) {
		fprintf(stderr, "%s: ", cssfile);
		perror("fseek");
		exit(1);
	}

	/* Read the modulus */

	bread = fread(modulus, 1, (size_t) MODULUS_SIZE, fp);
	if ( bread != MODULUS_SIZE ) {
		fprintf(stderr, "%s: not a valid sigstruct (file too small)\n",
			cssfile);
		exit(1);
	}

	fclose(fp);

	/* Calculate MRSIGNER, which is the SHA-256 hash of the modulus */

	if ( sha256_digest(modulus, MODULUS_SIZE, mrsigner) ) {
		print_hexstring_nl(stdout, mrsigner, 32);
		exit(0);
	}

	fprintf(stderr, "error calculating MRSIGNER\n");
	exit(1);
}

void usage () 
{
	fprintf(stderr, "usage: mrsigner cssfile\n");
	exit(1);
}
