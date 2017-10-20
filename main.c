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

#include "config.h"
#include "EnclaveQuote_u.h"
#include "sgx_stub.h"
#include <limits.h>
#include <stdio.h>
#include <sgx_urts.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sgx_uae_service.h>
#include <glib.h>

#define MAX_LEN 80

#ifdef __x86_64__
#define DEF_LIB_SEARCHPATH "/lib:/lib64:/usr/lib:/usr/lib64"
#else
#define DEF_LIB_SEARCHPATH "/lib:/usr/lib"
#endif

int file_in_searchpath (const char *file, char *search, char *fullpath,
	size_t len);

sgx_status_t sgx_create_enclave_search (
	const char *filename,
	const int debug,
	sgx_launch_token_t *token,
	int *updated,
	sgx_enclave_id_t *eid,
	sgx_misc_attribute_t *attr
);

void usage();
void from_hexstring(unsigned char *dest, unsigned char *src, size_t len);
void print_hexstring(FILE *fp, unsigned char *src, size_t len);

void usage () 
{
	fprintf(stderr, "usage: enclavequote SPID\n");
	exit(1);
}

int main (int argc, char *argv[])
{
	sgx_launch_token_t token= { 0 };
	sgx_status_t status;
	sgx_enclave_id_t eid= 0;
	sgx_quote_t *quote;
	sgx_spid_t spid;
	sgx_report_t qe_report;
	int updated= 0;
	int rv;
	uint32_t i, opt;
	sgx_report_t report;
	uint32_t sz= 0;
	sgx_target_info_t target_info;
	sgx_epid_group_id_t epid_gid;
	unsigned char *qp;
	gchar *b64quote;
	uint16_t linkable= SGX_UNLINKABLE_SIGNATURE;
	sgx_quote_nonce_t nonce;
	char flag_nonce= 0;

	while ( (opt= getopt(argc, argv, "h:ln:")) != -1 ) {
		switch(opt) {
		case 'l':
			linkable= SGX_LINKABLE_SIGNATURE;
			break;
		case 'n':
			if ( strlen(optarg) < 32 ) {
				fprintf(stderr, "nonce must be 32-byte hex string\n");
				exit(1);
			}
			from_hexstring((unsigned char *) &nonce, (unsigned char *) optarg, 16);
			flag_nonce= 1;
			break;
		case 'h':
		case '?':
		default:
			usage();
		}
	}

	argc-= optind;
	argv+= optind;

	if ( argc != 1 ) {
		usage();
	}

	if ( strlen(argv[0]) < 32 ) {
		fprintf(stderr, "SPID must be 32-byte hex string\n");
		exit(1);
	}

	from_hexstring((unsigned char *) &spid, (unsigned char *) argv[0], 16);
	fprintf(stderr, "Generting quote for SPID: ");
	print_hexstring(stderr, (unsigned char *) &spid, 16);
	fprintf(stderr, "\n");

	if ( flag_nonce ) {
		fprintf(stderr, "Using nonce: ");
		print_hexstring(stderr, (unsigned char *) &nonce, 16);
		fprintf(stderr, "\n");
	}

	/* Can we run SGX? */

	if ( ! have_sgx_psw() ) {
		fprintf(stderr, "Intel SGX runtime libraries not found.\n");
		fprintf(stderr, "This system cannot use Intel SGX.\n");
		exit(1);
	}

	/* Launch the enclave */

	status= sgx_create_enclave_search("EnclaveQuote.signed.so", SGX_DEBUG_FLAG, &token, &updated, &eid, 0);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_create_enclave: EnclaveQuote.signed.so: %08x\n",
			status);
		if ( status == SGX_ERROR_ENCLAVE_FILE_ACCESS ) 
			fprintf(stderr, "Did you forget to set LD_LIBRARY_PATH?\n");
		return 1;
	}

	memset(&report, 0, sizeof(report));

	status= sgx_init_quote(&target_info, &epid_gid);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_init_quote: %08x\n", status);
		return 1;
	}

	status= get_report(eid, &rv, &report, &target_info);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "get_report: %08x\n", status);
		return 1;
	}
	if ( rv != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_get_report: %08x\n", status);
		return 1;
	}

	status= sgx_calc_quote_size(NULL, 0, &sz);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_calc_quote_size: %08x\n", status);
		return 1;
	}

	quote= (sgx_quote_t *) malloc(sz);
	if ( quote == NULL ) {
		fprintf(stderr, "out of memory\n");
		return 1;
	}

	memset(quote, 0, sz);
	status= sgx_get_quote(&report, linkable, &spid,
		(flag_nonce) ? &nonce : NULL,
		NULL, 0,
		(flag_nonce) ? &qe_report : NULL,
		quote, sz);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_get_quote: %08x\n", status);
		return 1;
	}

	b64quote= NULL;
	b64quote= g_base64_encode((const guchar *) quote, sz);
	printf("%s\n", b64quote);
}

void from_hexstring (unsigned char *dest, unsigned char *src, size_t len)
{
	size_t i;

	for (i= 0; i<len; ++i) {
		unsigned int v;
		sscanf(&src[i*2], "%2xhh", &v);
		dest[i]= (unsigned char) v;
	}
}

void print_hexstring (FILE *fp, unsigned char *src, size_t len)
{
	size_t i;
	for(i= 0; i< len; ++i) {
		fprintf(fp, "%02x", src[i]);
	}
}

/*
 * Search for the enclave file and then try and load it.
 */

sgx_status_t sgx_create_enclave_search (const char *filename, const int debug,
	sgx_launch_token_t *token, int *updated, sgx_enclave_id_t *eid,
	sgx_misc_attribute_t *attr)
{
	struct stat sb;
	char epath[PATH_MAX];	/* includes NULL */

	/* Is filename an absolute path? */

	if ( filename[0] == '/' ) 
		return sgx_create_enclave(filename, debug, token, updated, eid, attr);

	/* Is the enclave in the current working directory? */

	if ( stat(filename, &sb) == 0 )
		return sgx_create_enclave(filename, debug, token, updated, eid, attr);

	/* Search the paths in LD_LBRARY_PATH */

	if ( file_in_searchpath(filename, getenv("LD_LIBRARY_PATH"), epath, PATH_MAX) )
		return sgx_create_enclave(epath, debug, token, updated, eid, attr);
		
	/* Search the paths in DT_RUNPATH */

	if ( file_in_searchpath(filename, getenv("DT_RUNPATH"), epath, PATH_MAX) )
		return sgx_create_enclave(epath, debug, token, updated, eid, attr);

	/* Standard system library paths */

	if ( file_in_searchpath(filename, DEF_LIB_SEARCHPATH, epath, PATH_MAX) )
		return sgx_create_enclave(epath, debug, token, updated, eid, attr);

	/*
	 * If we've made it this far then we don't know where else to look.
	 * Just call sgx_create_enclave() which assumes the enclave is in
	 * the current working directory. This is almost guaranteed to fail,
	 * but it will insure we are consistent about the error codes that
	 * get reported to the calling function.
	 */

	return sgx_create_enclave(filename, debug, token, updated, eid, attr);
}

int file_in_searchpath (const char *file, char *search, char *fullpath, 
	size_t len)
{
	char *p, *str;
	size_t rem;
	struct stat sb;

	if ( search == NULL ) return 0;
	if ( strlen(search) == 0 ) return 0;

	str= strdup(search);
	if ( str == NULL ) return 0;

	p= strtok(str, ":");
	while ( p != NULL) {
		size_t lp= strlen(p);

		if ( lp ) {

			strncpy(fullpath, p, len);
			rem= len-lp-1;

			strncat(fullpath, "/", rem);
			--rem;

			strncat(fullpath, file, rem);

			if ( stat(fullpath, &sb) == 0 ) {
				free(str);
				return 1;
			}
		}

		p= strtok(NULL, ":");
	}

	free(str);

	return 0;
}

