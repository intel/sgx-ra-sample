/*

Copyright 2018 Intel Corporation

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

THIS SOFTWARE IS PROVIDED BY INTEL CORPORATION "AS IS" AND ANY EXPRESS
OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OFLIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sgx_urts.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#include "hexutil.h"
#include "msgio.h"
#include "common.h"

#define BUFFER_SZ	1024*1024

static char *buffer= NULL;
static uint32_t buffer_size= BUFFER_SZ;

/*
 * Read a msg from stdin. There's a fixed portion and a variable-length
 * payload. 
 *
 * Our destination buffer is the entire message plus the payload, 
 * returned to the caller. This lets them cast it as an sgx_ra_msgN_t
 * structure, and take advantage of the flexible array member at the
 * end (if it has one, as sgx_ra_msg2_t and sgx_ra_msg3_t do).
 *
 * All messages are base16 encoded (ASCII hex strings) for simplicity
 * and readability. We decode the message into the destination.
 *
 * We do not allow any whitespace in the incoming message, save for the
 * terminating newline.
 *
 */


int read_msg (void **dest, size_t *sz)
{
	size_t bread;
	int repeat= 1;

	if ( buffer == NULL ) {
		buffer= (char *) malloc(buffer_size);
		if ( buffer == NULL ) {
			perror("malloc");
			return -1;
		}
	}

	bread= 0;
	while (repeat) {
		if ( fgets(&buffer[bread], (int)(buffer_size-bread), stdin) == NULL ) {
			if ( ferror(stdin) ) {
				perror("fgets");
				return -1;
			} else {
				fprintf(stderr, "EOF received\n");
				return 0;
			}
		}
		/* If the last char is not a newline, we have more reading to do */

		bread= strlen(buffer);
		if ( bread == 0 ) {
			fprintf(stderr, "EOF received\n");
			return 0;
		}

		if ( buffer[bread-1] == '\n' ) {
			repeat= 0;
			--bread;	/* Discard the newline */
		} else {
			buffer_size+= BUFFER_SZ;
			buffer= realloc(buffer, buffer_size);
			if ( buffer == NULL ) return -1;
		}
	}

	/* Make sure we didn't get \r\n */
	if ( bread && buffer[bread-1] == '\r' ) --bread;

	if ( bread%2 ) {
		fprintf(stderr, "read odd byte count %zu\n", bread);
		return 0;	/* base16 encoding = even number of bytes */
	}

	*dest= malloc(bread/2);
	if ( *dest == NULL ) return -1;

	if ( debug ) {
		edividerWithText("read buffer");
		eputs(buffer);
		edivider();
	}

	from_hexstring(*dest, buffer, bread/2);

	if ( sz != NULL ) *sz= bread;

	return 1;
}

/* Send a partial message (no newline) */

void send_msg_partial (void *src, size_t sz) {
	if ( sz ) print_hexstring(stdout, src, sz);
#ifndef _WIN32
	/*
	 * If were aren't writing to a tty, also print the message to stderr
	 * so you can still see the output.
	 */
	if ( !isatty(fileno(stdout)) ) print_hexstring(stderr, src, sz);
#endif
}

void send_msg (void *src, size_t sz)
{
	if ( sz ) print_hexstring(stdout, src, sz);
	printf("\n");
#ifndef _WIN32
	/* As above */
	if ( !isatty(fileno(stdout)) ) {
		print_hexstring(stderr, src, sz);
		fprintf(stderr, "\n");
	}
#endif

	/*
	 * Since we have both stdout and stderr, flush stdout to keep the
	 * the output stream synchronized.
	 */

	fflush(stdout);
}


/* Send a partial message (no newline) */

void fsend_msg_partial (FILE *fp, void *src, size_t sz) {
        if ( sz ) print_hexstring(fp, src, sz);
}

void fsend_msg (FILE *fp, void *src, size_t sz)
{
        if ( sz ) print_hexstring(fp, src, sz);
        fprintf(fp,"\n");
        fflush(fp);
}

