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
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "fileio.h"
#include "hexutil.h"

int from_file (unsigned char *dest, char *file, off_t *len)
{
	FILE *fp;

	/* Get the file size so we know how large our buffer should be */

	if ( dest == NULL ) {
		struct stat sb;

		if ( stat(file, &sb) != 0 ) {
			fprintf(stderr, "stat: ");
			perror(file);
			return 0;
		}

		*len= sb.st_size;
		return 1;
	}

#ifdef _WIN32
	if (fopen_s(&fp, file, "r") != 0) {
		fprintf(stderr, "fopen_s: ");
#else
	if ( (fp= fopen(file, "r")) == NULL ) {
		fprintf(stderr, "fopen: ");
#endif
		perror(file);
		exit(1);
	}
	if ( fread(dest, (size_t) *len, 1, fp) != 1 ) {
		return 0;
	}
	fclose(fp);

	return 1;
}

int from_hexstring_file (unsigned char *dest, char *file, size_t len)
{
	unsigned char *sbuf;
	FILE *fp;
	int rv;

	sbuf= (unsigned char *) malloc(len*2);

#ifdef _WIN32
	if (fopen_s(&fp, file, "r") != 0) {
		fprintf(stderr, "fopen_s: ");
#else
	if ( (fp= fopen(file, "r")) == NULL ) {
		fprintf(stderr, "fopen: ");
#endif
		perror(file);
		return 0;
	}
	if ( fread(sbuf, len*2, 1, fp) != 1 ) {
		free(sbuf);
		return 0;
	}
	fclose(fp);

	rv= from_hexstring(dest, sbuf, 16);

	free(sbuf);

	return rv;
}

int to_hexstring_file (unsigned char *src, char *file, size_t len)
{
	FILE *fp;

#ifdef _WIN32
	if (fopen_s(&fp, file, "w") != 0) {
		fprintf(stderr, "fopen_s: ");
#else
	if ( (fp= fopen(file, "w")) == NULL ) {
		fprintf(stderr, "fopen: ");
#endif
		perror(file);
		return 0;
	}
	
	print_hexstring(fp, src, len);

	fclose(fp);

	return 1;
}

