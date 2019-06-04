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
		fclose(fp);
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
	if ( sbuf == NULL ) {
		perror("malloc");
		return 0;
	}

#ifdef _WIN32
	if (fopen_s(&fp, file, "r") != 0) {
		fprintf(stderr, "fopen_s: ");
#else
	if ( (fp= fopen(file, "r")) == NULL ) {
		fprintf(stderr, "fopen: ");
#endif
		perror(file);
		free(sbuf);
		return 0;
	}
	if ( fread(sbuf, len*2, 1, fp) != 1 ) {
		fclose(fp);
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

