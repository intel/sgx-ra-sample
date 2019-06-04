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
#include "logfile.h"
#include "hexutil.h"

FILE *fplog = NULL;


FILE *create_logfile(const char *filename)
{
	FILE *fp;

#ifdef _WIN32
	if (fopen_s(&fp, filename, "w") != 0) {
		fprintf(stderr, "fopen_s: ");
#else
	if ( (fp= fopen(filename, "w")) == NULL ) {
		fprintf(stderr, "fopen: ");
#endif
		perror(filename);
		exit(1);
	}

	return fp;
}


void close_logfile (FILE *fp)
{
	if ( fp ) {
		fclose(fp);
		fp = NULL;
	}
}
