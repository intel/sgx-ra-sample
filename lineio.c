#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lineio.h"

#define BUFFER_SZ	1024*1024

static char buffer[BUFFER_SZ];
char *bp;

/* Read a line from stdin, and allocate b to store it. Return the size. */
size_t read_line (char **b)
{
	size_t blen;

	if ( fgets(buffer, BUFFER_SZ, stdin) == NULL ) return 0;
	blen= strlen(buffer);

	/* Remove trailing whitespace */

	bp= &buffer[blen-1];
	while ( *bp == '\n' || *bp == ' ' || *bp == '\t' || *bp == '\r' ) {
		--bp;
		--blen;
	}

	/* Null terminate */
	*(bp+1)= 0;

	/* Remove leading whitespace */

	bp= buffer;
	while ( *bp == ' ' || *bp == '\t' ) {
		++bp;
		--blen;
	}

	/* bp is now at the start of our text */

	*b= strdup(bp);

	printf("read %lu bytes\n", blen);

	return blen;
}
