#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sgx_urts.h>
#include "hexutil.h"
#include "msgio.h"

/*
 * Read a msg from std in. There's a fixed portion and a variable-length
 * payload. Read the fixed portion. If *p_size is not NULL, it points
 * to a data field in the fixed portion of the message that states the
 * length of the payload. Allocate a buffer to hold the payload, and
 * read the remaining bytes.
 *
 * All messages are base16 encoded (ASCII hex strings) for simplicity
 * and readability. We decode the message into the destination.
 *
 * We do not allow any whitespace in the incoming message, save for the
 * terminating newline.
 */


int read_msg (void *fixed, size_t f_size, void **payload, uint32_t *p_size,
	unsigned short flags)
{
	size_t bread, sz;
	char *buffer= NULL;

	sz=f_size*2; /* base16 encoding */
	buffer= malloc(sz);
	if ( buffer == NULL ) return -1;

	bread= fread(buffer, 1, sz, stdin);
	if ( bread != sz ) {
		fprintf(stderr, "expected %lu bytes, read %lu\n", sz, bread);
		return 0;
	}

	if ( flags & STRUCT_OMITS_PSIZE ) {
		/*
		 * The fixed data structure doesn't contain the payload size 
		 * as a member at the end (this is the case for msg3 for some
		 * reason). As a result, we have to write the size parameter
		 * separately, we can't just write everything to void *fixed.
		 */

		size_t sz= f_size-sizeof(uint32_t);
		
		from_hexstring(fixed, buffer, sz);
		from_hexstring((unsigned char *) &p_size, &buffer[sz],
			sizeof(uint32_t));
		
	} else from_hexstring(fixed, buffer, f_size);

	if ( p_size == NULL || *p_size == 0 ) {
		/* There's no payload. Read the trailing newline. If the last
		 * char isn't a newline then something is wrong. */
		return (fgetc(stdin) == '\n') ? 1 : 0;
	}

	/* Now read the variable payload length */

	sz=*p_size*2 + 1; /* base16 encoding +1 for newline */
	buffer= realloc(buffer, sz);
	if ( buffer == NULL ) return -1;

	bread= fread(buffer, 1, sz, stdin);
	if ( bread != sz ) {
		fprintf(stderr, "expected %lu bytes, read %lu\n", sz, bread);
		return 0;
	}

	/* If the last byte isn't a newline, something is wrong */

	if ( buffer[sz] != '\n' ) {
		fprintf(stderr, "expected ending newline, got 0x%02x\n", buffer[sz]);
		return 0;
	}

	/* Allocate the payload buffer */

	*payload= malloc(*p_size);
	if ( *payload == NULL ) return -1;

	from_hexstring(*payload, buffer, *p_size);

	return 1;
}

void send_msg (void *fixed, size_t f_size, void *payload, uint32_t p_size,
	unsigned short flags)
{
	print_hexstring(stdout, fixed, f_size);
	if ( flags & STRUCT_OMITS_PSIZE ) print_hexstring(stdout, &p_size,
		sizeof(uint32_t));
	if ( p_size > 0 ) print_hexstring(stdout, payload, p_size);

	printf("\n");

	/*
	 * Since we have both stdout and stderr, flush stdout to keep the
	 * the output stream synchronized.
	 */

	fflush(stdout);
}

