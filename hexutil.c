#include "hexutil.h"
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>

static char *_hex_buffer= NULL;
static size_t _hex_buffer_size= 0;

int from_hexstring (unsigned char *dest, const void *vsrc, size_t len)
{
	size_t i;
	const unsigned char *src= (const unsigned char *) vsrc;

	for (i= 0; i<len; ++i) {
		unsigned int v;
#ifdef _WIN32
		if ( sscanf_s(&src[i * 2], "%2xhh", &v) == 0 ) return 0;
#else
		if ( sscanf(&src[i*2], "%2xhh", &v) == 0 ) return 0;
#endif
		dest[i]= (unsigned char) v;
	}

	return 1;
}

void print_hexstring (FILE *fp, const void *vsrc, size_t len)
{
	const unsigned char *sp= (const unsigned char *) vsrc;
	size_t i;
	for(i= 0; i< len; ++i) {
		fprintf(fp, "%02x", sp[i]);
	}
}

void print_hexstring_nl (FILE *fp, const void *src, size_t len)
{
	print_hexstring(fp, src, len);
	fprintf(fp, "\n");
}

/* Not thread-safe */

const char _hextable[]= "0123456789abcdef";

const char *hexstring (const void *vsrc, size_t len)
{
	size_t i, bsz;
	const unsigned char *src= (const unsigned char *) vsrc;
	unsigned char *bp;

	bsz= len*2+1;	/* Make room for NULL byte */
	if ( bsz >= _hex_buffer_size ) {
		/* Allocate in 1K increments. Make room for the NULL byte. */
		size_t newsz= bsz/1024 + (bsz%1024) ? 1024 : 0;
		_hex_buffer_size= newsz;
		_hex_buffer= (char *) realloc(_hex_buffer, newsz);
		if ( _hex_buffer == NULL ) {
			return "(out of memory)";
		}
	}

	for(i= 0, bp= _hex_buffer; i< len; ++i) {
		*bp++= _hextable[src[i]>>4];
		*bp++= _hextable[src[i]&0xf];
	}
	_hex_buffer[len*2]= 0;
	
	return (const char *) _hex_buffer;
}

