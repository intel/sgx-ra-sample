#include "hexutil.h"

#include <stdio.h>
#include <sys/types.h>

int from_hexstring (unsigned char *dest, unsigned char *src, size_t len)
{
	size_t i;

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

void print_hexstring (FILE *fp, void *src, size_t len)
{
	unsigned char *sp= src;
	size_t i;
	for(i= 0; i< len; ++i) {
		fprintf(fp, "%02x", sp[i]);
	}
}
