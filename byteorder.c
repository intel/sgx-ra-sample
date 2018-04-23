#include <sys/types.h>
#include "byteorder.h"

/* Reverse the bytes in an array. Can do this in-place (src == dest) */

void reverse_bytes(void *dest, void *src, size_t len)
{
	size_t i;
	char *sp= (char *)src;

	if ( len < 2 ) return;

	if ( src == dest ) {
		size_t j;

		for (i= 0, j= len-1; i<j; ++i, --j) {
			char t= sp[j];
			sp[j]= sp[i];
			sp[i]= t;
		}
	} else {
		char *dp= (char *) dest + len - 1;
		for (i= 0; i< len; ++i, ++sp, --dp) *dp= *sp;
	}
}

