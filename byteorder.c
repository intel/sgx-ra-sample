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


#include <sys/types.h>
#include <inttypes.h>
#include "byteorder.h"

/*
 * Reverse the bytes in an array. Can do this in-place (src == dest)
 * but any other overlapping gives undefined behavior so don't do it.
 */

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

