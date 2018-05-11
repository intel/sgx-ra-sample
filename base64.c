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

#include <sys/types.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <string.h>

char *base64_encode(const char *msg, size_t sz)
{
	BIO *b64, *bmem;
	char *bstr, *dup;
	int len;

	b64= BIO_new(BIO_f_base64());
	bmem= BIO_new(BIO_s_mem());

	/* Single line output, please */
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	BIO_push(b64, bmem);

	if ( BIO_write(b64, msg, (int) sz) == -1 ) return NULL;

	BIO_flush(b64);

	len= BIO_get_mem_data(bmem, &bstr);
	dup= (char *) malloc(len+1);
	memcpy(dup, bstr, len);
	dup[len]= 0;

	BIO_free(bmem);
	BIO_free(b64);

	return dup;
}


char *base64_decode(const char *msg, size_t *sz)
{
	BIO *b64, *bmem;
	char *buf;
	size_t len= strlen(msg);

	buf= (char *) malloc(len+1);
	memset(buf, 0, len+1);

	b64= BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	bmem= BIO_new_mem_buf(msg, (int) len);

	BIO_push(b64, bmem);

	*sz= BIO_read(b64, buf, (int) len);
	if ( *sz == -1 ) return NULL;

	BIO_free_all(bmem);

	return buf;
}

