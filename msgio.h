#ifndef __MSGIO_H
#define __MSGIO_H

#include <sys/types.h>
#include <sgx_urts.h>

#define STRUCT_INCLUDES_PSIZE	0
#define STRUCT_OMITS_PSIZE		1

/* A 1MB buffer should be sufficient for demo purposes */
#define BUFFER_SZ	1024*1024

#ifdef __cplusplus
extern "C" {
#endif

int read_msg(void *fixedbuf, size_t f_size, void **payload,
	 uint32_t *p_size, unsigned short flags);

void send_msg(void *fixedbuf, size_t f_size, void *payload,
	 uint32_t p_size, unsigned short flags);

#ifdef __cplusplus
};
#endif

#endif
