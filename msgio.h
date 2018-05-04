#ifndef __MSGIO_H
#define __MSGIO_H

#include <sys/types.h>
#include <sgx_urts.h>
#include <stdio.h>

#define STRUCT_INCLUDES_PSIZE	0
#define STRUCT_OMITS_PSIZE		1

/* A 1MB buffer should be sufficient for demo purposes */
#define BUFFER_SZ	1024*1024

#ifdef __cplusplus
extern "C" {
#endif

int read_msg(void **dest, size_t *sz);

void send_msg_partial(void *buf, size_t f_size);
void send_msg(void *buf, size_t f_size);

void fsend_msg_partial(FILE *fp, void *buf, size_t f_size);
void fsend_msg(FILE *fp, void *buf, size_t f_size);

#ifdef __cplusplus
};
#endif

#endif
