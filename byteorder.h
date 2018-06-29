#ifndef __BYTEORDER_H
#define __BYTEORDER_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

void reverse_bytes(void *dest, void *src, size_t n);

#ifdef __cplusplus
};
#endif

#endif
