#ifndef __HEXUTIL__H
#define __HEXUTIL__H

#include <stdio.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

int from_hexstring(unsigned char *dest, unsigned char *src, size_t len);
void print_hexstring(FILE *fp, void *src, size_t len);

#ifdef __cplusplus
};
#endif

#endif

