#ifndef __HEXUTIL__H
#define __HEXUTIL__H

#include <stdio.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

int from_hexstring(unsigned char *dest, const void *src, size_t len);

void print_hexstring(FILE *fp, const void *src, size_t len);
void print_hexstring_nl(FILE *fp, const void *src, size_t len);

const char *hexstring(const void *src, size_t len);

#ifdef __cplusplus
};
#endif

#endif

