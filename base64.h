#ifndef __BASE64_H
#define __BASE64_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

unsigned char *base64_encode(const unsigned char *msg, size_t sz);
unsigned char *base64_decode(const unsigned char *msg, size_t *sz);

#ifdef __cplusplus
};
#endif

#endif

