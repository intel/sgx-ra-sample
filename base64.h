#ifndef __BASE64_H
#define __BASE64_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

char *base64_encode(const char *msg, size_t sz);
char *base64_decode(const char *msg, size_t *sz);

#ifdef __cplusplus
};
#endif

#endif

