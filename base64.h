#ifndef __BASE64_H
#define __BASE64_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif
unsigned char *base64_encode(unsigned char *msg, size_t sz);

#ifdef __cplusplus
};
#endif

#endif

