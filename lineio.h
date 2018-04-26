#ifndef __LINEIO_H
#define __LINEIO_H

/* A 1MB buffer should be sufficient for demo purposes */
#define BUFFER_SZ	1024*1024

#ifdef __cplusplus
extern "C" {
#endif

size_t read_line(char **buffer);

#ifdef __cplusplus
};
#endif

#endif
