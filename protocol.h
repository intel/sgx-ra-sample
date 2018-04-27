#ifndef __PROTOCOL_H
#define __PROTOCOL_H

#include <sys/types.h>

typedef u_int32_t attestation_status_t;

typedef struct _ra_msg4_struct {
	attestation_status_t status;
} ra_msg4_t;

#endif
