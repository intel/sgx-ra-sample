#ifndef __PROTOCOL_H
#define __PROTOCOL_H

#include <inttypes.h>
#include <sgx_quote.h>

/*
 * Define a structure to be used to transfer the Attestation Status 
 * from Server to client and include the Platform Info Blob in base16 
 * format as Message 4.
 *
 * The structure of Message 4 is not defined by SGX: it is up to the
 * service provider, and can include more than just the attestation
 * status and platform info blob.
 */

/*
 * This doesn't have to be binary. You could, in theory, return a
 * "trusted, with conditions" response, for example, if IAS reports
 * GROUP_OUT_OF_DATE.
 */

typedef enum {
	NotTrusted = 0,
	Trusted
} attestation_status_t;

typedef struct _ra_msg4_struct {
	attestation_status_t status;
	sgx_platform_info_t platformInfoBlob;
} ra_msg4_t;

#endif

