#ifndef _ENCLAVE_VERIFY_H
#define _ENCLAVE_VERIFY_H

#include <sgx_report.h>

#ifdef __cplusplus
extern "C" {
#endif

int verify_enclave_identity(sgx_measurement_t mrsigner, sgx_prod_id_t prodid,
	sgx_isv_svn_t min_isvsvn, int allow_debug, sgx_report_body_t *report);

#ifdef __cplusplus
};
#endif

#endif
