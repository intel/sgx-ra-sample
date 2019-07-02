#include <string.h>
#include "common.h"
#include "crypto.h"
#include "hexutil.h"
#include "enclave_verify.h"

/*
 * Validate the identity of the enclave.
 *
 * After the enclave report is verified by the Intel Attestation Service,
 * examine the metadata in the report to ensure it's an enclave that we
 * recognize. This code sample looks for four things: 
 *
 *  1) The enclave signer measurement (MRSIGNER) matches the measurement
 *     of the key used to sign the enclave. The signing key is in 
 *     Enclave/Enclave_private.pem
 *
 *  2) The ISV Product Id is == our expected Product ID. The product
 *     ID is set in Enclave/Enclave_config.xml. This allows ISV's to
 *     create multiple enclaves for multiple applications, but only
 *     allow a subset of those to attest to this particular service.
 *     In this code sampole, we only accept one enclave (the one
 *     that comes with it).
 *
 *  3) The ISV Software Version number (isvsvn) >= a minimum version
 *     number specified at runtime. The Enclave's version number is
 *     set in Enclave/Enclave_config.xml. This allows an ISV to enforce
 *     a minimum software version number which is a means of enforcing
 *     software updats on the client.
 * 
 *  4) Check to see if the enclave was compiled in debug mode. This
 *     code sample allows a debug-mode enclave to attest, but a 
 *     production service should NEVER allow debug enclaves.
 *
 * 1-3 are policy decisions that the ISV must make.
 *
 */

sgx_measurement_t my_mr_signer;
static int _init= 0;

extern int verbose;

int verify_enclave_identity(sgx_measurement_t req_mr_signer, 
	sgx_prod_id_t req_isv_product_id, sgx_isv_svn_t min_isvsvn,
	int allow_debug, sgx_report_body_t *report)
{
	if ( verbose ) {
		edividerWithText("Client enclave Identity");
		eprintf("Enclave MRSIGNER      = %s\n", 
			hexstring((const char *) &report->mr_signer,
			sizeof(sgx_measurement_t))
		);
		eprintf("Enclave MRENCLAVE     = %s\n", 
			hexstring((const char *) &report->mr_enclave,
			sizeof(sgx_measurement_t))
		);
		eprintf("Enclave ISV Prod Id   = %x\n", report->isv_prod_id);
		eprintf("Enclave ISV SVN       = %x\n", report->isv_svn);
		eprintf("Enclave is debuggable = %s\n",
			( report->attributes.flags & SGX_FLAGS_DEBUG ) ? "Yes" : "No"
		);
	}

	// Is the enclave compiled in debug mode?
	if ( ! allow_debug ) {
		if ( report->attributes.flags & SGX_FLAGS_DEBUG ) {
			eprintf("Debug-mode enclave not allowed\n");
			return 0;
		}
	}

	// Does the ISV product ID meet the minimum requirement?
	if ( report->isv_prod_id != req_isv_product_id ) {
		eprintf("ISV Product Id mismatch: saw %u, expected %u\n",
			report->isv_prod_id, req_isv_product_id);

		return 0;
	}

	// Does the ISV SVN meet the minimum version?
	if ( report->isv_svn < min_isvsvn ) {
		eprintf("ISV SVN version too low: %u < %u\n", report->isv_svn,
			min_isvsvn);

		return 0;
	}

	// Does the MRSIGNER match?

	if ( memcmp((const void *) &report->mr_signer, 
		(const void *) &req_mr_signer, sizeof(sgx_measurement_t) ) ) {

		eprintf("MRSIGNER mismatch\n");

		return 0;
	}

	return 1;
}

