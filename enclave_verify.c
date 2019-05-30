#include <string.h>
#include "common.h"
#include "crypto.h"
#include "hexutil.h"
#include "enclave_verify.h"
#include "enclave_sigstruct.h"

sgx_measurement_t my_mr_signer;
static int _init= 0;

extern int verbose;

/* From SIGSTRUCT (See Intel SDM Chapter 38, Section 13) */
#define OFFSET_MODULUS		128
#define OFFSET_ENCLAVEHASH	960
#define OFFSET_ISVPRODID	1024
#define OFFSET_ISVSVN		1026
#define MODULUS_SIZE		384

int verify_enclave_identity(sgx_report_body_t *report) 
{
	// Initialize our MRSIGNER value. This is a SHA256 hash of the
	// modulus of the key used to sign the enclave. The modulus can
	// be found in sigstruct.

	if ( ! _init ) {
		++_init;
		if ( verbose ) {
			eprintf("Calculating MRSIGNER from SIGSTRUCT\n");
		}
		sha256_digest(&enclave_sigstruct_raw[OFFSET_MODULUS], MODULUS_SIZE,
			(unsigned char *) my_mr_signer.m);
		if ( verbose ) {
			edividerWithText("Stored enclave identity");
			eprintf("MRSIGNER    = %s\n",
				hexstring((const char *) &my_mr_signer,
				sizeof(sgx_measurement_t))
			);
			eprintf("MRENCLAVE   = %s\n",
				hexstring((const char *)
				&enclave_sigstruct_raw[OFFSET_ENCLAVEHASH],
        		sizeof(sgx_measurement_t))
			);
			eprintf("ISV Prod Id = %x\n",
				*((sgx_prod_id_t *) &enclave_sigstruct_raw[OFFSET_ISVPRODID])
			);
			eprintf("ISV SVN     = %x\n",
				*((sgx_isv_svn_t *) &enclave_sigstruct_raw[OFFSET_ISVSVN])
			);
		}
	}

	if ( verbose ) {
		edividerWithText("Client enclave Identity");
		eprintf("Enclave MRSIGNER    = %s\n", 
			hexstring((const char *) &report->mr_signer,
			sizeof(sgx_measurement_t))
		);
		eprintf("Enclave MRENCLAVE   = %s\n", 
			hexstring((const char *) &report->mr_enclave,
			sizeof(sgx_measurement_t))
		);
		eprintf("Enclave ISV Prod Id = %x\n", report->isv_prod_id);
		eprintf("Enclave ISV SVN     = %x\n", report->isv_svn);
	}

	// Does the ISV product ID match?
	if ( report->isv_prod_id !=
		*((sgx_prod_id_t *) &enclave_sigstruct_raw[OFFSET_ISVPRODID]) ) {

		eprintf("ISV Prod Id mismatch\n");

		return 0;
	}

	// Does the ISV SVN match?
	if ( report->isv_svn !=
		*((sgx_isv_svn_t *) &enclave_sigstruct_raw[OFFSET_ISVSVN]) ) {

		eprintf("ISV SVN mismatch\n");

		return 0;
	}

	// Does the MRSIGNER match?

	if ( memcmp((const void *) &report->mr_signer, 
		(const void *) &my_mr_signer, sizeof(sgx_measurement_t)) ) {

		eprintf("MRSIGNER mismatch\n");

		return 0;
	}

	// Does the MRENCLAVE match?

	if ( memcmp((const void *) &report->mr_enclave, 
		&enclave_sigstruct_raw[OFFSET_ENCLAVEHASH],
		sizeof(sgx_measurement_t)) ) {

		eprintf("MRENCLAVE mismatch\n");

		return 0;
	}

	return 1;
}

