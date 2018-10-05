/*

Copyright 2018 Intel Corporation

This software and the related documents are Intel copyrighted materials,
and your use of them is governed by the express license under which they
were provided to you (License). Unless the License provides otherwise,
you may not use, modify, copy, publish, distribute, disclose or transmit
this software or the related documents without Intel's prior written
permission.

This software and the related documents are provided as is, with no
express or implied warranties, other than those that are expressly stated
in the License.

*/


#include "config.h"
#include <sgx_urts.h>
#include <sgx_capable.h>
#include "sgx_stub.h"
#include "sgx_detect.h"

#ifndef NULL
#define NULL 0
#endif

int sgx_support = SGX_SUPPORT_UNKNOWN;

int get_sgx_support()
{
#ifdef SGX_HW_SIM
	return SGX_SUPPORT_YES|SGX_SUPPORT_ENABLED;
#else
	sgx_device_status_t sgx_device_status;

	if (sgx_support != SGX_SUPPORT_UNKNOWN) return sgx_support;

	sgx_support = SGX_SUPPORT_NO;

	/* Check for the PSW */

	if (! have_sgx_psw()) return sgx_support;

	sgx_support = SGX_SUPPORT_YES;

	/* Try to enable SGX */

	if (sgx_cap_get_status(&sgx_device_status) != SGX_SUCCESS)
		return sgx_support;

	/* If SGX isn't enabled yet, perform the software opt-in/enable. */

	if (sgx_device_status != SGX_ENABLED) {
		switch (sgx_device_status) {
		case SGX_DISABLED_REBOOT_REQUIRED:
			/* A reboot is required. */
			sgx_support |= SGX_SUPPORT_REBOOT_REQUIRED;
			break;
		case SGX_DISABLED_LEGACY_OS:
			/* BIOS enabling is required */
			sgx_support |= SGX_SUPPORT_ENABLE_REQUIRED;
			break;
		}

		return sgx_support;
	}

	sgx_support |= SGX_SUPPORT_ENABLED;

	return sgx_support;
#endif
}

