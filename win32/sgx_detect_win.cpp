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

#include <Windows.h>
#include <fcntl.h>
#include <io.h>
#include <sgx_urts.h>
#include <sgx_uae_service.h>
#include <sgx.h>
#include "../sgx_detect.h"

static HINSTANCE h_urts = NULL;
static HINSTANCE h_service = NULL;

int sgx_support = SGX_SUPPORT_UNKNOWN;

typedef sgx_status_t(SGXAPI *fp_sgx_enable_device_t)(sgx_device_status_t *);
typedef sgx_status_t(SGXAPI *fp_sgx_get_quote_size_t)(const uint8_t *p_sig_rl, uint32_t *p_quote_size);
typedef sgx_status_t(SGXAPI *fp_sgx_calc_quote_size_t)(const uint8_t *p_sig_rl, uint32_t p_sigrl_size, uint32_t *p_quote_size);


int is_psw_installed();

int get_sgx_support()
{
	fp_sgx_enable_device_t fp_sgx_enable_device = NULL;
	sgx_device_status_t sgx_device_status;

	if (sgx_support != SGX_SUPPORT_UNKNOWN) return sgx_support;

	sgx_support = SGX_SUPPORT_NO;

	// Check for the PSW

	if (! is_psw_installed()) return sgx_support;

	sgx_support = SGX_SUPPORT_YES;

	// Try to enable SGX

	fp_sgx_enable_device = (fp_sgx_enable_device_t)GetProcAddress(h_service, "sgx_enable_device");
	if (fp_sgx_enable_device(&sgx_device_status) != SGX_SUCCESS) return sgx_support;

	// If SGX isn't enabled yet, perform the software opt-in/enable.

	if (sgx_device_status != SGX_ENABLED) {
		switch (sgx_device_status) {
		case SGX_DISABLED_REBOOT_REQUIRED:
			// A reboot is required.
			sgx_support |= SGX_SUPPORT_REBOOT_REQUIRED;
			break;
		case SGX_DISABLED_LEGACY_OS:
			// BIOS enabling is required
			sgx_support |= SGX_SUPPORT_ENABLE_REQUIRED;
			break;
		}

		return sgx_support;
	}

	sgx_support |= SGX_SUPPORT_ENABLED;

	return sgx_support;
}

int is_psw_installed()
{
	LPSTR systemdir;
	UINT rv, sz;

	// Get the system directory path. Start by finding out how much space we need
	// to hold it.

	sz = GetSystemDirectory(NULL, 0);
	if (sz == 0) return 0;

	systemdir = new CHAR[sz + 1];
	rv = GetSystemDirectory(systemdir, sz);
	if (rv == 0 || rv > sz) return 0;

	// Set our DLL search path to just the System directory so we don't accidentally
	// load the DLLs from an untrusted path.

	if (SetDllDirectory(systemdir) == 0) {
		delete[] systemdir;
		return 0;
	}

	delete[] systemdir; // No longer need this

	// Need to be able to load both of these DLLs from the System directory.

	if ((h_service = LoadLibrary("sgx_uae_service.dll")) == NULL) {
		return 0;
	}

	if ((h_urts = LoadLibrary("sgx_urts.dll")) == NULL) {
		FreeLibrary(h_service);
		h_service = NULL;
		return 0;
	}

	return 1;
}
