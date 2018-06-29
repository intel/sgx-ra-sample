/*
Copyright 2017 Intel Corporation

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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

