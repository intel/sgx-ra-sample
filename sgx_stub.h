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

#ifndef __SGX_STUB_H
#define __SGX_STUB_H

#ifdef __cplusplus
extern "C" {
#endif

	int have_sgx_psw();

	void *get_sgx_ufunction(const char *name); /* Returns func pointer */

#ifdef __cplusplus
};
#endif

#endif
