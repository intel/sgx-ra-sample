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

#pragma once

#include <sgx_urts.h>

#define SGX_SUPPORT_UNKNOWN			0x00000000
#define SGX_SUPPORT_NO				0x80000000
#define SGX_SUPPORT_YES				0x00000001
#define SGX_SUPPORT_ENABLED			0x00000002
#define SGX_SUPPORT_REBOOT_REQUIRED	0x00000004
#define SGX_SUPPORT_ENABLE_REQUIRED	0x00000008

#ifdef __cplusplus 
extern "C" {
#endif

int get_sgx_support();

#ifdef __cplusplus
}
#endif

