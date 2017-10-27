#pragma once

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