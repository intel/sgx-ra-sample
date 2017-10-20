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

#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include "sgx_stub.h"
#include <sgx_edger8r.h>
#include <sgx_uae_service.h>
#include <sgx_urts.h>

typedef void* (*func)();

static const char *dlerr= NULL;

static void _undefined_symbol (const char *symbol);
static void *_load_symbol(void *handle, const char *symbol, int *status);
static void *_load_libsgx_uae_service();
static void *_load_libsgx_urts();

static void *h_libsgx_uae_service= NULL;
static void *h_libsgx_urts= NULL;
static int l_libsgx_uae_service= 0;
static int l_libsgx_urts= 0;

static func p_sgx_get_whitelist= NULL;
static func p_sgx_get_extended_epid_group_id= NULL;
static func p_sgx_destroy_enclave= NULL;
static func p_sgx_calc_quote_size= NULL;
static func p_sgx_report_attestation_status= NULL;
static func p_sgx_get_quote= NULL;
static func p_sgx_init_quote= NULL;
static func p_sgx_get_ps_cap= NULL;
static func p_sgx_get_quote_size= NULL;
static func p_sgx_ecall= NULL;
static func p_sgx_get_whitelist_size= NULL;
static func p_sgx_ocall= NULL;
static func p_sgx_create_enclave= NULL;

static int l_sgx_get_whitelist= 0;
static int l_sgx_get_extended_epid_group_id= 0;
static int l_sgx_destroy_enclave= 0;
static int l_sgx_calc_quote_size= 0;
static int l_sgx_report_attestation_status= 0;
static int l_sgx_get_quote= 0;
static int l_sgx_init_quote= 0;
static int l_sgx_get_ps_cap= 0;
static int l_sgx_get_quote_size= 0;
static int l_sgx_ecall= 0;
static int l_sgx_get_whitelist_size= 0;
static int l_sgx_ocall= 0;
static int l_sgx_create_enclave= 0;

static void _undefined_symbol (const char *symbol)
{
	fprintf(stderr, "%s: %s\n", symbol, dlerr);
	exit(1);
}

static void *_load_symbol(void *handle, const char *symbol, int *status)
{
	void *hsym;

	dlerr= dlerror();
	hsym= dlsym(handle, symbol);
	dlerr= dlerror();
	*status= ( dlerr == NULL ) ? 1 : -1;

	return hsym;
}


static void *_load_libsgx_uae_service()
{
	if ( l_libsgx_uae_service == 0 ) {
		h_libsgx_uae_service= dlopen("libsgx_uae_service.so", RTLD_GLOBAL|RTLD_NOW);
		l_libsgx_uae_service= ( h_libsgx_uae_service == NULL ) ? -1 : 1;
	}

	return h_libsgx_uae_service;
}

static void *_load_libsgx_urts()
{
	if ( l_libsgx_urts == 0 ) {
		h_libsgx_urts= dlopen("libsgx_urts.so", RTLD_GLOBAL|RTLD_NOW);
		l_libsgx_urts= ( h_libsgx_urts == NULL ) ? -1 : 1;
	}

	return h_libsgx_urts;
}

int have_sgx_psw()
{
	return ( 
		_load_libsgx_uae_service() == NULL ||
		_load_libsgx_urts() == NULL 
	) ? 0 : 1;
}


sgx_status_t sgx_get_whitelist(uint8_t *p_whitelist, uint32_t whitelist_size)
{
	if ( l_sgx_get_whitelist == 0 ) {
		if ( h_libsgx_uae_service == 0 ) _load_libsgx_uae_service();
		*(void **)(&p_sgx_get_whitelist)=
			_load_symbol(h_libsgx_uae_service,
			"sgx_get_whitelist",
			&l_sgx_get_whitelist);
	}

	if ( l_sgx_get_whitelist == -1 )
		_undefined_symbol("sgx_get_whitelist");

	return (sgx_status_t) p_sgx_get_whitelist(p_whitelist, whitelist_size);
}

sgx_status_t sgx_get_extended_epid_group_id(uint32_t *p_extended_epid_group_id)
{
	if ( l_sgx_get_extended_epid_group_id == 0 ) {
		if ( h_libsgx_uae_service == 0 ) _load_libsgx_uae_service();
		*(void **)(&p_sgx_get_extended_epid_group_id)=
			_load_symbol(h_libsgx_uae_service,
			"sgx_get_extended_epid_group_id",
			&l_sgx_get_extended_epid_group_id);
	}

	if ( l_sgx_get_extended_epid_group_id == -1 )
		_undefined_symbol("sgx_get_extended_epid_group_id");

	return (sgx_status_t) p_sgx_get_extended_epid_group_id(p_extended_epid_group_id);
}

sgx_status_t sgx_destroy_enclave(const sgx_enclave_id_t enclave_id)
{
	if ( l_sgx_destroy_enclave == 0 ) {
		if ( h_libsgx_urts == 0 ) _load_libsgx_urts();
		*(void **)(&p_sgx_destroy_enclave)=
			_load_symbol(h_libsgx_urts,
			"sgx_destroy_enclave",
			&l_sgx_destroy_enclave);
	}

	if ( l_sgx_destroy_enclave == -1 )
		_undefined_symbol("sgx_destroy_enclave");

	return (sgx_status_t) p_sgx_destroy_enclave(enclave_id);
}

sgx_status_t sgx_calc_quote_size(const uint8_t *p_sig_rl, uint32_t sig_rl_size, uint32_t *p_quote_size)
{
	if ( l_sgx_calc_quote_size == 0 ) {
		if ( h_libsgx_uae_service == 0 ) _load_libsgx_uae_service();
		*(void **)(&p_sgx_calc_quote_size)=
			_load_symbol(h_libsgx_uae_service,
			"sgx_calc_quote_size",
			&l_sgx_calc_quote_size);
	}

	if ( l_sgx_calc_quote_size == -1 )
		_undefined_symbol("sgx_calc_quote_size");

	return (sgx_status_t) p_sgx_calc_quote_size(p_sig_rl, sig_rl_size, p_quote_size);
}

sgx_status_t sgx_report_attestation_status(const sgx_platform_info_t *p_platform_info, int attestation_status, sgx_update_info_bit_t *p_update_info)
{
	if ( l_sgx_report_attestation_status == 0 ) {
		if ( h_libsgx_uae_service == 0 ) _load_libsgx_uae_service();
		*(void **)(&p_sgx_report_attestation_status)=
			_load_symbol(h_libsgx_uae_service,
			"sgx_report_attestation_status",
			&l_sgx_report_attestation_status);
	}

	if ( l_sgx_report_attestation_status == -1 )
		_undefined_symbol("sgx_report_attestation_status");

	return (sgx_status_t) p_sgx_report_attestation_status(p_platform_info, attestation_status, p_update_info);
}

sgx_status_t sgx_get_quote(const sgx_report_t *p_report, sgx_quote_sign_type_t quote_type, const sgx_spid_t *p_spid, const sgx_quote_nonce_t *p_nonce, const uint8_t *p_sig_rl, uint32_t sig_rl_size, sgx_report_t *p_qe_report, sgx_quote_t *p_quote, uint32_t quote_size)
{
	if ( l_sgx_get_quote == 0 ) {
		if ( h_libsgx_uae_service == 0 ) _load_libsgx_uae_service();
		*(void **)(&p_sgx_get_quote)=
			_load_symbol(h_libsgx_uae_service,
			"sgx_get_quote",
			&l_sgx_get_quote);
	}

	if ( l_sgx_get_quote == -1 )
		_undefined_symbol("sgx_get_quote");

	return (sgx_status_t) p_sgx_get_quote(p_report, quote_type, p_spid, p_nonce, p_sig_rl, sig_rl_size, p_qe_report, p_quote, quote_size);
}

sgx_status_t sgx_init_quote(sgx_target_info_t *p_target_info, sgx_epid_group_id_t *p_gid)
{
	if ( l_sgx_init_quote == 0 ) {
		if ( h_libsgx_uae_service == 0 ) _load_libsgx_uae_service();
		*(void **)(&p_sgx_init_quote)=
			_load_symbol(h_libsgx_uae_service,
			"sgx_init_quote",
			&l_sgx_init_quote);
	}

	if ( l_sgx_init_quote == -1 )
		_undefined_symbol("sgx_init_quote");

	return (sgx_status_t) p_sgx_init_quote(p_target_info, p_gid);
}

sgx_status_t sgx_get_ps_cap(sgx_ps_cap_t *p_sgx_ps_cap)
{
	if ( l_sgx_get_ps_cap == 0 ) {
		if ( h_libsgx_uae_service == 0 ) _load_libsgx_uae_service();
		*(void **)(&p_sgx_get_ps_cap)=
			_load_symbol(h_libsgx_uae_service,
			"sgx_get_ps_cap",
			&l_sgx_get_ps_cap);
	}

	if ( l_sgx_get_ps_cap == -1 )
		_undefined_symbol("sgx_get_ps_cap");

	return (sgx_status_t) p_sgx_get_ps_cap(p_sgx_ps_cap);
}

sgx_status_t sgx_get_quote_size(const uint8_t *p_sig_rl, uint32_t *p_quote_size)
{
	if ( l_sgx_get_quote_size == 0 ) {
		if ( h_libsgx_uae_service == 0 ) _load_libsgx_uae_service();
		*(void **)(&p_sgx_get_quote_size)=
			_load_symbol(h_libsgx_uae_service,
			"sgx_get_quote_size",
			&l_sgx_get_quote_size);
	}

	if ( l_sgx_get_quote_size == -1 )
		_undefined_symbol("sgx_get_quote_size");

	return (sgx_status_t) p_sgx_get_quote_size(p_sig_rl, p_quote_size);
}

sgx_status_t sgx_ecall(const sgx_enclave_id_t eid, const int index, const void *ocall_table, void *ms)
{
	if ( l_sgx_ecall == 0 ) {
		if ( h_libsgx_urts == 0 ) _load_libsgx_urts();
		*(void **)(&p_sgx_ecall)=
			_load_symbol(h_libsgx_urts,
			"sgx_ecall",
			&l_sgx_ecall);
	}

	if ( l_sgx_ecall == -1 )
		_undefined_symbol("sgx_ecall");

	return (sgx_status_t) p_sgx_ecall(eid, index, ocall_table, ms);
}

sgx_status_t sgx_get_whitelist_size(uint32_t *p_whitelist_size)
{
	if ( l_sgx_get_whitelist_size == 0 ) {
		if ( h_libsgx_uae_service == 0 ) _load_libsgx_uae_service();
		*(void **)(&p_sgx_get_whitelist_size)=
			_load_symbol(h_libsgx_uae_service,
			"sgx_get_whitelist_size",
			&l_sgx_get_whitelist_size);
	}

	if ( l_sgx_get_whitelist_size == -1 )
		_undefined_symbol("sgx_get_whitelist_size");

	return (sgx_status_t) p_sgx_get_whitelist_size(p_whitelist_size);
}

sgx_status_t sgx_ocall(const unsigned int index, void *ms)
{
	if ( l_sgx_ocall == 0 ) {
		if ( h_libsgx_urts == 0 ) _load_libsgx_urts();
		*(void **)(&p_sgx_ocall)=
			_load_symbol(h_libsgx_urts,
			"sgx_ocall",
			&l_sgx_ocall);
	}

	if ( l_sgx_ocall == -1 )
		_undefined_symbol("sgx_ocall");

	return (sgx_status_t) p_sgx_ocall(index, ms);
}

sgx_status_t sgx_create_enclave(const char *file_name, const int debug, sgx_launch_token_t *launch_token, int *launch_token_updated, sgx_enclave_id_t *enclave_id, sgx_misc_attribute_t *misc_attr)
{
	if ( l_sgx_create_enclave == 0 ) {
		if ( h_libsgx_urts == 0 ) _load_libsgx_urts();
		*(void **)(&p_sgx_create_enclave)=
			_load_symbol(h_libsgx_urts,
			"sgx_create_enclave",
			&l_sgx_create_enclave);
	}

	if ( l_sgx_create_enclave == -1 )
		_undefined_symbol("sgx_create_enclave");

	return (sgx_status_t) p_sgx_create_enclave(file_name, debug, launch_token, launch_token_updated, enclave_id, misc_attr);
}
