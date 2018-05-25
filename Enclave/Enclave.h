#ifndef __ENCLAVE_QUOTE_H
#define __ENCLAVE_QUOTE_H

typedef enum _ra_state
{
    ra_inited= 0,
    ra_get_gaed,
    ra_proc_msg2ed
}ra_state;

typedef struct _ra_db_item_t
{
    sgx_ec256_public_t          g_a;
    sgx_ec256_public_t          g_b;
    sgx_ec_key_128bit_t         vk_key;
    sgx_ec256_public_t          sp_pubkey;
    sgx_ec256_private_t         a;
    sgx_ps_sec_prop_desc_t      ps_sec_prop;
    sgx_ec_key_128bit_t         mk_key;
    sgx_ec_key_128bit_t         sk_key;
    sgx_ec_key_128bit_t         smk_key;
    sgx_quote_nonce_t           quote_nonce;
    sgx_target_info_t           qe_target; 
    ra_state                    state;
    sgx_spinlock_t              item_lock;
    uintptr_t                   derive_key_cb;
} ra_db_item_t;

#endif

