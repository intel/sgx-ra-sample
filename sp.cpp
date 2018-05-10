/*

Copyright 2018 Intel Corporation

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

THIS SOFTWARE IS PROVIDED BY INTEL CORPORATION "AS IS" AND ANY EXPRESS
OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OFLIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/


#ifndef _WIN32
#include "config.h"
#endif

#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/types.h>
#ifdef _WIN32
#include <intrin.h>
#include "win32/getopt.h"
#else
#include <getopt.h>
#include <unistd.h>
#endif
#include <sgx_key_exchange.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "json.hpp"
#include "common.h"
#include "hexutil.h"
#include "fileio.h"
#include "crypto.h"
#include "byteorder.h"
#include "msgio.h"
#include "protocol.h"
#include "base64.h"
#include "iasrequest.h"
#include "logfile.h"

using namespace json;
using namespace std;

#include <map>
#include <string>
#include <iostream>

#ifdef _WIN32
#define strdup(x) _strdup(x)
#endif

static const unsigned char def_service_private_key[32] = {
	0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce,
	0x3b, 0x66, 0xde, 0x11, 0x43, 0x9c, 0x87, 0xec,
	0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6, 0xae, 0xea,
	0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01
};

typedef struct config_struct {
	sgx_spid_t spid;
	uint16_t quote_type;
	EVP_PKEY *service_private_key;
	EVP_PKEY *session_private_key;
	unsigned char kdk[16];
	char *cert_file;
	char *cert_type[4];
	X509_STORE *store;
	X509 *signing_ca;
} config_t;

Msg4 msg4;

void usage();

int derive_kdk(EVP_PKEY *Gb, unsigned char kdk[16], sgx_ra_msg1_t *msg1,
	config_t *config);

int process_msg01 (IAS_Connection *ias, sgx_ra_msg2_t *msg2, char **sigrl,
	config_t *config);
int process_msg3 (IAS_Connection *ias, ra_msg4_t *msg2, config_t *config);

int get_sigrl (IAS_Connection *ias, sgx_epid_group_id_t gid, char **sigrl,
	uint32_t *msg2);
int get_attestation_report(IAS_Connection *ias, const char *b64quote,
	sgx_ps_sec_prop_desc_t sec_prop);

char debug= 0;
char verbose= 0;

int main(int argc, char *argv[])
{
	char flag_spid = 0;
	char flag_pubkey = 0;
	char flag_cert = 0;
	char flag_ca = 0;
	char flag_usage = 0;
	char *sigrl = NULL;
	config_t config;
	sgx_ra_msg2_t msg2;
	ra_msg4_t msg4;
	int oops;
	IAS_Connection *ias= NULL;

	/* Create a logfile to capture debug output and actual msg data */

	fplog = create_logfile("sp.log");
	fprintf(fplog, "Server log started\n");

	memset(&config, 0, sizeof(config));
#ifdef _WIN32
	strncpy_s((char *)config.cert_type, 4, "PEM", 3);
#else
	strncpy((char *)config.cert_type, "PEM", 3);
#endif
	static struct option long_opt[] =
	{
		{"ias-signing-cafile",
							required_argument,	0, 'A'},
		{"ias-cert-file",	required_argument,	0, 'C'},
		{"key-file",		required_argument,	0, 'K'},
		{"spid-file",		required_argument,	0, 'S'},
		{"debug",			required_argument,	0, 'd'},
		{"session-key",		required_argument,	0, 'e'},
		{"help",			no_argument, 		0, 'h'},
		{"key",				required_argument,	0, 'k'},
		{"linkable",		no_argument,		0, 'l'},
		{"spid",			required_argument,	0, 's'},
		{"ias-cert-type",	required_argument,	0, 't'},
		{"verbose",			no_argument,		0, 'v'},
		{ 0, 0, 0, 0 }
	};

	/* Parse our options */

	while (1) {
		int c;
		int opt_index = 0;

		c = getopt_long(argc, argv, "A:C:K:S:de:hk:lr:s:v", long_opt, &opt_index);
		if (c == -1) break;

		switch (c) {
		case 0:
			break;
		case 'A':
			if (!cert_load_file(&config.signing_ca, optarg)) {
				crypto_perror("cert_load_file");
				eprintf("%s: could not load IAS Signing Cert CA\n", optarg);
				return 1;
			}

			config.store = cert_init_ca(config.signing_ca);
			if (config.store == NULL) {
				eprintf("%s: could not initialize certificate store\n", optarg);
				return 1;
			}
			++flag_ca;

			break;
		case 'C':
			config.cert_file = strdup(optarg);
			if (config.cert_file == NULL) {
				perror("strdup");
				return 1;
			}
			++flag_cert;

			break;
		case 'S':
			if (!from_hexstring_file((unsigned char *)&config.spid, optarg, 16)) {
				eprintf("SPID must be 32-byte hex string\n");
				return 1;
			}
			++flag_spid;

			break;
		case 'K':
			if (!key_load_file(&config.service_private_key, optarg, KEY_PRIVATE)) {
				crypto_perror("key_load_file");
				eprintf("%s: could not load EC private key\n", optarg);
				return 1;
			}
			break;
		case 'd':
			debug = 1;
			break;
		case 'e':
			if (!key_load(&config.session_private_key, optarg, KEY_PRIVATE)) {
				crypto_perror("key_load");
				eprintf("%s: could not load session key\n", optarg);
				return 1;
			}
			break;
		case 'k':
			if (!key_load(&config.service_private_key, optarg, KEY_PRIVATE)) {
				crypto_perror("key_load");
				eprintf("%s: could not load EC private key\n", optarg);
				return 1;
			}
			break;
		case 'l':
			config.quote_type = SGX_LINKABLE_SIGNATURE;
			break;
		case 's':
			if (strlen(optarg) < 32) {
				eprintf("SPID must be 32-byte hex string\n");
				return 1;
			}
			if (!from_hexstring((unsigned char *)&config.spid, (unsigned char *)optarg, 16)) {
				eprintf("SPID must be 32-byte hex string\n");
				return 1;
			}
			++flag_spid;
			break;
		case 't':
			break;
		case 'v':
			verbose = 1;
			break;
		case 'h':
		case '?':
		default:
			usage();
		}
	}

	/*
	 * Use the hardcoded default key unless one is provided on the
	 * command line. Most real-world services would hardcode the
	 * key since the public half is also hardcoded into the enclave.
	 */

	if (config.service_private_key == NULL) {
		if (debug) {
			eprintf("Using default private key\n");
		}
		config.service_private_key = key_private_from_bytes(def_service_private_key);
		if (config.service_private_key == NULL) {
			crypto_perror("key_private_from_bytes");
			return 1;
		}

	}

	if (debug) {
		eprintf("+++ using private key:\n");
		PEM_write_PrivateKey(stderr, config.service_private_key, NULL,
			NULL, 0, 0, NULL);
		PEM_write_PrivateKey(fplog, config.service_private_key, NULL,
			NULL, 0, 0, NULL);
	}

	if (!flag_spid) {
		eprintf("--spid or --spid-file is required\n");
		flag_usage = 1;
	}

	if (!flag_cert) {
		eprintf("--ias-cert-file is required\n");
		flag_usage = 1;
	}

	if (!flag_ca) {
		eprintf("--ias-signing-cafile is required\n");
		flag_usage = 1;
	}

	if (flag_usage) usage();

	if (verbose) eprintf("Using cert file %s\n", config.cert_file);

	/* Initialize out support libraries */

	crypto_init();

	/* Initialize our IAS request object */

	try {
		ias = new IAS_Connection(IAS_SERVER_DEVELOPMENT, 0);
		ias->client_cert(config.cert_file, (char *)config.cert_type);
	}
	catch (int e) {
		oops = 1;
		eprintf("exception while creating IAS request object\n");
		return 1;
	}

	/* Set the cert store for this connect */
	ias->cert_store(config.store);

	/* Read message 0 and 1, then generate message 2 */

	if ( ! process_msg01(ias, &msg2, &sigrl, &config) ) {
		eprintf("error processing msg1\n");
		crypto_destroy();
		return 1;
	}

	/* Send message 2 */

	/*
	 * sgx_ra_msg2_t is a struct with a flexible array member at the
	 * end (defined as uint8_t sig_rl[]). We could go to all the 
	 * trouble of building a byte array large enough to hold the
	 * entire struct and then cast it as (sgx_ra_msg2_t) but that's
	 * a lot of work for no gain when we can just send the fixed 
	 * portion and the array portion by hand.
	 */

	dividerWithText(stderr, "Copy/Paste Msg2 Below to Client");
	dividerWithText(fplog, "Msg2 (send to Client)");

	send_msg_partial((void *) &msg2, sizeof(sgx_ra_msg2_t));
	fsend_msg_partial(fplog, (void *) &msg2, sizeof(sgx_ra_msg2_t));

	send_msg(&msg2.sig_rl, msg2.sig_rl_size);
	fsend_msg(fplog, &msg2.sig_rl, msg2.sig_rl_size);

	edivider();

	/* Read message 3 */

	process_msg3(ias, &msg4, &config);

	crypto_destroy();

	return 0;
}

int process_msg3 (IAS_Connection *ias, ra_msg4_t *msg4, config_t *config)
{
	sgx_ra_msg3_t *msg3;
	size_t blen= 0;
	size_t sz;
	int rv;
	uint32_t quote_sz;
	char *buffer= NULL;
	char *b64quote;

	/*
	 * Read our incoming message. We're using base16 encoding/hex strings
	 * so we should end up with sizeof(msg)*2 bytes.
	 */

	fprintf(stderr, "Waiting for msg3 on stdin\n");

	/*
	 * Read message 3
	 *
	 * CMACsmk(M) || M
	 *
	 * where
	 *
	 * M = ga || PS_SECURITY_PROPERTY || QUOTE
	 *
	 */

	rv= read_msg((void **) &msg3, &sz);
	if ( rv == -1 ) {
		eprintf("system error reading msg3\n");
		return 0;
	} else if ( rv == 0 ) {
		eprintf("protocol error reading msg3\n");
		return 0;
	}
	if ( debug ) {
		eprintf("+++ read %lu bytes\n", sz);
	}

	/*
	 * The quote size will be the total msg3 size - sizeof(sgx_ra_msg3_t)
	 * since msg3.quote is a flexible array member.
	 *
	 * Total message size is sz/2 since the income message is in base16.
	 */
	quote_sz = (uint32_t)((sz / 2) - sizeof(sgx_ra_msg3_t));

	/* Encode the report body as base64 */

	b64quote= base64_encode((char *) &msg3->quote, quote_sz);

	if ( verbose ) {
		sgx_quote_t *q= (sgx_quote_t *) msg3->quote;

		edividerWithText("Msg3 Details (from Client)");
		eprintf("msg3.mac                 = %s\n",
			hexstring(&msg3->mac, sizeof(msg3->mac)));
		eprintf("msg3.g_a.gx              = %s\n",
			hexstring(msg3->g_a.gx, sizeof(msg3->g_a.gx)));
		eprintf("msg3.g_a.gy              = %s\n",
			hexstring(&msg3->g_a.gy, sizeof(msg3->g_a.gy)));
		eprintf("msg3.ps_sec_prop         = %s\n",
			hexstring(&msg3->ps_sec_prop, sizeof(msg3->ps_sec_prop)));
		eprintf("msg3.quote.version       = %s\n",
			hexstring(&q->version, sizeof(uint16_t)));
		eprintf("msg3.quote.sign_type     = %s\n",
			hexstring(&q->sign_type, sizeof(uint16_t)));
		eprintf("msg3.quote.epd_group_id  = %s\n",
			hexstring(&q->epid_group_id, sizeof(sgx_epid_group_id_t)));
		eprintf("msg3.quote.qe_svn        = %s\n",
			hexstring(&q->qe_svn, sizeof(sgx_isv_svn_t)));
		eprintf("msg3.quote.pce_svn       = %s\n",
			hexstring(&q->pce_svn, sizeof(sgx_isv_svn_t)));
		eprintf("msg3.quote.xeid          = %s\n",
			hexstring(&q->xeid, sizeof(uint32_t)));
		eprintf("msg3.quote.basename      = %s\n",
			hexstring(&q->basename, sizeof(sgx_basename_t)));
		eprintf("msg3.quote.report_body   = %s\n",
			hexstring(&q->report_body, sizeof(sgx_report_body_t)));
		eprintf("msg3.quote.signature_len = %s\n",
			hexstring(&q->signature_len, sizeof(uint32_t)));
		eprintf("msg3.quote.signature     = %s\n",
			hexstring(&q->signature, q->signature_len));

		edividerWithText("Enclave Quote (base64) ==> Send to IAS");

		eputs(b64quote);

		eprintf("\n");
		edivider();
	}

	if ( ! get_attestation_report(ias, b64quote, msg3->ps_sec_prop) ) {
		eprintf("Attestation failed\n");
	}

	free(b64quote);

	return 1;
}

/*
 * Read and process message 0 and message 1. These messages are sent by
 * the client concatenated together for efficiency (msg0||msg1).
 */

int process_msg01 (IAS_Connection *ias, sgx_ra_msg2_t *msg2, char **sigrl,
	config_t *config)
{
	struct msg01_struct {
		uint32_t msg0_extended_epid_group_id;
		sgx_ra_msg1_t msg1;
	} *msg01;
	sgx_ra_msg1_t *msg1;
	size_t blen= 0;
	char *buffer= NULL;
	unsigned char smk[16], gb_ga[128];
	unsigned char digest[32], r[32], s[32];
	EVP_PKEY *Gb;
	int rv;

	memset(msg2, 0, sizeof(sgx_ra_msg2_t));

	/*
	 * Read our incoming message. We're using base16 encoding/hex strings
	 * so we should end up with sizeof(msg)*2 bytes.
	 */

	fprintf(stderr, "Waiting for msg0||msg1 on stdin\n");

	rv= read_msg((void **) &msg01, NULL);
	if ( rv == -1 ) {
		eprintf("system error reading msg0||msg1\n");
		return 0;
	} else if ( rv == 0 ) {
		eprintf("protocol error reading msg0||msg1\n");
		return 0;
	}

	if ( verbose ) {
		edividerWithText("Msg0 Details (from Client)");
		eprintf("msg0.extended_epid_group_id = %u\n",
			 msg01->msg0_extended_epid_group_id);
		edivider();
	}

	/* According to the Intel SGX Developer Reference
	 * "Currently, the only valid extended Intel(R) EPID group ID is zero. The
	 * server should verify this value is zero. If the Intel(R) EPID group ID 
	 * is not zero, the server aborts remote attestation"
	 */

	if ( msg01->msg0_extended_epid_group_id != 0 ) {
		eprintf("msg0 Extended Epid Group ID is not zero.  Exiting.\n");
		free(msg01);
		return 0;
	}

	msg1= &msg01->msg1;	

	if ( verbose ) {
		edividerWithText("Msg1 Details (from Client)");
		eprintf("msg1.g_a.gx = %s\n",
			hexstring(&msg1->g_a.gx, sizeof(msg1->g_a.gx)));
		eprintf("msg1.g_a.gy = %s\n",
			hexstring(&msg1->g_a.gy, sizeof(msg1->g_a.gy)));
		eprintf("msg1.gid    = %s\n",
			hexstring( &msg1->gid, sizeof(msg1->gid)));
		edivider();
	}

	if ( config->session_private_key == NULL ) {
		/* Generate our session key */

		if ( debug ) eprintf("+++ generating session key Gb\n");

		Gb= key_generate();
		if ( Gb == NULL ) {
			eprintf("Could not create a session key\n");
			free(msg01);
			return 0;
		}
	} else {
		/* Use a fixed session key for testing purposes */
		Gb= config->session_private_key;

		if ( debug ) eprintf("+++ using stated session key Gb\n");
	}

	/*
	 * Derive the KDK from the key (Ga) in msg1 and our session key.
	 * An application would normally protect the KDK in memory to 
	 * prevent trivial inspection.
	 */

	if ( debug ) eprintf("+++ deriving KDK\n");

	if ( ! derive_kdk(Gb, config->kdk, msg1, config) ) {
		eprintf("Could not derive the KDK\n");
		free(msg01);
		return 0;
	}

	if ( debug ) eprintf("+++ KDK = %s\n", hexstring( config->kdk, 16));

	/*
 	 * Derive the SMK from the KDK 
	 * SMK = AES_CMAC(KDK, 0x01 || "SMK" || 0x00 || 0x80 || 0x00) 
	 */

	if ( debug ) eprintf("+++ deriving SMK\n");

	cmac128(config->kdk, (unsigned char *)("\x01SMK\x00\x80\x00"), 7, smk);

	if ( debug ) eprintf("+++ SMK = %s\n", hexstring(smk, 16));

	/*
	 * Build message 2
	 *
	 * A || CMACsmk(A) || SigRL
	 * (148 + 16 + SigRL_length bytes = 164 + SigRL_length bytes)
	 *
	 * where:
	 *
	 * A      = Gb || SPID || TYPE || KDF-ID || SigSP(Gb, Ga) 
	 *          (64 + 16 + 2 + 2 + 64 = 148 bytes)
	 * Ga     = Client enclave's session key
	 *          (64 bytes)
	 * Gb     = Service Provider's session key
	 *          (64 bytes)
	 * SPID   = The Service Provider ID, issued by Intel to the vendor
	 *          (16 bytes)
	 * TYPE   = Quote type (0= linkable, 1= linkable)
	 *          (2 bytes)
	 * KDF-ID = (0x0001= CMAC entropy extraction and key derivation)
	 *          (2 bytes)
	 * SigSP  = ECDSA signature of (Gb.x || Gb.y || Ga.x || Ga.y) as r || s
	 *          (signed with the Service Provider's private key)
	 *          (64 bytes)
	 *
	 * CMACsmk= AES-128-CMAC(A)
	 *          (16 bytes)
	 * 
	 * || denotes concatenation
	 *
	 * Note that all key components (Ga.x, etc.) are in little endian 
	 * format, meaning the byte streams need to be reversed.
	 *
	 * For SigRL, send:
	 *
	 *  SigRL_size || SigRL_contensts
	 *
	 * where sigRL_size is a 32-bit uint (4 bytes). This matches the
	 * structure definition in sgx_ra_msg2_t
	 */

	key_to_sgx_ec256(&msg2->g_b, Gb);
	memcpy(&msg2->spid, &config->spid, sizeof(sgx_spid_t));
	msg2->quote_type= config->quote_type;
	msg2->kdf_id= 1;

	/* Get the sigrl */

	if ( ! get_sigrl(ias, msg1->gid, sigrl, &msg2->sig_rl_size) ) {
		eprintf("could not retrieve the sigrl\n");
		return 0;
	}

	memcpy(gb_ga, &msg2->g_b, 64);
	memcpy(&gb_ga[64], &msg1->g_a, 64);

	if ( debug ) eprintf("+++ GbGa = %s\n", hexstring(gb_ga, 128));

	ecdsa_sign(gb_ga, 128, config->service_private_key, r, s, digest);
	reverse_bytes(&msg2->sign_gb_ga.x, r, 32);
	reverse_bytes(&msg2->sign_gb_ga.y, s, 32);

	if ( debug ) {
		eprintf("+++ sha256(GbGa) = %s\n", hexstring(digest, 32));
		eprintf("+++ r = %s\n", hexstring(r, 32));
		eprintf("+++ s = %s\n", hexstring(s, 32));
	}

	/* The "A" component is conveniently at the start of sgx_ra_msg2_t */

	cmac128(smk, (unsigned char *) msg2, 148, (unsigned char *) &msg2->mac);

	if ( verbose ) {
		edividerWithText("Msg2 Details");
		eprintf("msg2.g_b.gx      = %s\n",
			hexstring(&msg2->g_b.gx, sizeof(msg2->g_b.gx)));
		eprintf("msg2.g_b.gy      = %s\n",
			hexstring(&msg2->g_b.gy, sizeof(msg2->g_b.gy)));
		eprintf("msg2.spid        = %s\n",
			hexstring(&msg2->spid, sizeof(msg2->spid)));
		eprintf("msg2.quote_type  = %s\n",
			hexstring(&msg2->quote_type, sizeof(msg2->quote_type)));
		eprintf("msg2.kdf_id      = %s\n",
			hexstring(&msg2->kdf_id, sizeof(msg2->kdf_id)));
		eprintf("msg2.sign_ga_gb  = %s\n",
			hexstring(&msg2->sign_gb_ga, sizeof(msg2->sign_gb_ga)));
		eprintf("msg2.mac         = %s\n",
			hexstring(&msg2->mac, sizeof(msg2->mac)));
		eprintf("msg2.sig_rl_size = %s\n",
			hexstring(&msg2->sig_rl_size, sizeof(msg2->sig_rl_size)));
		edivider();
	}

	free(msg01);

	return 1;
}

int derive_kdk(EVP_PKEY *Gb, unsigned char kdk[16], sgx_ra_msg1_t *msg1,
	config_t *config)
{
	unsigned char *Gab_x;
	size_t slen;
	EVP_PKEY *Ga;
	unsigned char cmackey[16];

	memset(cmackey, 0, 16);

	/*
	 * Compute the shared secret using the peer's public key and a generated
	 * public/private key.
	 */

	Ga= key_from_sgx_ec256(&msg1->g_a);
	if ( Ga == NULL ) {
		crypto_perror("key_from_sgx_ec256");
		return 0;
	}

	/* The shared secret in a DH exchange is the x-coordinate of Gab */
	Gab_x= key_shared_secret(Gb, Ga, &slen);
	if ( Gab_x == NULL ) {
		crypto_perror("key_shared_secret");
		return 0;
	}

	/* We need it in little endian order, so reverse the bytes. */
	/* We'll do this in-place. */

	if ( debug ) eprintf("+++ shared secret= %s\n", hexstring(Gab_x, slen));

	reverse_bytes(Gab_x, Gab_x, slen);

	if ( debug ) eprintf("+++ reversed     = %s\n", hexstring(Gab_x, slen));

	/* Now hash that to get our KDK (Key Definition Key) */

	/*
	 * KDK = AES_CMAC(0x00000000000000000000000000000000, secret)
	 */

	cmac128(cmackey, Gab_x, slen, kdk);

	return 1;
}

int get_sigrl (IAS_Connection *ias, sgx_epid_group_id_t gid, char **sig_rl,
	uint32_t *sig_rl_size)
{
	IAS_Request *req= NULL;
	int oops;
	string sigrlstr;

	try {
		oops= 0;
		req= new IAS_Request(ias);
	}
	catch (int e) {
		eprintf("Exception while creating IAS request object\n");
		return 0;
	}


	if ( req->sigrl(*(uint32_t *) gid, sigrlstr) != IAS_OK ) {
		return 0;
	}

	*sig_rl= strdup(sigrlstr.c_str());
	if ( *sig_rl == NULL ) return 0;

	*sig_rl_size= (uint32_t ) sigrlstr.length();

	return 1;
}

int get_attestation_report(IAS_Connection *ias, const char *b64quote,
	sgx_ps_sec_prop_desc_t secprop) 
{
	IAS_Request *req = NULL;
	map<string,string> payload;
	vector<string> messages;
	ias_error_t status;
	string content;

	try {
		req= new IAS_Request(ias);
	}
	catch (int e) {
		eprintf("Exception while creating IAS request object\n");
		return 0;
	}

	payload.insert(make_pair("isvEnclaveQuote", b64quote));
	
	status= req->report(payload, content, messages);
	if ( status == IAS_OK ) {
		if ( verbose ) {
			edividerWithText("Report Body");
			eprintf("%s\n", content.c_str());
			edivider();
			if ( messages.size() ) {
				edividerWithText("IAS Advisories");
				for (vector<string>::const_iterator i = messages.begin();
					i != messages.end(); ++i ) {

					eprintf("%s\n", i->c_str());
				}
				edivider();
			}
		}


            JSON reportObj = JSON::Load(content);

            if ( verbose ) {
                edividerWithText("IAS Report - JSON - Required Fields");
                eprintf("id:\t\t\t%s\n", reportObj["id"].ToString().c_str());
                eprintf("timestamp:\t\t%s\n", reportObj["timestamp"].ToString().c_str());
                eprintf("isvEnclaveQuoteStatus:\t%s\n", reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
                eprintf("isvEnclaveQuoteBody:\t%s\n", reportObj["isvEnclaveQuoteBody"].ToString().c_str());

                edividerWithText("IAS Report - JSON - Optional Fields");

                eprintf("platformInfoBlob:\t%s\n", reportObj["iplatformInfoBlob"].ToString().c_str());
                eprintf("revocationReason:\t%s\n", reportObj["revocationReason"].ToString().c_str());
                eprintf("pseManifestStatus:\t%s\n", reportObj["pseManifestStatus"].ToString().c_str());
                eprintf("pseManifestHash:\t%s\n", reportObj["pseManifestHash"].ToString().c_str());
                eprintf("nonce:\t%s\n", reportObj["nonce"].ToString().c_str());
                eprintf("epidPseudonym:\t%s\n", reportObj["epidPseudonym"].ToString().c_str());
                edivider();
            }
       
          
            /* This samples attestion policy is either Trusted in the case of an "OK", 
             * or a NotTrusted for any other isvEnclaveQuoteStatus value */
  
            /* Simply check to see if status is OK, else enclave considered not trusted */
            memset (&msg4, 0, sizeof (Msg4));

	    if ( verbose ) edividerWithText("ISV Enclave Trust Status");

            if ( !(reportObj["isvEnclaveQuoteStatus"].ToString().compare("OK"))) {
                msg4.trustStatus = Trusted;
		if ( verbose ) eprintf("Enclave TRUSTED\n");
            }
            else {
                msg4.trustStatus = NotTrusted;
		if ( verbose ) eprintf("Enclave NOT TRUSTED\n");
            }

            if (!reportObj["iplatformInfoBlob"].IsNull()) {
                if ( verbose ) eprintf("A Platform Info Blob (PIB) was provided by the IAS\n");
                int ret = from_hexstring ((unsigned char *)(&msg4.platformInfoBlob), 
                                           reportObj["iplatformInfoBlob"].ToString().c_str(),
                                           reportObj["iplatformInfoBlob"].ToString().length());

            }
            else {
		if ( verbose ) eprintf("A Platform Info Blob (PIB) was NOT provided by the IAS\n");
            }
                 
	    if ( verbose ) edivider();

            edividerWithText("Copy/Paste Msg4 Below to Client"); 

	    send_msg(&msg4, sizeof( msg4));
	    fsend_msg(fplog, &msg4, sizeof( msg4));
            edivider();

            return 1;
	}

	eprintf("attestation query returned %lu: \n", status);

	switch(status) {
		case IAS_QUERY_FAILED:
			eprintf("Could not query IAS\n");
			break;
		case IAS_BADREQUEST:
			eprintf("Invalid payload\n");
			break;
		case IAS_UNAUTHORIZED:
			eprintf("Failed to authenticate or authorize request\n");
			break;
		case IAS_SERVER_ERR:
			eprintf("An internal error occurred on the IAS server\n");
			break;
		case IAS_UNAVAILABLE:
			eprintf("Service is currently not able to process the request. Try again later.\n");
			break;
		case IAS_INTERNAL_ERROR:
			eprintf("An internal error occurred while processing the IAS response\n");
			break;
		case IAS_BAD_CERTIFICATE:
			eprintf("The signing certificate could not be validated\n");
			break;
		case IAS_BAD_SIGNATURE:
			eprintf("The report signature could not be validated\n");
			break;
		default:
			if ( status >= 100 && status < 600 ) {
				eprintf("Unexpected HTTP response code\n");
			} else {
				eprintf("An unknown error occurred.\n");
			}
	}

	return 0;
}

#define NNL <<endl<<endl<<
#define NL <<endl<<

void usage () 
{
	cerr << "usage: sp [ options ] " NL
"Required:" NL
"  -A, --ias-signing-cafile=FILE" NL
"                           Specify the IAS Report Signing CA file." NL
"  -C, --ias-cert-file=FILE Specify the client certificate to use when" NL
"                             communicating with IAS." NL
"  -S, --spid-file=FILE     Set the SPID from a file containg a 32-byte." NL
"                             ASCII hex string." NL
"  -s, --spid=HEXSTRING     Set the SPID from a 32-byte ASCII hex string." NNL
"Optional:" NL
"  -K, --key-file=FILE      The private key file in PEM format (default: use" NL
"                             hardcoded key). The client must be given the " NL
"                             corresponding public key. Can't combine with" NL
"                             --key." NL
"  -d, --debug              Print debug information to stderr." NL
"  -e, --session-key=HEXSTRING" NL
"                           Use HEXSTRING for the server's private sesion key." NL
"                             Creates semi-deterministic sessions for testing" NL
"                             purposes." NL
"  -k, --key=HEXSTRING      The private key as a hex string. See --key-file" NL
"                             for notes. Can't combine with --key-file." NL
"  -l, --linkable           Request a linkable quote (default: unlinkable)." NL
"  -t, --ias-cert-type=TYPE The client certificate type. Can be PEM (default)" NL
"                             or P12." NL
"  -v, --verbose            Be verbose. Print message structure details and the" NL
"                             results of intermediate operations to stderr." 
<<endl;
	::exit(1);
}

