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


#ifdef _WIN32
#pragma comment(lib, "crypt32.lib")
#else
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
#include "getopt.h"
#else
#include <getopt.h>
#include <unistd.h>
#endif
#include <sgx_key_exchange.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "common.h"
#include "hexutil.h"
#include "fileio.h"
#include "crypto.h"
#include "byteorder.h"
#include "msgio.h"
#include "protocol.h"
#include "base64.h"
#include "iasrequest.h"

using namespace std;

#include <map>
#include <string>

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
	char verbose;
	char debug;
	unsigned char kdk[16];
	char *cert_file;
	IAS_Connection *ias;
} config_t;

void usage();
int derive_kdk(EVP_PKEY *Gb, unsigned char kdk[16], sgx_ra_msg1_t *msg1,
	config_t *config);
int process_msg01 (sgx_ra_msg2_t *msg2, char **sigrl, config_t *config);
int process_msg3 (ra_msg4_t *msg2, config_t *config);
int get_sigrl (config_t *config, sgx_epid_group_id_t gid, char **sigrl,
	uint32_t *msg2);
int get_attestation_report(config_t *config, const char *b64quote,
	sgx_ps_sec_prop_desc_t sec_prop);

int main (int argc, char *argv[])
{
	u_int32_t i;
	char flag_spid= 0;
	char flag_pubkey= 0;
	char flag_cert= 0;
	char *sigrl= NULL;
	config_t config;
	sgx_ra_msg2_t msg2;
	ra_msg4_t msg4;
	uint32_t msg2_sz;
	int oops;

	memset(&config, 0, sizeof(config));

	static struct option long_opt[] =
	{
		{"cert-file",	required_argument,	0, 'C'},
		{"key-file",	required_argument,	0, 'K'},
		{"spid-file",	required_argument,	0, 'S'},
		{"debug",		required_argument,	0, 'd'},
		{"session-key",	required_argument,	0, 'e'},
		{"help",		no_argument, 		0, 'h'},
		{"key",			required_argument,	0, 'k'},
		{"linkable",	no_argument,		0, 'l'},
		{"spid",		required_argument,	0, 's'},
		{"verbose",		no_argument,		0, 'v'},
		{ 0, 0, 0, 0 }
	};

	/* Parse our options */

	while (1) {
		int c;
		int opt_index= 0;
		off_t fsz;

		c= getopt_long(argc, argv, "C:K:S:de:hk:lr:s:v", long_opt, &opt_index);
		if ( c == -1 ) break;

		switch(c) {
		case 0:
			break;
		case 'C':
			config.cert_file= strdup(optarg);
			if ( config.cert_file == NULL ) {
				perror("strdup");
				exit(1);
			}
			++flag_cert;

			break;
		case 'S':
			if ( ! from_hexstring_file((unsigned char *) &config.spid, optarg, 16)) {
				fprintf(stderr, "SPID must be 32-byte hex string\n");
				exit(1);
			}
			++flag_spid;

			break;
		case 'K':
			if ( ! key_load_file(&config.service_private_key, optarg, KEY_PRIVATE) ) {
				crypto_perror("key_load_file");
				fprintf(stderr, "%s: could not load EC private key\n", optarg);
				exit(1);
			}
			break;
		case 'd':
			config.debug= 1;
			break;
		case 'e':
			if ( ! key_load(&config.session_private_key, optarg, KEY_PRIVATE) ) {
				crypto_perror("key_load");
				fprintf(stderr, "%s: could not load session key\n", optarg);
				exit(1);
			}
			break;
		case 'k':
			if ( ! key_load(&config.service_private_key, optarg, KEY_PRIVATE) ) {
				crypto_perror("key_load");
				fprintf(stderr, "%s: could not load EC private key\n", optarg);
				exit(1);
			}
			break;
		case 'l':
			config.quote_type= SGX_LINKABLE_SIGNATURE;
			break;
		case 's':
			if ( strlen(optarg) < 32 ) {
				fprintf(stderr, "SPID must be 32-byte hex string\n");
				exit(1);
			}
			if ( ! from_hexstring((unsigned char *) &config.spid, (unsigned char *) optarg, 16) ) {
				fprintf(stderr, "SPID must be 32-byte hex string\n");
				exit(1);
			}
			++flag_spid;
			break;
		case 'v':
			config.verbose= 1;
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

	if ( config.service_private_key == NULL ) {
		if ( config.debug ) {
			fprintf(stderr, "Using default private key\n");
		}
		config.service_private_key= key_private_from_bytes(def_service_private_key);
		if ( config.service_private_key == NULL ) {
			crypto_perror("key_private_from_bytes");
			exit(1);
		}

	}

	if ( config.debug ) {
		fprintf(stderr, "+++ using private key:\n");
		PEM_write_PrivateKey(stderr, config.service_private_key, NULL,
			NULL, 0, 0, NULL);
	}

	if ( ! flag_spid ) {
		fprintf(stderr, "One of --spid or --spid-file is required.\n");
		exit(1);
	}

	if ( ! flag_cert ) {
		fprintf(stderr, "--cert-file is required\n");
		exit(1);
	}

	fprintf(stderr, "Using cert file %s\n", config.cert_file);

	/* Initialize out support libraries */

	crypto_init();

	/* Initialize our IAS request object */

	try {
		oops= 0;
		config.ias= new IAS_Connection(IAS_SERVER_DEVELOPMENT, 0);
		config.ias->client_cert(config.cert_file, "PEM");
	}
	catch (int e) {
		oops= 1;
		fprintf(stderr, "exception while creating IAS request object\n");
	}
	if ( oops ) exit(1);

	/* Read message 0 and 1, then generate message 2 */

	if ( ! process_msg01(&msg2, &sigrl, &config) ) {
		fprintf(stderr, "error processing msg1\n");
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

	dividerWithText("Copy/Paste Msg2 Below to Client");

	send_msg_partial((void *) &msg2, sizeof(sgx_ra_msg2_t));
	send_msg(msg2.sig_rl, msg2.sig_rl_size);

	divider();

	/* Read message 3 */

	process_msg3(&msg4, &config);

	crypto_destroy();

	return 0;
}

int process_msg3 (ra_msg4_t *msg4, config_t *config)
{
	sgx_ra_msg3_t *msg3;
	size_t blen= 0;
	size_t sz;
	int rv;
	uint32_t quote_sz;
	char *buffer= NULL;
	unsigned char smk[16], gb_ga[128];
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
		fprintf(stderr, "system error reading msg3\n");
		return 0;
	} else if ( rv == 0 ) {
		fprintf(stderr, "protocol error reading msg3\n");
		return 0;
	}
	if ( config->debug ) {
		fprintf(stderr, "+++ read %lu bytes\n", sz);
	}

	/*
	 * The quote size will be the total msg3 size - sizeof(sgx_ra_msg3_t)
	 * since msg3.quote is a flexible array member.
	 *
	 * Total message size is sz/2 since the income message is in base16.
	 */
	quote_sz= (sz/2)-sizeof(sgx_ra_msg3_t);

	/* Encode the report body as base64 */

	b64quote= base64_encode((char *) &msg3->quote, quote_sz);

	if ( config->verbose ) {
		sgx_quote_t *q= (sgx_quote_t *) msg3->quote;

		dividerWithText("Msg3 Details");
		fprintf(stderr,   "msg3.mac                 = ");
		print_hexstring(stderr, &msg3->mac, sizeof(msg3->mac));
		fprintf(stderr, "\nmsg3.g_a.gx              = ");
		print_hexstring(stderr, &msg3->g_a.gx, sizeof(msg3->g_a.gx));
		fprintf(stderr, "\nmsg3.g_a.gy              = ");
		print_hexstring(stderr, &msg3->g_a.gy, sizeof(msg3->g_a.gy));
		fprintf(stderr, "\nmsg3.ps_sec_prop         = ");
		print_hexstring(stderr, &msg3->ps_sec_prop, sizeof(msg3->ps_sec_prop));
		fprintf(stderr, "\nmsg3.quote.version       = ");
		print_hexstring(stderr, &q->version, sizeof(uint16_t));
		fprintf(stderr, "\nmsg3.quote.sign_type     = ");
		print_hexstring(stderr, &q->sign_type, sizeof(uint16_t));
		fprintf(stderr, "\nmsg3.quote.epd_group_id  = ");
		print_hexstring(stderr, &q->epid_group_id, sizeof(sgx_epid_group_id_t));
		fprintf(stderr, "\nmsg3.quote.qe_svn        = ");
		print_hexstring(stderr, &q->qe_svn, sizeof(sgx_isv_svn_t));
		fprintf(stderr, "\nmsg3.quote.pce_svn       = ");
		print_hexstring(stderr, &q->pce_svn, sizeof(sgx_isv_svn_t));
		fprintf(stderr, "\nmsg3.quote.xeid          = ");
		print_hexstring(stderr, &q->xeid, sizeof(uint32_t));
		fprintf(stderr, "\nmsg3.quote.basename      = ");
		print_hexstring(stderr, &q->basename, sizeof(sgx_basename_t));
		fprintf(stderr, "\nmsg3.quote.report_body   = ");
		print_hexstring(stderr, &q->report_body, sizeof(sgx_report_body_t));
		fprintf(stderr, "\nmsg3.quote.signature_len = ");
		print_hexstring(stderr, &q->signature_len, sizeof(uint32_t));
		fprintf(stderr, "\nmsg3.quote.signature     = ");
		print_hexstring(stderr, &q->signature, q->signature_len);
		fprintf(stderr, "\n");

		dividerWithText("Enclave Quote (base64)");
		fputs(b64quote, stderr);
		fprintf(stderr, "\n");
		divider();
	}

	get_attestation_report(config, b64quote, msg3->ps_sec_prop);

	free(b64quote);

	return 1;
}

/*
 * Read and process message 0 and message 1. These messages are sent by
 * the client concatenated together for efficiency (msg0||msg1).
 */

int process_msg01 (sgx_ra_msg2_t *msg2, char **sigrl, config_t *config)
{
	struct msg01_struct {
		uint32_t msg0_extended_epid_group_id;
		sgx_ra_msg1_t msg1;
	} *msg01;
	sgx_ra_msg1_t *msg1;
	size_t blen= 0;
	size_t sz;
	char *buffer= NULL;
	unsigned char smk[16], gb_ga[128];
	unsigned char digest[32], r[32], s[32];
	EVP_PKEY *Gb;
	mode_t fmode;
	int rv;

	memset(msg2, 0, sizeof(sgx_ra_msg2_t));

	/*
	 * Read our incoming message. We're using base16 encoding/hex strings
	 * so we should end up with sizeof(msg)*2 bytes.
	 */

	fprintf(stderr, "Waiting for msg0||msg1 on stdin\n");

	rv= read_msg((void **) &msg01, NULL);
	if ( rv == -1 ) {
		fprintf(stderr, "system error reading msg0||msg1\n");
		return 0;
	} else if ( rv == 0 ) {
		fprintf(stderr, "protocol error reading msg0||msg1\n");
		return 0;
	}

	if ( config->verbose ) {
		dividerWithText("Msg0 Details");
		fprintf(stderr, "msg0.extended_epid_group_id = ");
		fprintf(stderr, "%u\n", msg01->msg0_extended_epid_group_id);
		divider();
	}

	/* According to the Intel SGX Developer Reference
	 * "Currently, the only valid extended Intel(R) EPID group ID is zero. The
	 * server should verify this value is zero. If the Intel(R) EPID group ID 
	 * is not zero, the server aborts remote attestation"
	 */

	if ( msg01->msg0_extended_epid_group_id != 0 ) {
		fprintf(stderr, "msg0 Extended Epid Group ID is not zero.  Exiting.\n");
		free(msg01);
		return 0;
	}

	msg1= &msg01->msg1;	

	if ( config->verbose ) {
		dividerWithText("Msg1 Details");
		fprintf(stderr,   "msg1.g_a.gx = ");
		print_hexstring(stderr, &msg1->g_a.gx, sizeof(msg1->g_a.gx));
		fprintf(stderr, "\nmsg1.g_a.gy = ");
		print_hexstring(stderr, &msg1->g_a.gy, sizeof(msg1->g_a.gy));
		fprintf(stderr, "\nmsg1.gid    = ");
		print_hexstring(stderr, &msg1->gid, sizeof(msg1->gid));
		fprintf(stderr, "\n");
		divider();
	}

	if ( config->session_private_key == NULL ) {
		/* Generate our session key */

		if ( config->debug ) fprintf(stderr, "+++ generating session key Gb\n");
		Gb= key_generate();
		if ( Gb == NULL ) {
			fprintf(stderr, "Could not create a session key\n");
			free(msg01);
			return 0;
		}
	} else {
		/* Use a fixed session key for testing purposes */
		Gb= config->session_private_key;

		if ( config->debug ) fprintf(stderr, "+++ using stated session key Gb\n");
	}

	/*
	 * Derive the KDK from the key (Ga) in msg1 and our session key.
	 * An application would normally protect the KDK in memory to 
	 * prevent trivial inspection.
	 */

	fprintf(stderr, "+++ deriving KDK\n");
	if ( ! derive_kdk(Gb, config->kdk, msg1, config) ) {
		fprintf(stderr, "Could not derive the KDK\n");
		free(msg01);
		return 0;
	}

	if ( config->debug ) {
		fprintf(stderr, "+++ KDK = ");
		print_hexstring(stderr, config->kdk, 16);
		fprintf(stderr, "\n");
	}

	/*
 	 * Derive the SMK from the KDK 
	 * SMK = AES_CMAC(KDK, 0x01 || "SMK" || 0x00 || 0x80 || 0x00) 
	 */

	fprintf(stderr, "+++ deriving SMK\n");
	cmac128(config->kdk, (unsigned char *)("\x01SMK\x00\x80\x00"), 7, smk);

	if ( config->debug ) {
		fprintf(stderr, "+++ SMK = ");
		print_hexstring(stderr, smk, 16);
		fprintf(stderr, "\n");
	}

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

	if ( ! get_sigrl(config, msg1->gid, sigrl, &msg2->sig_rl_size) ) {
		fprintf(stderr, "could not retrieve the sigrl\n");
	}

	memcpy(gb_ga, &msg2->g_b, 64);
	memcpy(&gb_ga[64], &msg1->g_a, 64);

	if ( config->debug ) {
		fprintf(stderr, "+++ GbGa = ");
		print_hexstring(stderr, gb_ga, 128);
		fprintf(stderr, "\n");
	}

	ecdsa_sign(gb_ga, 128, config->service_private_key, r, s, digest);
	reverse_bytes(&msg2->sign_gb_ga.x, r, 32);
	reverse_bytes(&msg2->sign_gb_ga.y, s, 32);

	if ( config->debug ) {
		fprintf(stderr, "+++ sha256(GbGa) = ");
		print_hexstring(stderr, digest, 32);
		fprintf(stderr, "\n");
		fprintf(stderr, "+++ r = ");
		print_hexstring(stderr, r, 32);
		fprintf(stderr, "\n");
		fprintf(stderr, "+++ s = ");
		print_hexstring(stderr, s, 32);
		fprintf(stderr, "\n");
	}

	/* The "A" component is conveniently at the start of sgx_ra_msg2_t */

	cmac128(smk, (unsigned char *) msg2, 148, (unsigned char *) &msg2->mac);

	if ( config->verbose ) {
		dividerWithText("Msg2 Details");
		fprintf(stderr,   "msg2.g_b.gx      = ");
		print_hexstring(stderr, &msg2->g_b.gx, sizeof(msg2->g_b.gx));
		fprintf(stderr, "\nmsg2.g_b.gy      = ");
		print_hexstring(stderr, &msg2->g_b.gy, sizeof(msg2->g_b.gy));
		fprintf(stderr, "\nmsg2.spid        = ");
		print_hexstring(stderr, &msg2->spid, sizeof(msg2->spid));
		fprintf(stderr, "\nmsg2.quote_type  = ");
		print_hexstring(stderr, &msg2->quote_type, sizeof(msg2->quote_type));
		fprintf(stderr, "\nmsg2.kdf_id      = ");
		print_hexstring(stderr, &msg2->kdf_id, sizeof(msg2->kdf_id));
		fprintf(stderr, "\nmsg2.sign_ga_gb  = ");
		print_hexstring(stderr, &msg2->sign_gb_ga, sizeof(msg2->sign_gb_ga));
		fprintf(stderr, "\nmsg2.mac         = ");
		print_hexstring(stderr, &msg2->mac, sizeof(msg2->mac));
		fprintf(stderr, "\nmsg2.sig_rl_size = ");
		print_hexstring(stderr, &msg2->sig_rl_size, sizeof(msg2->sig_rl_size));
		fprintf(stderr, "\n");
		divider();
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

	if ( config->debug ) {
		fprintf(stderr, "+++ shared secret= ");
		print_hexstring(stderr, Gab_x, slen);
		fprintf(stderr, "\n");
	}

	reverse_bytes(Gab_x, Gab_x, slen);

	if ( config->debug ) {
		fprintf(stderr, "+++ reversed     = ");
		print_hexstring(stderr, Gab_x, slen);
		fprintf(stderr, "\n");
	}

	/* Now hash that to get our KDK (Key Definition Key) */

	/*
     * KDK = AES_CMAC(0x00000000000000000000000000000000, secret)
     */

	cmac128(cmackey, Gab_x, slen, kdk);

	return 1;
}

int get_sigrl (config_t *config, sgx_epid_group_id_t gid, char **sig_rl,
	uint32_t *sig_rl_size)
{
	IAS_Connection *conn= config->ias;
	IAS_Request *req;
	int oops;
	string sigrlstr;

	try {
		oops= 0;
		req= new IAS_Request(conn);
	}
	catch (int e) {
		fprintf(stderr, "Exception while creating IAS request object\n");
		oops= 1;
	}
	if ( oops ) return 0;

	if ( ! req->sigrl(*(uint32_t *) gid, sigrlstr) ) {
		return 0;
	}

	*sig_rl= strdup(sigrlstr.c_str());
	if ( *sig_rl == NULL ) return 0;

	*sig_rl_size= (uint32_t ) sigrlstr.length();

	return 1;
}

int get_attestation_report(config_t *config, const char *b64quote,
	sgx_ps_sec_prop_desc_t secprop) 
{
	IAS_Connection *conn= config->ias;
	IAS_Request *req;
	int oops;
	map<string,string> payload;

	try {
		oops= 0;
		req= new IAS_Request(conn);
	}
	catch (int e) {
		fprintf(stderr, "Exception while creating IAS request object\n");
		oops= 1;
	}
	if ( oops ) return 0;

	payload.insert(make_pair("isvEnclaveQuote", b64quote));
	
	req->report(payload);
}

void usage () 
{
	fprintf(stderr, "usage: sp [ options ]\n\n");
	fprintf(stderr, "Required:\n");
	fprintf(stderr, "  -C  --cert-file=FILE     Specify the certificate to use when contacting IAS\n");
	fprintf(stderr, "  -S, --spid-file=FILE     Set the SPID from a file containg a 32-byte\n");
	fprintf(stderr, "                              ASCII hex string\n");
	fprintf(stderr, "  -s, --spid=HEXSTRING     Set the SPID from a 32-byte ASCII hex string\n");
	fprintf(stderr, "\nOne of --spid OR --spid-file is required\n\n");
	fprintf(stderr, "\nOne of --msg2 OR --msg4 is required\n\n");
	fprintf(stderr, "Optional:\n");
	fprintf(stderr, "  -K, --key-file=FILE      The private key file in PEM format\n");
	fprintf(stderr, "  -d, --debug              Print debug information\n");
	fprintf(stderr, "  -e, --session-key=HEXSTRING\n");
	fprintf(stderr, "                           Use HEXSTRING for the server's private sesion key\n");
	fprintf(stderr, "  -k, --key=HEXSTRING      The private key as a hex string\n");
	fprintf(stderr, "  -l, --linkable           Request a linkable quote (default: unlinkable)\n");
	exit(1);
}

