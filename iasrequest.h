#ifndef __IASREQUEST_H
#define __IASREQUEST_H

#include <sys/types.h>

typedef enum ias_operation_enum {
	IAS_API_SIGRL,
	IAS_API_REPORT,
	IAS_API_RETRIEVE_REPORT
} ias_operation_t;

typedef struct ias_connection_struct {
	int agent;
	char *server_name;
	u_int16_t server_port;
	char *proxy_name;
	u_int16_t proxy_port;
	int proxy_mode;
} ias_connection_t;

/* Our arguments and data must be NULL-terminated strings */

typedef struct ias_request_struct {
	ias_connection_t *conn;
	ias_operation_t operation;
	u_int16_t api_version;
	char *arg;
	char *data;
} ias_request_t;

/* v1 API has been EOL'd */
#define IAS_MIN_VERSION	2
#define IAS_MAX_VERSION	3

#define IAS_PROXY_NONE	0
#define IAS_PROXY_AUTO	1
#define IAS_PROXY_FORCE	2

#define IAS_AGENT_DEFAULT	0
#define IAS_AGENT_MIN		0
#define IAS_AGENT_MAX		0

#define IAS_AGENT_WGET		0

#define IAS_SERVER_DEVELOPMENT	"test-as.sgx.trustedservices.intel.com"
#define IAS_SERVER_PRODUCTION	"as.sgx.trustedservices.intel.com"
#define IAS_PORT				443

#define DEFAULT_VERSION	2

#ifdef __cplusplus
extern "C" {
#endif

ias_connection_t *ias_connection_new(int agent, const char *server,
	u_int16_t port);
void ias_connection_free(ias_connection_t *conn);

int ias_connection_set_proxy(ias_connection_t *conn,
	const char *proxyserver, u_int16_t proxyport);
int ias_connection_set_proxy_mode (ias_connection_t *conn, int mode);

ias_request_t *ias_request_new(ias_connection_t *conn,
	ias_operation_t op, u_int16_t version);
void ias_request_free(ias_request_t *request);

int ias_request_set_arg (ias_request_t *request, const char *arg);
int ias_request_set_data (ias_request_t *request, const char *data);
int ias_request_add_data (ias_request_t *request, const char *add_data);

char *ias_request_send(ias_request_t *request);

#ifdef __cplusplus
;
#endif

#endif
