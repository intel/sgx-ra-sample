#include "iasrequest.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char *ias_request_send_sigrl(ias_request_t *request);
char *ias_request_send_report(ias_request_t *request);

static char base_uri_prefix[]= "/attestation/";

#define BUFFER_SIZE	4096

/*
 * For this code sample, the focus is on the message exchange and attestation
 * response, not the basics of writing a network client. But, at least provide
 * a generic framework to abstract the client agent from the connection details.
 */

/*============================================================================
 * IAS connection functions
 *============================================================================*/

/* Allocate a new connection structure */

ias_connection_t *ias_connection_new (int agent, const char *server, u_int16_t port)
{
	ias_connection_t *conn= (ias_connection_t *) malloc(sizeof(ias_connection_t));

	conn->agent= agent;
	conn->server_name= strdup(server);
	if ( conn->server_name == NULL ) {
		return NULL;
	}

	conn->server_port= port;
	conn->proxy_name= NULL;
	conn->proxy_port= 0;
	conn->proxy_mode= IAS_PROXY_NONE;

	return conn;
}

/* Free the connection structure and underlying allocated data. */

void ias_connection_free (ias_connection_t *conn)
{
	if ( conn->server_name != NULL ) free(conn->server_name);
	if ( conn->proxy_name != NULL ) free(conn->proxy_name);
	free(conn);
}

/* Set the proxy server and port. */

int ias_connection_set_proxy(ias_connection_t *conn, const char *proxy,
	u_int16_t port)
{
	conn->proxy_name= strdup(proxy);
	if ( conn->proxy_name == NULL ) {
		return 0;
	}
	conn->proxy_port= port;
}

/* Set the policy on when to use the proxy. */

int ias_connection_set_proxy_mode (ias_connection_t *conn, int mode)
{
	conn->proxy_mode= mode;
}

/*============================================================================
 * IAS request functions
 *============================================================================*/
 
/* Allocate a request structure, referencing the connection */

ias_request_t *ias_request_new(ias_connection_t *conn, ias_operation_t op,
	u_int16_t version)
{
	ias_request_t *request;

	/* Make sure we have a legal API version */

	if ( version < IAS_MIN_VERSION || version > IAS_MAX_VERSION ) {
		return NULL;
	}

	/* Make sure we have a legal operation */

	if ( op < IAS_API_SIGRL || op > IAS_API_RETRIEVE_REPORT ) {
		return 0;
	}

	if ( op == IAS_API_RETRIEVE_REPORT ) {
		return 0;
	}

	request= (ias_request_t *) malloc(sizeof(ias_request_t));

	request->conn= conn;
	request->operation= op;
	request->api_version= version;
	request->arg= NULL;
	request->data= NULL;	
}

/* Free the request and any underlying data that was malloc'd */

void ias_request_free(ias_request_t *request)
{
	if ( request->arg != NULL ) free(request->arg);
	if ( request->data != NULL ) free(request->data);
	free(request);
}

/* 
 * Set the request argument using strdup(). Free the old value if needed.
 * Not super-efficient, but this is a code sample and it works for our
 * purposes.
 */

int ias_request_set_arg (ias_request_t *request, const char *arg)
{
	char *newp= strdup(arg);
	if ( newp == NULL ) {
		return 0;
	}

	if ( request->arg != NULL ) free(request->arg);
	request->arg= newp;
}

/* 
 * Like the above.
 */

int ias_request_set_data (ias_request_t *request, const char *data)
{
	char *newp= strdup(data);
	if ( newp == NULL ) {
		return 0;
	}

	if ( request->data != NULL ) free(request->data);
	request->data= newp;

	return 1;
}

/*
 * Append data to the end. Again, this is not the height of efficiency, but
 * it works for our purposes.
 */

int ias_request_add_data (ias_request_t *request, const char *add_data)
{
	size_t sold, snew;
	char *newp;

	/* Handle the special case */

	if ( request->data == NULL ) return ias_request_set_data(request, add_data);

	sold= strlen(request->data);
	snew= strlen(add_data);

	newp= (char *) realloc(request->data, sold+snew+1);
	if ( newp == NULL ) {
		return 0;
	} 

	/* Do the copy and concatenation. Don't forget the NULL bytes. */
	strncpy(newp, request->data, sold+1);
	strncat(newp, add_data, snew+1);
	free(request->data);
	request->data= newp;

	return 1;
}

/* Request dispatcher */

char *ias_request_send(ias_request_t *request)
{
	if ( request->operation == IAS_API_SIGRL ) {
		ias_request_send_sigrl(request);
	} else if ( request->operation == IAS_API_REPORT ) {
		/* ias_request_send_report(request); */
	} else {
		return NULL;
	}
}

/* Prepare the SigRL request */

char *ias_request_send_sigrl(ias_request_t *request) 
{
	char *url;
	size_t wsz= BUFFER_SIZE-1;
	size_t sz= 0;
	ias_connection_t *conn= request->conn;
	char port[7];	/* Large enough for a 16-bit unsigned int */

	/*
	 * First use a fixed buffer that is probnably long enough. If snprintf
	 * is truncated, then realloc so it fits.
	 */

	if ( conn->server_port != 443 ) snprintf(port, 7, ":%u", conn->server_port);
	else port[0]= 0;

	while ( wsz >= sz ) {
		sz= wsz+1;
		url= (char *) malloc(sz);

		wsz= snprintf(url, sz, "https://%s%s%s/v%u/sigrl/%s",
			conn->server_name,
			port,
			base_uri_prefix,
			request->api_version,
			request->arg
		);
	}

	fprintf(stderr, "+++ %s\n", url);

	return NULL;
}

