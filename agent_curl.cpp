#include <sys/types.h>
#include <curl/curl.h>
#include "httpparser/response.h"
#include "httpparser/httpresponseparser.h"
#include "agent_curl.h"
#include "common.h"
#include "iasrequest.h"

extern char debug;

using namespace std;
using namespace httpparser;

#include <string>

static size_t _header_callback(char *ptr, size_t sz, size_t n, void *data);
static size_t _write_callback(char *ptr, size_t sz, size_t n, void *data);
static size_t _read_callback(char *buffer, size_t size, size_t nitems, 
	void *instream);

AgentCurl::AgentCurl (IAS_Connection *conn_in) : Agent(conn_in)
{
	curl= NULL;
	sresponse= "";
}

AgentCurl::~AgentCurl ()
{
	curl_easy_cleanup(curl);
}

int AgentCurl::initialize ()
{
	size_t pwlen;
	char *passwd= NULL;

	// Calls curl_global_init() if it hasn't been already. This is
	// not a thread-safe approach, but we are single-threaded.

	curl= curl_easy_init();
	if ( curl == NULL ) return 0;

	if ( debug ) {
		if ( curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L) != CURLE_OK )
			return 0;
	}

	// General client configuration options
	//------------------------------------------------------------

	// HTTPS only
	if ( curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS) !=
		CURLE_OK ) return 0;

	// Include the server response headers
	if ( curl_easy_setopt(curl, CURLOPT_HEADER, 1L) != CURLE_OK ) return 0;

	// If we use a proxy, tunnel through it so we don't get the proxy
	// response headers, as they interfere with parsing the destiantion 
	// response.

	if ( curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1L) !=
		CURLE_OK ) return 0;

#ifdef CURL_OPT_SUPPRESS_CONNECT_HEADERS
	// Suppress the proxy CONNECT headers.
	if ( curl_easy_setopt(curl, CURLOPT_SUPPRESS_CONNECT_HEADERS, 1L) !=
		CURLE_OK ) return 0;
#else
	// Sigh. Our version of libcurl is too old so we need to detect
	// proxy headers by hand.

	if ( curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, _header_callback)
		 != CURLE_OK) return 0;

	if ( curl_easy_setopt(curl, CURLOPT_HEADERDATA, this) != CURLE_OK)
		return 0;
#endif

	// Configure proxy
	//------------------------------------------------------------

	if ( conn->proxy_mode() == IAS_PROXY_NONE ) {
		// Setting this to an empty string will force the proxy off
		// regardless of any proxy environment vars.

		if ( curl_easy_setopt(curl, CURLOPT_PROXY, "") != CURLE_OK )
			return 0;

	} else if ( conn->proxy_mode() == IAS_PROXY_FORCE ) {
		string proxy_url= conn->proxy_url();

		// First, are we overriding the proxy environment vars?

		if ( proxy_url != "" ) {
			if ( curl_easy_setopt(curl, CURLOPT_PROXY, proxy_url.c_str())
				 != CURLE_OK )

				return 0;
		}

		// Now force the use of the proxy by overriding no_proxy
		// environment vars.

		if ( curl_easy_setopt(curl, CURLOPT_NOPROXY, "") != CURLE_OK )
			return 0;
	}

	// Configure SSL
	//------------------------------------------------------------

	// In case you need to specify a cert store location. These hardcoded
	// paths are the defaults.

/*
	if ( curl_easy_setopt(curl, CURLOPT_CAINFO,
		"/etc/ssl/certs/ca-certificates.crt") != CURLE_OK ) return 0;

	if ( curl_easy_setopt(curl, CURLOPT_CAPATH, "/etc/ssl/certs/") != CURLE_OK )
		 return 0;
*/

	if ( curl_easy_setopt(curl, CURLOPT_SSLCERT,
		conn->client_cert_file().c_str()) != CURLE_OK ) return 0;

	if ( curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE,
		conn->client_cert_type().c_str()) != CURLE_OK ) return 0;
	if ( curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM") != CURLE_OK ) return 0;

	if ( conn->client_key_file() != "" ) {
		if ( curl_easy_setopt(curl, CURLOPT_SSLKEY, 
			conn->client_key_file().c_str()) != CURLE_OK ) return 0;
	}

	// Set the password for the key (if any). Note that this method
	//  allocates passwd so need to free it later.

	if ( conn->client_key_passwd(&passwd, &pwlen) == 0 ) return 0;
	if ( pwlen ) {
		CURLcode ccode= curl_easy_setopt(curl, CURLOPT_KEYPASSWD, passwd);
		delete[] passwd;
		if ( ccode != CURLE_OK ) return 0;
	} else {
		curl_easy_setopt(curl, CURLOPT_KEYPASSWD, NULL);
	}

	// Set the write callback.

	if ( curl_easy_setopt(curl, CURLOPT_WRITEDATA, this) != CURLE_OK )
		return 0;

	if ( curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _write_callback) 
		!= CURLE_OK ) return 0;

	return 1;
}


int AgentCurl::request(string const &url, string const &postdata,
	Response &response)
{
	sresponse= "";
	HttpResponseParser parser;
	HttpResponseParser::ParseResult result;
	const char *bp;

	if ( postdata != "" ) {
		curl_slist *slist= NULL;

		bp= postdata.c_str();

		if ( (slist= curl_slist_append(slist, "Expect:")) == NULL )
			return 0;

		if ( curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist)
			 != CURLE_OK ) return 0;

		// Set our method to POST and send the length

		if ( curl_easy_setopt(curl, CURLOPT_POSTFIELDS, 
			postdata.c_str()) != CURLE_OK ) return 0;

/*
		if ( curl_easy_setopt(curl, CURLOPT_POST, 1L) != CURLE_OK )
			return 0;

		// Set the read/write callbacks. The read callbacks are for
		// sending data (curl reads from us) and the write 
		// callbacks are the server responses (written to us).

		if ( curl_easy_setopt(curl, CURLOPT_READFUNCTION, _read_callback) 
			!= CURLE_OK ) return 0;

		if ( curl_easy_setopt(curl, CURLOPT_READDATA, &bp) != CURLE_OK )
			return 0;
*/

	} 

	if ( curl_easy_setopt(curl, CURLOPT_URL, url.c_str()) != CURLE_OK )
		return 0;

	if ( curl_easy_perform(curl) != 0 ) {
		return 0;
	}

	result= parser.parse(response, sresponse.c_str(),
		sresponse.c_str()+sresponse.length());

    return ( result == HttpResponseParser::ParsingCompleted );
}

size_t AgentCurl::header_callback(char *ptr, size_t sz, size_t n)
{
	size_t len= sz*n;
	string header;

	header.assign(ptr, len);
	eprintf("HEADER [%s]\n", header.c_str());
	return len;
}

size_t AgentCurl::write_callback(char *ptr, size_t sz, size_t n)
{
	size_t len= sz*n;
	sresponse.append(ptr, len);
	return len;
}

static size_t _header_callback(char *ptr, size_t sz, size_t n, void *data)
{
	AgentCurl *agent= (AgentCurl *) data;

	return agent->header_callback(ptr, sz, n);
}

static size_t _write_callback(char *ptr, size_t sz, size_t n, void *data)
{
	AgentCurl *agent= (AgentCurl *) data;

	return agent->write_callback(ptr, sz, n);
}

static size_t _read_callback(char *buffer, size_t sz, size_t n, void *instream)
{
	// We need to write no more than sz*n bytes into "buffer", so we need
	// to keep track of where we are in our internal postdata buffer.
	char **bp= (char **) instream;
	size_t len= sz*n;
	size_t slen= strlen(*bp);

	if ( !slen ) return 0;

	len= ( slen < len ) ? slen : len;

	memcpy(buffer, *bp, len);
	for (slen= 0; slen< len; ++slen) fputc(buffer[slen], stderr);
	*bp+= len;

	return len;
}

