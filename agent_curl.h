#ifndef __AGENTCURL__H
#define __AGENTCURL__H

#ifdef _WIN32
# define CA_BUNDLE "C:\\Program Files\\cURL\\bin\\curl-ca-bundle.crt"
#else
# define CA_BUNDLE "/etc/ssl/certs/ca-certificates.crt"
#endif

#include <curl/curl.h>
#include "httpparser/response.h"
#include "iasrequest.h"
#include "agent.h"

using namespace std;

#include <string>

class AgentCurl : protected Agent
{
	CURL *curl;
	string sresponse;
	int flag_eoh;
	size_t header_pos, header_len;

public:
	AgentCurl(IAS_Connection *conn);
	~AgentCurl();
	int initialize();
	int request(string const &url, string const &postdata, 
		Response &response);
	size_t write_callback(char *ptr, size_t sz, size_t n);
	size_t header_callback(char *ptr, size_t sz, size_t n);

};

#endif
