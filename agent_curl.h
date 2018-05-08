#ifndef __AGENTCURL__H
#define __AGENTCURL__H

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

public:
	AgentCurl(IAS_Connection *conn);
	~AgentCurl();
	int initialize();
	int request(string const &url, string const &postdata, 
		Response &response);
	size_t write_callback(char *ptr, size_t sz, size_t n);

};

#endif
