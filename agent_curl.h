/*

Copyright 2018 Intel Corporation

This software and the related documents are Intel copyrighted materials,
and your use of them is governed by the express license under which they
were provided to you (License). Unless the License provides otherwise,
you may not use, modify, copy, publish, distribute, disclose or transmit
this software or the related documents without Intel's prior written
permission.

This software and the related documents are provided as is, with no
express or implied warranties, other than those that are expressly stated
in the License.

*/

#ifndef __AGENTCURL__H
#define __AGENTCURL__H

#include <curl/curl.h>
#include "httpparser/response.h"
#include "iasrequest.h"
#include "agent.h"
#include "settings.h"

using namespace std;

#include <string>

class AgentCurl : protected Agent
{
	CURL *curl;
	string sresponse;
	int flag_eoh;
	size_t header_pos, header_len;

public:
	static string name;

	AgentCurl(IAS_Connection *conn);
	~AgentCurl();
	int initialize();
	int request(string const &url, string const &postdata, 
		Response &response);
	size_t write_callback(char *ptr, size_t sz, size_t n);
	size_t header_callback(char *ptr, size_t sz, size_t n);

};

#endif
