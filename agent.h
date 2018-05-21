#ifndef __AGENT_H
#define __AGENT_H

#ifdef _WIN32
# define DEFAULT_CA_BUNDLE DEFAULT_CA_BUNDLE_WIN32
#else
# define DEFAULT_CA_BUNDLE DEFAULT_CA_BUNDLE_LINUX
#endif

#include "httpparser/response.h"
#include "iasrequest.h"

using namespace httpparser;

using namespace std;

#include <string>

class IAS_Connection;

class Agent {
protected:
	IAS_Connection *conn;

public:
	Agent(IAS_Connection *conn_in) { conn= conn_in; }
	~Agent() { };

	virtual int initialize() { return 1; };
	virtual int request(string const &url, string const &postdata,
		Response &response) { return 0; };
};


#endif

