#ifndef __AGENT__WGET__H
#define __AGENT__WGET__H

#include "httpparser/response.h"
#include "iasrequest.h"
#include "agent.h"

using namespace httpparser;
using namespace std;

#include <string>

class Agent;
class IAS_Request;

class AgentWget : protected Agent
{
public:
	static string name;

	AgentWget(IAS_Connection *conn) : Agent(conn) {};
	int request(string const &url, string const &post, Response &response);
};

#endif
