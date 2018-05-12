#pragma once

#include "../httpparser/response.h"
#include "../iasrequest.h"
#include "../agent.h"
#include <Windows.h>
#include <winhttp.h>

using namespace std;

#include <string>

class AgentWin : protected Agent
{
	HINTERNET http;
	string sresponse;
	PCCERT_CONTEXT ctx;
	HCERTSTORE cstore;
	WINHTTP_STATUS_CALLBACK callback;

	// DWORD read_certificate(BYTE **buffer);
	int load_certificate();
	void perror(const char *prefix);

public:
	AgentWin(IAS_Connection *conn);
	~AgentWin();
	int initialize();
	int request(string const &url, string const &postdata, Response &response);
};

