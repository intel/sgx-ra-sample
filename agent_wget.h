#ifndef __HTTP_H
#define __HTTP_H

#include "httpparser/response.h"
#include "iasrequest.h"

using namespace httpparser;

#ifdef __cplusplus
extern "C" {
#endif

using namespace std;

#include <string>

int http_request(IAS_Request *req, Response &response, string url,
	string const &post);

#ifdef __cplusplus
};
#endif

#endif
