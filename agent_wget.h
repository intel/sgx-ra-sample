#ifndef __HTTP_H
#define __HTTP_H

#include "iasrequest.h"

#ifdef __cplusplus
extern "C" {
#endif

using namespace std;

#include <string>

int http_request(IAS_Request *req, string url, string const &post);

#ifdef __cplusplus
};
#endif

#endif
