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

#ifndef __MSGIO_H
#define __MSGIO_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <sys/types.h>
#include <sgx_urts.h>
#include <stdio.h>
#ifdef _WIN32
#include <WS2tcpip.h>
#endif
#include <string>
using namespace std;

#define STRUCT_INCLUDES_PSIZE	0
#define STRUCT_OMITS_PSIZE		1

/* A 1MB buffer should be sufficient for demo purposes */
#define MSGIO_BUFFER_SZ	1024*1024

#define DEFAULT_PORT	"7777"		// A C string for getaddrinfo()

#ifndef _WIN32
typedef int SOCKET;
#endif

class MsgIO {
	string wbuffer, rbuffer;
	char lbuffer[MSGIO_BUFFER_SZ];
	bool use_stdio;
	SOCKET ls, s;

public:
	MsgIO();
	MsgIO(const char *server, const char *port);
	~MsgIO();

	int server_loop();
	void disconnect();

	int read(void **dest, size_t *sz);

	void send_partial(void *buf, size_t f_size);
	void send(void *buf, size_t f_size);
};

#ifdef __cplusplus
extern "C" {
#endif

extern char debug;
extern char verbose;

int read_msg(void **dest, size_t *sz);

void send_msg_partial(void *buf, size_t f_size);
void send_msg(void *buf, size_t f_size);

void fsend_msg_partial(FILE *fp, void *buf, size_t f_size);
void fsend_msg(FILE *fp, void *buf, size_t f_size);

#ifdef __cplusplus
};
#endif


#endif
