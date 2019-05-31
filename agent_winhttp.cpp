/*

Copyright 2019 Intel Corporation

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

#include <sys/types.h>
#include "httpparser/response.h"
#include "httpparser/httpresponseparser.h"
#include "agent_winhttp.h"
#include "agent.h"
#include "common.h"
#include "iasrequest.h"

extern "C" {
	extern char debug;
};

using namespace std;
using namespace httpparser;

#include <string>

static size_t _header_callback(char *ptr, size_t sz, size_t n, void *data);
static size_t _write_callback(char *ptr, size_t sz, size_t n, void *data);
static size_t _read_callback(char *buffer, size_t size, size_t nitems, 
	void *instream);

string AgentWinHttp::name= "winhttp";

AgentWinHttp::AgentWinHttp(IAS_Connection *conn_in) : Agent(conn_in)
{
	sresponse= "";
}

AgentWinHttp::~AgentWinHttp()
{
}


int AgentWinHttp::request(string const &url, string const &postdata,
	Response &response)
{
	sresponse= "";
	HttpResponseParser parser;
	HttpResponseParser::ParseResult result;

	result= parser.parse(response, sresponse.substr(header_pos).c_str(),
		sresponse.c_str()+sresponse.length());

    return ( result == HttpResponseParser::ParsingCompleted );
}

size_t AgentWinHttp::header_callback(char *ptr, size_t sz, size_t n)
{
	size_t len= sz*n;
	string header;
	size_t idx;

	// Look for a blank header that occurs in the middle of the
	// headers: that's the separator between the proxy and server
	// headers. We want the last header block.

	header.assign(ptr, len);
	// Find where newline chars begin
	idx= header.find_first_of("\n\r");

	if ( flag_eoh ) {
		if ( idx != 0 )	{
			// We got a non-blank header line after receiving the
			// end of a header block, so we have started a new
			// header block.

			header_pos= header_len;
			flag_eoh= 0;
		} 
	} else {
		// If we have a blank line, we reached the end of a header
		// block.
		if ( idx == 0 ) flag_eoh= 1;
	}

	header_len+= len;

	return len;
}

size_t AgentWinHttp::write_callback(char *ptr, size_t sz, size_t n)
{
	size_t len= sz*n;
	sresponse.append(ptr, len);
	return len;
}

static size_t _header_callback(char *ptr, size_t sz, size_t n, void *data)
{
	AgentWinHttp *agent= (AgentWinHttp *) data;

	return agent->header_callback(ptr, sz, n);
}

static size_t _write_callback(char *ptr, size_t sz, size_t n, void *data)
{
	AgentWinHttp *agent= (AgentWinHttp *) data;

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

