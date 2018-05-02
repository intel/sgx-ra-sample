#include <string.h>
#include <stdio.h>
#include "http.h"
#include "iasrequest.h"

using namespace std;

#include <string>

static string ias_servers[2]= {
    IAS_SERVER_DEVELOPMENT_HOST,
    IAS_SERVER_PRODUCTION_HOST
};

IAS_Connection::IAS_Connection(int server_idx, uint32_t flags)
{
	c_server= ias_servers[server_idx];
	c_cert_type= "PEM";
	c_flags= flags;
	c_pwlen= 0;
	c_key_passwd= NULL;
	c_xor= NULL;
	c_server_port= IAS_PORT;
	c_proxy_mode= IAS_PROXY_AUTO;
}

IAS_Connection::~IAS_Connection()
{
	if ( c_key_passwd != NULL ) delete[] c_key_passwd;
	if ( c_xor != NULL ) delete[] c_xor;
}

int IAS_Connection::proxy(const char *server, uint16_t port)
{
	int rv= 1;
	try {
		c_proxy_server= server;
	}
	catch (int e) {
		rv= 0;
	}
	c_proxy_port= port;

	return rv;
}

int IAS_Connection::client_cert(const char *file, const char *certtype)
{
	int rv= 1;
	try {
		c_cert_file= file;
		if ( certtype != NULL ) c_cert_type= certtype;
	}
	catch (int e) {
		rv= 0;
	}
	return rv;
}

int IAS_Connection::client_key(const char *file, const char *passwd)
{
	int rv= 1;
	size_t pwlen= strlen(passwd);
	size_t i;

	try {
		c_key_file= file;
	}
	catch (int e) {
		rv= 0;
	}
	if ( ! rv ) return 0;

	if ( passwd != NULL ) {
		try {
			c_key_passwd= new unsigned char[pwlen];
			c_xor= new unsigned char[pwlen];
		}
		catch (int e) { 
			rv= 0;
		}
		if ( ! rv ) {
			if ( c_key_passwd != NULL ) delete[] c_key_passwd;
			c_key_passwd= NULL;
			return 0;
		}
	}

	//rand_bytes(c_xor, pwlen);
	for (i= 0; i< pwlen; ++i) c_key_passwd[i]= (unsigned char) passwd[i]^c_xor[i];

	return 1;
}

size_t IAS_Connection::client_key_passwd(char **passwd)
{
	size_t rv= c_pwlen;
	size_t i;

	try {
		*passwd= new char[c_pwlen+1];
	}
	catch (int e) {
		rv= 0;
	}
	if ( ! rv ) return 0;

	for (i= 0; i< c_pwlen; ++i) *passwd[i]= (char) (c_key_passwd[i] ^ c_xor[i]);
	passwd[c_pwlen]= 0;

	return rv;
}

string IAS_Connection::base_url()
{
	string url= "https://" + c_server;

	if ( c_server_port != 443 ) {
		url+= ":";
		url+= to_string(c_server_port);
	}

	url+= "/attestation/v";

	return url;
}


IAS_Request::IAS_Request(IAS_Connection *conn, uint16_t version)
{
	r_conn= conn;
	r_api_version= version;
}

IAS_Request::~IAS_Request()
{
}

int IAS_Request::sigrl(uint32_t gid)
{
	char sgid[9];
	string url= r_conn->base_url();

	snprintf(sgid, 9, "%08x", gid);

	url+= to_string(r_api_version);
	url+= "/sigrl/";
	url+= sgid;

	fprintf(stderr, ">>>%s\n", url.c_str());
	http_request(this, url, "");
}
