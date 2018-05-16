#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Winhttp.lib")

#include "agent_win32.h"
#include <wincrypt.h>
#include <Windows.h>
#include <winhttp.h>
#include <stdio.h>
#include "../httpparser/httpresponseparser.h"
#include "../httpparser/response.h"
#include "../common.h"

#include <string>
#include <locale>
#include <codecvt>

using namespace std;

// Quick and easy conversion from a unicode string to a standard string
using convert_type = codecvt_utf8<wchar_t>;

wstring_convert<convert_type, wchar_t> converter;

#define USER_AGENT L"WinHTTP"

void _win_http_callback(HINTERNET conn, DWORD_PTR ctx, DWORD status, LPVOID info, DWORD sz);
void _callback_secure_failure(DWORD status);

extern "C" {
	extern char debug;
	extern char verbose;
};

AgentWin::AgentWin(IAS_Connection *conn_in) : Agent(conn_in)
{
	http = NULL;
	ctx = NULL;
	cstore = NULL;
}

AgentWin::~AgentWin()
{
	if ( ctx != NULL ) CertFreeCertificateContext(ctx);
	if ( http != NULL) WinHttpCloseHandle(http);
}

int AgentWin::initialize()
{
	DWORD access = WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY;
	LPCWSTR proxy_server = NULL;
	LPCWSTR proxy_bypass = NULL;
	int status = 0;
	BYTE *cert= NULL;

	// Proxy configuration
	//-----------------------------------------------------

	if (conn->proxy_mode() == IAS_PROXY_NONE) {
		access = WINHTTP_ACCESS_TYPE_NO_PROXY;
	}
	else if (conn->proxy_mode() == IAS_PROXY_FORCE) {
		string proxy = conn->proxy_url();
		wstring wproxy = wstring(proxy.begin(), proxy.end());

		access= WINHTTP_ACCESS_TYPE_NAMED_PROXY;
		proxy_bypass= WINHTTP_NO_PROXY_BYPASS;
		proxy_server = wproxy.c_str();
	}

	http= WinHttpOpen(USER_AGENT, access, proxy_server, proxy_bypass, 0);
	if (http == NULL) return 0;

	// Set the client certificate
	//-----------------------------------------------------

	if (!load_certificate()) return 0;

	// Debugging info
	//-----------------------------------------------------

	if (debug) {
		callback = WinHttpSetStatusCallback(http,
			(WINHTTP_STATUS_CALLBACK)_win_http_callback,
			WINHTTP_CALLBACK_FLAG_ALL_NOTIFICATIONS,
			NULL);
	}


	// TEMPORARY
	{
		unsigned long val = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
		if (WinHttpSetOption(http, WINHTTP_OPTION_SECURE_PROTOCOLS, (LPVOID)&val, sizeof(unsigned long)) == FALSE)
		{
			this->perror("WinHttpSetOption: WINHTTP_OPTION_SECURE_PROTOCOLS");
			return 0;
		}

	}

	return 1;
}

int AgentWin::request(string const &url, string const &postdata,
	Response &response)
{
	HINTERNET hcon = NULL;
	HINTERNET req = NULL;
	int status = 0;
	void *data = (void *) postdata.c_str();
	wstring wurl = wstring(url.begin(), url.end());
	URL_COMPONENTS urlcomp;
	DWORD hdrsz= 0;
	DWORD datasz = 0;
	BYTE *hdr = NULL;
	LPCWSTR accept_types[] = {
		L"application/json",
		L"text/*",
		0
	};
	HttpResponseParser parser;
	HttpResponseParser::ParseResult result;
	wstring whostname, wuri;

	// How to crack a URL
	// https://msdn.microsoft.com/EN-US/library/windows/desktop/aa384092(v=vs.85).aspx

	ZeroMemory(&urlcomp, sizeof(urlcomp));
	urlcomp.dwStructSize = sizeof(urlcomp);

	urlcomp.dwSchemeLength = (DWORD)-1;
	urlcomp.dwHostNameLength = (DWORD)-1;
	urlcomp.dwUrlPathLength = (DWORD)-1;
	urlcomp.dwExtraInfoLength = (DWORD)-1;

	if (WinHttpCrackUrl(wurl.c_str(), (DWORD)wurl.length(), 0, &urlcomp) == FALSE)
	{
		this->perror("WinHttpCrackUrl");
		return 0;
	}

	whostname = wstring(urlcomp.lpszHostName, urlcomp.dwHostNameLength);
	wuri = wstring(urlcomp.lpszUrlPath, urlcomp.dwUrlPathLength);

	hcon = WinHttpConnect(http, whostname.c_str(), urlcomp.nPort, NULL);
	if (hcon == NULL) {
		this->perror("WinHttpConnect");
		return 0;
	}

	req = WinHttpOpenRequest(hcon, (postdata.length()) ? L"POST" : L"GET", wuri.c_str(), NULL,
		WINHTTP_NO_REFERER, accept_types, WINHTTP_FLAG_REFRESH | WINHTTP_FLAG_SECURE);
	if (req == NULL) {
		this->perror("WinHttpOpenRequest");
		goto error;
	}


	// TEMPORARY
	{
		unsigned long val = SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_UNKNOWN_CA;
		if (WinHttpSetOption(req, WINHTTP_OPTION_SECURITY_FLAGS, (LPVOID)&val, sizeof(unsigned long)) == FALSE)
		{
			this->perror("WinHttpSetOption: WINHTTP_OPTION_SECURITY_FLAGS ");
			goto error;
		}
	}

	// Set the client certificate context

	if (WinHttpSetOption(req, WINHTTP_OPTION_CLIENT_CERT_CONTEXT, (LPVOID) ctx, sizeof(CERT_CONTEXT)) == FALSE)
	{
		this->perror("WinHttpSetOption: WINHTTP_OPTION_CLIENT_CERT_CONTEXT");
		goto error;
	}

	if (WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (LPVOID)(postdata.length()) ? data : NULL,
		(DWORD)postdata.length(), (DWORD)postdata.length(), NULL) == FALSE) {
		this->perror("WinHttpSendRequest");
		goto error;
	}

	if (WinHttpReceiveResponse(req, NULL) == FALSE) {
		this->perror("WinHttpReceiveResponse");
		goto error;
	}

	// Get the headers

	WinHttpQueryHeaders(req, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, WINHTTP_NO_OUTPUT_BUFFER,
		&hdrsz, WINHTTP_NO_HEADER_INDEX);

	try {
		hdr = new BYTE[hdrsz];
	}
	catch (...) {
		goto error;
	}

	if (WinHttpQueryHeaders(req, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, WINHTTP_NO_OUTPUT_BUFFER,
		&hdrsz, WINHTTP_NO_HEADER_INDEX) == FALSE) goto error;

	// TO DO: Detect and remove proxy headers

	sresponse.assign((const char *) hdr, hdrsz);

	// Read the response data 

	if (WinHttpQueryDataAvailable(req, &datasz) == FALSE) goto error;
	while (datasz > 0) {
		BYTE *data;
		DWORD bread = 0;
		
		try {
			data = new BYTE[datasz];
		}
		catch (...) {
			goto error;
		}

		if (WinHttpReadData(req, data, datasz, &bread) == TRUE) {
			sresponse.append((const char *)data, bread);
		}
		else {
			delete[] data;
			goto error;
		}
		// Yeah, it's not very efficient but it's not likely we'll loop more than once, anyway
		delete[] data; 

		if (WinHttpQueryDataAvailable(req, &datasz) == FALSE) goto error;
	}

	result = parser.parse(response, sresponse.c_str(), sresponse.c_str() + sresponse.length());

	status= (result == HttpResponseParser::ParsingCompleted);

error:
	if (hdr != NULL) delete[] hdr;
	if (hcon != NULL) WinHttpCloseHandle(hcon);
	if (req != NULL) WinHttpCloseHandle(req);

	return status;
}

void AgentWin::perror(const char *prefix)
{
	LPSTR buffer= NULL;
	size_t sz;
	DWORD err = GetLastError();

	sz = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_HMODULE,
		reinterpret_cast<LPCVOID>(GetModuleHandle(TEXT("winhttp.dll"))),
		err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR) &buffer, 0, NULL);
	if ( sz > 0 )
	{ 
		eprintf("%s: %s\n", prefix, buffer);
	}
	else {
		eprintf("%s: Error %ld (0x%08x)\n", prefix, err, err);
		eprintf("FormatMessage: error %ld\n", GetLastError());
	}
}

int AgentWin::load_certificate()
{
	string name = conn->client_cert_file();
	wstring wname = wstring(name.begin(), name.end());

	// Assumes that the certificate is located in your personal certificate store.
	cstore = CertOpenSystemStore(NULL, TEXT("MY"));
	if (cstore == NULL) return 0;

	ctx = CertFindCertificateInStore(cstore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR, (LPVOID) wname.c_str(), NULL);
	if (ctx == NULL) return 0;

	return 1;
}

// Callback to get status info of the connection. For debugging purposes

void _win_http_callback(HINTERNET conn, DWORD_PTR ctx, DWORD status, LPVOID info, DWORD sz)
{
	string msg;

	eprintf("+++ Status 0x%08x: ", status);

	// Print the status info
	switch (status) {
	case WINHTTP_CALLBACK_STATUS_CLOSING_CONNECTION:
		eprintf("Closing connection to the server\n");
		break;
	case WINHTTP_CALLBACK_STATUS_CONNECTED_TO_SERVER:
		msg = converter.to_bytes(wstring((wchar_t *) info, sz));
		eprintf("Successfully connected to the server %s\n", msg.c_str());
		break;
	case WINHTTP_CALLBACK_STATUS_CONNECTING_TO_SERVER:
		msg = converter.to_bytes(wstring((wchar_t *)info, sz));
		eprintf("Connecting to the server %s\n", msg.c_str());
		break;
	case WINHTTP_CALLBACK_STATUS_CONNECTION_CLOSED:
		eprintf("Connection closed\n");
		break;
	case WINHTTP_CALLBACK_STATUS_DATA_AVAILABLE:
		eprintf("%lu bytes available for reading", *((DWORD *)info));
		break;
	case WINHTTP_CALLBACK_STATUS_HANDLE_CREATED:
		eprintf("HINTERNET handle created at 0x%08x\n", info);
		break;
	case WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING:
		eprintf("Handle at 0x%08x terminated\n", info);
		break;
	case WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE:
		eprintf("Response header received\n");
		break;
	case WINHTTP_CALLBACK_STATUS_INTERMEDIATE_RESPONSE:
		eprintf("Received intermediate statrus code from server: %lu\n", *((DWORD *)info));
		break;
	case WINHTTP_CALLBACK_STATUS_NAME_RESOLVED:
		msg = converter.to_bytes(wstring((wchar_t *)info, sz));
		eprintf("Resolved IP address to %s\n", msg.c_str());
		break;
	case WINHTTP_CALLBACK_STATUS_READ_COMPLETE:
		// The full meaning of this messages depends on who called it (WinHttpReadData vs WinHttpWebSocketReceive)
		eprintf("Reas completed\n");
		break;
	case WINHTTP_CALLBACK_STATUS_RECEIVING_RESPONSE:
		eprintf("Waiting for server to respond\n");
		break;
	case WINHTTP_CALLBACK_STATUS_REDIRECT:
		msg = converter.to_bytes(wstring((wchar_t *)info, sz));
		eprintf("Redirecting to: %s\n", msg.c_str());
		break;
	case WINHTTP_CALLBACK_STATUS_REQUEST_ERROR:
		eprintf("Error while sending HTTP request\n");
		break;
	case WINHTTP_CALLBACK_STATUS_REQUEST_SENT:
		eprintf("Sent %lu bytes to server\n", *((DWORD *)info));
		break;
	case WINHTTP_CALLBACK_STATUS_RESOLVING_NAME:
		msg = converter.to_bytes(wstring((wchar_t *)info, sz));
		eprintf("Resolving IP address for %s\n", msg.c_str());
		break;
	case WINHTTP_CALLBACK_STATUS_RESPONSE_RECEIVED:
		eprintf("Received %lu bytes from server\n", *((DWORD *)info));
		break;
	case WINHTTP_CALLBACK_STATUS_SECURE_FAILURE:
		// This message requires further interpretation
		_callback_secure_failure(*((DWORD *) info));
		break;
	case WINHTTP_CALLBACK_STATUS_SENDING_REQUEST:
		eprintf("Sending the information request to the server\n");
		break;
	case WINHTTP_CALLBACK_STATUS_WRITE_COMPLETE:
		// The full meaning of this messages depends on who called it (WinHttpSendData vs WinHttpWebSocketReceive)
		eprintf("Data sent to server\n");
		break;
	case WINHTTP_CALLBACK_STATUS_GETPROXYFORURL_COMPLETE:
		eprintf("Found proxy server for the target URL\n");
		break;
	case WINHTTP_CALLBACK_STATUS_CLOSE_COMPLETE:
		eprintf("Socket closed\n");
		break;
	case WINHTTP_CALLBACK_STATUS_SHUTDOWN_COMPLETE:
		eprintf("Socket shutdown\n");
		break;
	}

}

void _callback_secure_failure(DWORD info)
{
	eprintf("Errors in SSL/TLS connection:\n");
	if (info & WINHTTP_CALLBACK_STATUS_FLAG_CERT_REV_FAILED)
		eprintf(">>> Certification revocation checking has been enabled, but the revocation check failed to verify whether a certificate has been revoked\n");
	if (info & WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CERT)
		eprintf(">>> SSL certificate is invalid\n");
	if (info & WINHTTP_CALLBACK_STATUS_FLAG_CERT_REVOKED)
		eprintf(">>> SSL certificate was revoked\n");
	if (info & WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CA)
		eprintf(">>> The Certificate Authority that generated the server's certificate is not recognized\n");
	if (info & WINHTTP_CALLBACK_STATUS_FLAG_CERT_CN_INVALID)
		eprintf(">>> SSL certificate Common Name is incorrect\n");
	if (info & WINHTTP_CALLBACK_STATUS_FLAG_CERT_DATE_INVALID)
		eprintf(">>> Server's certificate date is bad, or the certificate has expired\n");
	if (info & WINHTTP_CALLBACK_STATUS_FLAG_SECURITY_CHANNEL_ERROR)
		eprintf(">>> Error loading SSL libraries\n");
}

/*

DWORD AgentWin::read_certificate(BYTE **buffer)
{
	HANDLE hfile;
	DWORD bread = 0;
	size_t sz;
	DWORD pathsz, filesz;
	string path;
	wchar_t *wpath;

	path = conn->client_cert_file();
	pathsz = (DWORD) path.length() + 1;

	try {
		wpath = new wchar_t[pathsz];
	}
	catch (...)
	{
		return 0;
	}
	
	if (mbstowcs_s(&sz, (wchar_t *)wpath, pathsz, path.c_str(), pathsz) != 0) {
	}

	hfile = (HANDLE) CreateFile(wpath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hfile == NULL) return NULL;

	// We aren't that large
	filesz = GetFileSize((HANDLE)hfile, NULL);
	if (filesz == INVALID_FILE_SIZE) return NULL;
	
	*buffer = new BYTE[filesz];

	if (ReadFile(hfile, *buffer, filesz, &bread, NULL) == FALSE) {
		CloseHandle(hfile);
		delete[] *buffer;
		*buffer= NULL;
		return 0;
	}

	return bread;
}

*/