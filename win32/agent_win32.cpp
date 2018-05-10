#include "agent_win32.h"
#include <Windows.h>
#include <winhttp.h>
#include <stdio.h>
#include "../httpparser/httpresponseparser.h"
#include "../httpparser/response.h"

#define USER_AGENT L"WinHTTP"

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
	DWORD certsz;

	// Proxy configuration
	//-----------------------------------------------------

	if (conn->proxy_mode() == IAS_PROXY_NONE) {
		access = WINHTTP_ACCESS_TYPE_NO_PROXY;
	}
	else if (conn->proxy_mode() == IAS_PROXY_FORCE) {
		size_t sz, wsz;
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
		return 0;
	}

	hcon = WinHttpConnect(http, urlcomp.lpszHostName, urlcomp.nPort, NULL);
	if (hcon == NULL) return 0;

	req = WinHttpOpenRequest(hcon, (postdata.length()) ? L"POST" : L"GET", urlcomp.lpszUrlPath, NULL,
		WINHTTP_NO_REFERER, accept_types, WINHTTP_FLAG_REFRESH | WINHTTP_FLAG_SECURE);
	if (req == NULL) goto error;

	if (WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (LPVOID)(postdata.length()) ? data : NULL,
		postdata.length(), postdata.length(), NULL) == FALSE) goto error;

	if (WinHttpReceiveResponse(req, NULL) == FALSE) goto error;

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
		BOOL result;
		
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
	if (hcon != NULL) CloseHandle(hcon);
	if (req != NULL) CloseHandle(req);

	return status;
}

int AgentWin::load_certificate()
{
	string name = conn->client_cert_file();
	wstring wname = wstring(name.begin(), name.end());

	cstore = CertOpenSystemStore(NULL, TEXT("MY"));
	if (cstore == NULL) return 0;

	/*
	certsz = read_certificate(&cert);
	if (certsz == 0 || cert == NULL) goto cleanup;

	ctx = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, cert, certsz);
	if (ctx == NULL) goto cleanup;
	*/

	ctx = CertFindCertificateInStore(cstore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR, (LPVOID) wname.c_str(), NULL);
	if (ctx == NULL) return 0;

	return 1;
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