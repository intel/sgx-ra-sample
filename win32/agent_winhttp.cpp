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
#include "../httpparser/response.h"
#include "../httpparser/httpresponseparser.h"
#include "agent_winhttp.h"
#include "../agent.h"
#include "../common.h"
#include "../iasrequest.h"
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp")
extern "C" {
	extern char debug;
};

using namespace std;
using namespace httpparser;

#include <string>

std::string AgentWinHttp::name= "winhttp";

//Simple std:: string(ASCII) to wstring
std::wstring  strToWStr(const std::string& str) {
	return std::wstring(str.begin(), str.end());
}

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
	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	char* pDataBuffer;
	BOOL  bResults = FALSE;
	HINTERNET  hSession = NULL,
		hConnect = NULL,
		hRequest = NULL;
	std::wstring wUrlAdr = strToWStr(url.c_str());
	size_t pos_sgx_str = wUrlAdr.find(L"/sgx");
	size_t pos_api_str = wUrlAdr.find(L"api");
	std::wstring wMainUrlPart = wUrlAdr.substr(pos_api_str, pos_sgx_str- pos_api_str);
	std::wstring wServUrlPart = wUrlAdr.substr(pos_sgx_str);
	WCHAR* pProxyAddress = NULL;
	// Use WinHttpOpen to obtain a session handle.

	if (conn->proxy_mode() != IAS_PROXY_AUTO) { //No proxy and Force proxy
		hSession = WinHttpOpen(L"ISV Auth Server",
			WINHTTP_ACCESS_TYPE_NO_PROXY,
			WINHTTP_NO_PROXY_NAME,
			WINHTTP_NO_PROXY_BYPASS, 0);
	}
	else{//Using Auto Proxy
		hSession = WinHttpOpen(L"ISV Auth Server",
			WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
			WINHTTP_NO_PROXY_NAME,
			WINHTTP_NO_PROXY_BYPASS, 0);
	}

	//setting force proxy
	if (hSession && conn->proxy_mode() == IAS_PROXY_FORCE &&
			conn->proxy_url() !="") {
		WINHTTP_PROXY_INFO proxyInfo;
		std::wstring wProxyWStr;
		proxyInfo.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
		wProxyWStr = strToWStr(conn->proxy_url());
		//lpszProxy requires LPWSTR not a constant
		//+1 for null termination
		pProxyAddress = new WCHAR[wProxyWStr.size() + 1];
		//copy address to buffer
		std::wstring::iterator it = wProxyWStr.begin();
		for (int i = 0;
			it != wProxyWStr.end(); ++it, ++i) {
			pProxyAddress[i] = *(it);
		}
		//copy NULL temrination
		pProxyAddress[wProxyWStr.size()] = wProxyWStr[wProxyWStr.size()];

		proxyInfo.lpszProxy = pProxyAddress;
		proxyInfo.lpszProxyBypass = NULL;
		if( !WinHttpSetOption(hSession, WINHTTP_OPTION_PROXY, &proxyInfo,
				sizeof(proxyInfo)))
			printf("Error establishing proxy conenction \n");
	}

	// Specify an HTTP server.
	if (hSession)	//using simple std::string to std::wstring function, may not work properly for not ASCII
		hConnect = WinHttpConnect(hSession, wMainUrlPart.c_str(),
			INTERNET_DEFAULT_PORT, 0);

	// Create an HTTP request handle.
	if (hConnect) {
		std::wstring strPostget;
		strPostget = (postdata == "") ? L"GET" : L"POST";
		hRequest = WinHttpOpenRequest(hConnect, strPostget.c_str(), wServUrlPart.c_str(),
			NULL, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES,
			WINHTTP_FLAG_SECURE);
	}
	
	if (hRequest) {
		std::wstring subscriptionKeyHeader = L"Ocp-Apim-Subscription-Key: ";
		subscriptionKeyHeader.append(strToWStr(conn->getSubscriptionKey()));

		if (postdata != "") {

			// Set our POST specific headers
			//Winhttp requires cr lf before additional headers
			subscriptionKeyHeader.append(L"\r\nContent-Type: application/json");
			subscriptionKeyHeader.append(L"\r\nExpect:");
		}

		bResults = WinHttpAddRequestHeaders(hRequest, subscriptionKeyHeader.c_str(), -1L,
			WINHTTP_ADDREQ_FLAG_ADD_IF_NEW);
	}
	// Send a request.
	if (bResults) {
		if (postdata != "") {
			//POST
			DWORD dataLenght = (DWORD)postdata.size();
			bResults = WinHttpSendRequest(hRequest,
				WINHTTP_NO_ADDITIONAL_HEADERS, 0,
				(LPVOID)postdata.c_str(), dataLenght,
				dataLenght, 0);
			
		}
		else { 
			//GET
			bResults = WinHttpSendRequest(hRequest,
				WINHTTP_NO_ADDITIONAL_HEADERS, 0,
				WINHTTP_NO_REQUEST_DATA, 0,
				0, 0);
		}
	}

	// End the request.
	if (bResults)
		bResults = WinHttpReceiveResponse(hRequest, NULL);

	WCHAR* pHeaderBuffer = NULL;
	if (bResults)
	{
		WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
			WINHTTP_HEADER_NAME_BY_INDEX, NULL,
			&dwSize, WINHTTP_NO_HEADER_INDEX);

		// Allocate memory for the buffer.
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		{
			pHeaderBuffer = new WCHAR[dwSize / sizeof(WCHAR)];

			// Now, use WinHttpQueryHeaders to retrieve the header.
			bResults = WinHttpQueryHeaders(hRequest,
				WINHTTP_QUERY_RAW_HEADERS_CRLF,
				WINHTTP_HEADER_NAME_BY_INDEX,
				pHeaderBuffer, &dwSize,
				WINHTTP_NO_HEADER_INDEX);
			wstring resp(pHeaderBuffer);
			sresponse.append(resp.begin(), resp.end());
		}
	}
	if (bResults)
		printf("Header contents: \n%S", pHeaderBuffer);

	// Keep checking for data until there is nothing left.
	if (bResults)
	{
		do
		{
			// Check for available data.
			dwSize = 0;
			if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
				printf("Error %u in WinHttpQueryDataAvailable.\n",
					GetLastError());

			// Allocate space for the buffer.
			pDataBuffer = new char[dwSize + 1];
			if (!pDataBuffer)
			{
				printf("Out of memory\n");
				dwSize = 0;
			}
			else
			{
				// Read the data.
				ZeroMemory(pDataBuffer, dwSize + 1);
				if (!WinHttpReadData(hRequest, (LPVOID)pDataBuffer,
					dwSize, &dwDownloaded))
					printf("Error %u in WinHttpReadData.\n", GetLastError());
				else
					printf("%s", pDataBuffer);
				string bodyStr(pDataBuffer);
				sresponse.append(bodyStr.begin(), bodyStr.end());
				// Free the memory allocated to the buffer.
				delete[] pDataBuffer;
			}
		} while (dwSize > 0);
	}
	// Report any errors.
	if (!bResults)
		printf("Error %d has occurred.\n", GetLastError());

	// Close any open handles.
	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);

	HttpResponseParser parser;
	HttpResponseParser::ParseResult result;

	result = parser.parse(response, sresponse.c_str(),
		sresponse.c_str() + sresponse.length());

	return  (result == HttpResponseParser::ParsingCompleted);
}
