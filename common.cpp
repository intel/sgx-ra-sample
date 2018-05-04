/*

Copyright 2018 Intel Corporation

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

using namespace std;


#include <time.h>
#include <stdio.h>
#include <stdarg.h>
#include <cstdio>
#include <string.h>
#include <string>
#include "common.h"
#include "logfile.h"

#define LINE_TYPE '-'
#define LINE_SHORT_LEN 4
#define LINE_MAX_LEN   76
#define LINE_TRAILING_LEN(header) ((LINE_MAX_LEN - string(header).size()) - LINE_SHORT_LEN -2)

#define LINE_COMPLETE (string( LINE_MAX_LEN, LINE_TYPE).c_str())

#define LINE_HEADER(header) (string(string( LINE_SHORT_LEN, LINE_TYPE) + ' ' + string(header) + ' ' + string(LINE_TRAILING_LEN(header), LINE_TYPE)).c_str())

#define INDENT(level) (string( level, ' ' ))

#define WARNING_INDENT(level) (string(level, '*'))

#define TIMESTR_SIZE	64

void edividerWithText (const char *text)
{
	dividerWithText(stderr, text);
	if ( fplog != NULL ) dividerWithText(fplog, text);
}

void dividerWithText (FILE *fd, const char *text)
{
    fprintf(fd, "\n%s\n", LINE_HEADER(text));
}

void edivider ()
{
	divider(stderr);
	if ( fplog != NULL ) divider(fplog);
}

void divider (FILE * fd)
{
    fprintf(fd, "%s\n", LINE_COMPLETE);
}

int eprintf (const char *format, ...)
{
	va_list va;
	int rv;

	va_start(va, format);
	rv= vfprintf(stderr, format, va);
	va_end(va);

	if ( fplog != NULL ) {
		time_t ts;
		struct tm *timetm;
		char timestr[TIMESTR_SIZE];	

		/* Don't timestamp a single "\n" */
		if ( !(strlen(format) == 1 && format[0] == '\n') ) {
			time(&ts);
#ifndef _WIN32
			timetm= localtime(&ts);
#else
			localtime_s(&timetm, &ts);
#endif

			/* If you change this format, you _may_ need to change TIMESTR_SIZE */
			if ( strftime(timestr, TIMESTR_SIZE, "%b %e %Y %T", timetm) == 0 ) {
				/* oops */
				timestr[0]= 0;
			}
			fprintf(fplog, "%s ", timestr);
		}
		va_start(va, format);
		rv= vfprintf(fplog, format, va);
		va_end(va);
	}

	return rv;
}

int eputs (const char *s)
{
	if ( fplog != NULL ) fputs(s, fplog);
	return fputs(s, stderr);
}
