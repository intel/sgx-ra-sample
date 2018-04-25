/*
 * getopt - POSIX like getopt for Windows console Application
 *
 * win-c - Windows Console Library
 * Copyright (c) 2015 Koji Takami
 * Released under the MIT license
 * https://github.com/takamin/win-c/blob/master/LICENSE
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Koji Takami
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/* Minor edits by John Mechalas <john.p.mechalas@intel.com> */

#pragma once

/*
 * Implementing getopt and getopt_long for Win32. Windows does not provide any
 * command-line argument parsing capability.
 */

#define no_argument			0
#define required_argument	1
#define optional_argument	2

#ifdef __cplusplus
extern "C" {
#endif
	/* POSIX definitions and structures */

	struct option {
		const char *name;
		int has_arg;
		int *flag;
		int val;
	};
	
	extern int opterr, optind, optopt;
	extern char *optarg;

	int getopt_long (int argc, char * const argv[], const char *optstring, const struct option *longopts, int *longindex);
	int getopt (int argc, char * const argv[], const char *optstring);

#ifdef __cplusplus
}
#endif
