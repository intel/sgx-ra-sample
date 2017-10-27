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
