#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "http.h"
#include "common.h"
#include "iasrequest.h"

using namespace std;

#include <string>
#include <vector>
#include <map>

static vector<string> wget_args;

#define CHUNK_SZ 8192
#define WGET_NO_ERROR		0
#define WGET_SERVER_ERROR	8

int http_request (IAS_Request *req, string url, string const &post)
{
	
	IAS_Connection *conn= req->conn();
	int pipefd[2];
	pid_t pid;
	string arg;
	string sresponse;
	int status;
	char buffer[CHUNK_SZ];
	size_t bread;
	int repeat;
	int rv= 1;
	char tmpfile[]= "/tmp/wgetpostXXXXXX";
	int postdata= 0;

	if ( post.length() > 0 ) {
		int fd= mkstemp(tmpfile);
		size_t bwritten, rem;
		const char *bp= post.c_str();

		fprintf(stderr, "+++ POST data written to %s\n", tmpfile);

		postdata= 1;

		if ( fd == -1 ) {
			perror("mkstemp");
			return 0;
		}
		
		rem= post.length();
		while ( rem ) {
retry_write:
			bwritten= write(fd, bp, rem);
			if ( bwritten == -1 ) {
				if (errno == EINTR) goto retry_write;
				else {
					perror("write");
					close(fd);
					unlink(tmpfile);
					return 0;
				}
			}
			rem-= bwritten;
			bp+= bwritten;
		}

		close(fd);
	}

	// Only need to initialize these once
	if ( wget_args.size() == 0 ) {
		wget_args.push_back("wget");

		// Output options

		wget_args.push_back("--quiet");
		wget_args.push_back("--output-document=-");
		wget_args.push_back("--save-headers");
		wget_args.push_back("--content-on-error");
		wget_args.push_back("--no-http-keep-alive");

		arg= "--certificate=";
		arg+= conn->client_cert_file();
		wget_args.push_back(arg);

		arg= "--certificate-type=";
		arg+= conn->client_cert_type();
		wget_args.push_back(arg);

		arg= conn->client_key_file();
		if ( arg != "" ) {
			arg= "--private-key=" + arg;
			wget_args.push_back(arg);
		}

		arg= conn->proxy_server();
		// Override environment
		if ( arg != "" ) {
			string proxy_url= "http://";
			proxy_url+= arg;
			if ( conn->proxy_port() != 80 ) {
				proxy_url+= ":";
				proxy_url+= to_string(conn->proxy_port());
			}
			proxy_url+= "/";

			setenv("https_proxy", proxy_url.c_str(), 1);
		}

		if ( conn->proxy_mode() == IAS_PROXY_NONE ) {
			wget_args.push_back("--no-proxy");
		} else if ( conn->proxy_mode() == IAS_PROXY_FORCE ) {
			unsetenv("no_proxy");
		} 
	}

	/* Set up two pipes for reading from the child */

	if ( pipe(pipefd) == -1 ) {
		perror("pipe");
		return 0;
	}

	/* Spawn the child process */

	pid= fork();
	if ( pid == -1 ) {			/* oops */
		perror("fork");
		return 0;
	} else if ( pid == 0 ) {	/* child */
		char **argv;
		size_t sz, i;

		// Add instance-specific options

		if ( postdata ) {
			arg= "--post-file=";
			arg+= tmpfile;
			wget_args.push_back(arg);
		}

		// Add the url

		wget_args.push_back(url.c_str());

		sz= wget_args.size();

		// Create the argument list

		argv= (char **) malloc(sizeof(char *)*(sz+1));
		for(i= 0; i< sz; ++i) {
			argv[i]= strdup(wget_args[i].c_str());
			if ( argv[i] == NULL ) {
				perror("strdup");
				exit(1);
			}
		}
		argv[sz]= 0;

retry_dup:
		/* Dup stdout onto our pipe */

		if ( dup2(pipefd[1], STDOUT_FILENO) == -1 ) {
			if ( errno == EINTR ) goto retry_dup;
			perror("dup2");
			exit(1);
		}
		close(pipefd[1]);
		close(pipefd[0]);

		execvp("wget", argv);
		perror("execvp: wget");
		exit(1);
	} 
	
	/* parent */

	close(pipefd[1]);

	/* Read until eol */

	repeat= 1;
	while ( repeat ) {
		bread= read(pipefd[0], buffer, CHUNK_SZ);
		if ( bread == -1 ) {
			if ( errno == EINTR ) continue;
			else {
				perror("read");
				repeat= 0;
				rv= 0;
			}
		} else if ( bread == 0 ) {
			repeat= 0;
		} else {
			sresponse.append(buffer, bread);
		}
	}

	/* This is a blocking wait */
retry_wait:
	if ( waitpid(pid, &status, 0) == -1 ) {
		if ( errno == EINTR) goto retry_wait;
		else {
			perror("waitpid");
			rv= 0;
		}
	}

	fprintf(stderr, "+++ rv= %d\n", rv);

	unlink(tmpfile);
	if ( ! rv ) return 0;

	if ( WIFEXITED(status) ) {
		int exitcode= WEXITSTATUS(status);
		fprintf(stderr, "+++ wget exited with code %08x\n", exitcode);
		dividerWithText("HTTP Response");
		fprintf(stderr, "%s\n", sresponse.c_str());
		divider();
	} else rv= 0;

	return rv;
}

