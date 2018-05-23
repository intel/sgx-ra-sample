## This must come first when building an application that uses Intel
## SGX enclaves.

include $(top_srcdir)/build-aux/sgx_app.am

## It sets the following automake variables:
##
##   AM_CPPFLAGS = -I$(SGXSDK_INCDIR)
##   AM_LDFLAGS = -L$(SGXSDK_LIBDIR)
##
## And a pattern rule for building proxy functions from EDL files:
##
##   %_u.h %_u.c: %.edl
##
## And sets these Makefile variables:
##
##   SGXSDK
##   SGXSDK_BINDIR
##   SGXSDK_INCDIR
##   SGXSDK_LIBDIR
##   SGXSSL
##   SGXSSL_BINDIR
##   SGXSSL_INCDIR
##   SGXSSL_LIBDIR
##   SGX_URTS_LIB
##   SGX_UAE_SERVICE_LIB
##   SGX_EDGER8R

SUBDIRS = EnclaveQuote 

## Supply additional flags to edger8r here. 
##
## SGX_EDGER8R_FLAGS=


## Needed to make our pattern rule work

EnclaveQuote.edl: EnclaveQuote/EnclaveQuote.edl
	ln -s $?

EnclaveQuote.signed.so: EnclaveQuote/EnclaveQuote.signed.so
	ln -s $?


## Additional automake variables
##
## AM_CPPFLAGS += 
## AM_CFLAGS = 

AM_CXXFLAGS = -std=c++11 

AM_CPPFLAGS += -fno-builtin-memset @OPENSSL_CPPFLAGS@

## Additional targets to remove with 'make clean'. You must list
## any edger8r generated files here.

CLEANFILES = EnclaveQuote_u.c EnclaveQuote_u.h EnclaveQuote.edl EnclaveQuote.signed.so


## The build target

bin_PROGRAMS = client sp 

## You can't use $(wildcard ...) with automake so all source files 
## have to be explicitly listed.

common = byteorder.c common.cpp crypto.c hexutil.c fileio.c base64.c \
	msgio.c logfile.c

## client 

client_SOURCES = client.cpp sgx_detect_linux.c sgx_stub.c $(common)
nodist_client_SOURCES = EnclaveQuote_u.c EnclaveQuote_u.h
EXTRA_client_DEPENDENCIES = EnclaveQuote.signed.so
BUILT_SOURCES = EnclaveQuote_u.c EnclaveQuote_u.h

client_LDFLAGS = $(AM_LDFLAGS) @OPENSSL_LDFLAGS@

## sp

sp_SOURCES = sp.cpp agent_wget.cpp agent_curl.cpp iasrequest.cpp $(common)

## Library flags. At minimum, an Intel SGX application will need:
##
##   -l$(SGX_URTS_LIB)
##
## Applications that use platform services or perform attestation
## will also need:
##
##  -l$(SGX_UAE_SERVICE_LIB)
##
## Use the variables, not the actual library names to ensure these
## targets work on simulation builds.

client_LDADD=-l$(SGX_URTS_LIB) -lsgx_ukey_exchange -l$(SGX_UAE_SERVICE_LIB) \
	-lcrypto -l:libsgx_capable.a -lpthread -ldl

# Statically link to the 1.1.0 build of libcrypto.a to avoid potential 
# conflicts with the system version of libcrypto.so needed by libcurl.

sp_LDADD=$(OPENSSL_LIB) -lpthread -ldl -lcurl 

