SGX_ENCLAVES:=EnclaveQuote

CC=gcc
# Define ENCLAVE_LIBDIR to hardcode the library path that enclaves 
# are loaded from. Otherwise, create_enclave will search in the
# programs current working directory.
#CFLAGS=-g -O2 -fno-builtin-memset
CFLAGS=-g -O2 -fno-builtin-memset
CPPFLAGS= -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include
LDFLAGS= -L$(SGXSDK_LIBDIR)
LIBS=-g -O2 -lglib-2.0

INSTALL=/usr/bin/install -c
prefix=/usr/local
exec_prefix=${prefix}
bindir=${exec_prefix}/bin
libdir=${exec_prefix}/lib
enclave_libdir=${exec_prefix}/lib

APP_OBJS=main.o sgx_stub.o

%.o: %.c
	$(CC) -c $(CPPFLAGS) $(CFLAGS) -I$(SGXSDK_INCDIR) $<

all: quote $(SGX_ENCLAVES)

install: install-program install-enclaves

install-program: all 
	$(INSTALL) -d $(bindir)
	$(INSTALL) -t $(bindir) enclavereport

install-enclaves:
	for dir in $(SGX_ENCLAVES); do \
		$(MAKE) -C $$dir install; \
	done

include sgx_app.mk

quote: $(ENCLAVE_UOBJS) $(APP_OBJS)
	$(CC) -o $@ $(LDFLAGS) $(APP_OBJS) $(ENCLAVE_UOBJS) $(LIBS) -ldl

clean: clean_enclaves
	rm -f quote $(APP_OBJS) $(ENCLAVE_CLEAN)

distclean: clean distclean_enclaves
	rm -rf Makefile config.log config.status config.h autom4te.cache
	rm -rf sgx_app.mk sgx_enclave.mk

