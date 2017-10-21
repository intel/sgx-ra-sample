CC=gcc
CFLAGS=-g -O2
CPPFLAGS= -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include
LDFLAGS=

INSTALL=/usr/bin/install -c
prefix=/usr/local
exec_prefix=${prefix}
bindir=${exec_prefix}/bin
libdir=${exec_prefix}/lib
enclave_libdir=${exec_prefix}/lib

ENCLAVE=EnclaveQuote

OBJS=$(ENCLAVE).o

%.o: %.c
	$(CC) $(CPPFLAGS) $(ENCLAVE_CPPFLAGS) $(CFLAGS) $(ENCLAVE_CFLAGS) -c $<

all: $(ENCLAVE).so

install: all
	$(INSTALL) -d $(enclave_libdir)
	$(INSTALL) -t $(enclave_libdir) $(ENCLAVE_SIGNED)

include ../sgx_enclave.mk

$(ENCLAVE).so: $(ENCLAVE_TOBJ) $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(ENCLAVE_TOBJ) $(OBJS) $(LDFLAGS) $(ENCLAVE_LDFLAGS)

clean:
	rm -f $(OBJS) $(ENCLAVE_CLEAN) 

distclean: clean
	rm -f Makefile $(ENCLAVE_DISTCLEAN)

