SGXSDK=/opt/intel/sgxsdk
SGXSDK_BINDIR=/opt/intel/sgxsdk/bin/x64
SGXSDK_INCDIR=/opt/intel/sgxsdk/include
SGXSDK_LIBDIR=/opt/intel/sgxsdk/lib64
SGX_TRTS_LIB=sgx_trts
SGX_TSERVICE_LIB=sgx_tservice
SGX_EDGER8R=$(SGXSDK_BINDIR)/sgx_edger8r
SGX_SIGN=$(SGXSDK_BINDIR)/sgx_sign

ENCLAVE_CFLAGS=-nostdinc -fvisibility=hidden -fpie -fstack-protector
ENCLAVE_CPPFLAGS=-I$(SGXSDK_INCDIR) -I$(SGXSDK_INCDIR)/tlibc
ENCLAVE_CXXFLAGS=-nostdinc++ $(ENCLAVE_CFLAGS)
ENCLAVE_LDFLAGS=-Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
	-L$(SGXSDK_LIBDIR) \
	-Wl,--whole-archive -l$(SGX_TRTS_LIB) -Wl,--no-whole-archive \
	-Wl,--start-group $(ENCLAVE_EXTRA_LIBS) -lsgx_tstdc -lsgx_tstdcxx -lsgx_tcrypto -l$(SGX_TSERVICE_LIB) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
	-Wl,--defsym,__ImageBase=0
ENCLAVE_PKEY=$(ENCLAVE)_private.pem
ENCLAVE_CFG=$(ENCLAVE).config.xml

ENCLAVE_TOBJ= $(ENCLAVE)_t.o
ENCLAVE_CLEAN= $(ENCLAVE)_t.o $(ENCLAVE)_t.c $(ENCLAVE)_t.h $(ENCLAVE).so $(ENCLAVE).signed.so
ENCLAVE_DISTCLEAN=
ENCLAVE_SIGNED= $(ENCLAVE).signed.so
ENCLAVE_UNSIGNED= $(ENCLAVE).so

define _NL_


endef

$(ENCLAVE_SIGNED): signed_enclave_dev

signed_enclave_dev: $(ENCLAVE_UNSIGNED) $(ENCLAVE_PKEY) $(ENCLAVE_CFG)
	$(SGX_SIGN) sign -key $(ENCLAVE_PKEY) -enclave $(ENCLAVE_UNSIGNED) -out $(ENCLAVE_SIGNED) -config $(ENCLAVE_CFG)

signed_enclave_rel:
	@echo "--------------------------------------------------------------"
	@echo "The project has been built in release hardware mode."
	@echo "Please sign $(ENCLAVE_UNSIGNED) with your signing key "
	@echo "before you run the application to launch and access "
	@echo "the enclave."
	@echo
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_SIGN) sign -key <your_key> -enclave $(ENCLAVE_UNSIGNED) -out $(ENCLAVE_SIGNED) -config $(ENCLAVE_CFG)
	@echo "You can also sign the enclave using an external signing tool."
	@echo "--------------------------------------------------------------"


$(ENCLAVE_CFG):
	@echo "Creating default enclave configuration file:"
	@echo "$(ENCLAVE_CFG)"
	@echo "<EnclaveConfiguration>">$(ENCLAVE_CFG)
	@echo "	<ProdID>0</ProdID>">>$(ENCLAVE_CFG)
	@echo "	<ISVSVN>0</ISVSVN>">>$(ENCLAVE_CFG)
	@echo "	<StackMaxSize>0x40000</StackMaxSize>">>$(ENCLAVE_CFG)
	@echo "	<HeapMaxSize>0x100000</HeapMaxSize>">>$(ENCLAVE_CFG)
	@echo "	<TCSNum>1</TCSNum>">>$(ENCLAVE_CFG)
	@echo "	<TCSPolicy>1</TCSPolicy>">>$(ENCLAVE_CFG)
	@echo "	<!-- Recommend changing 'DisableDebug' to 1 to make the enclave undebuggable for enclave release -->">>$(ENCLAVE_CFG)
	@echo "	<DisableDebug>0</DisableDebug>">>$(ENCLAVE_CFG)
	@echo "	<MiscSelect>0</MiscSelect>">>$(ENCLAVE_CFG)
	@echo "	<MiscMask>0xFFFFFFFF</MiscMask>">>$(ENCLAVE_CFG)
	@echo "	</EnclaveConfiguration>">>$(ENCLAVE_CFG)
	@echo ""

$(ENCLAVE_PKEY):
	@echo "Creating random private key file for testing and"
	@echo "debugging purposes:"
	@echo "$(ENCLAVE_PKEY)"
	openssl genrsa -3 -out $@ 3072

$(ENCLAVE)_t.c: $(ENCLAVE).edl 
	$(SGX_EDGER8R) $(SGX_EDGER8R_FLAGS) --trusted $<

