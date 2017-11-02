AC_INIT(sgxautosample, 1.0, john.p.mechalas@intel.com)

AC_PROG_CC()
AC_PROG_CXX()
AC_PROG_INSTALL()

AC_CONFIG_HEADERS([config.h])

CPPFLAGS="$CPPFLAGS `pkg-config --cflags glib-2.0`"
LIBS="$CFLAGS `pkg-config --libs glib-2.0`"

SGX_INIT()

# List your enclaves here. The build system expects each enclave to be in
# its own subdirectory, named after the enclave, containing an EDL file
# also named after the Enclave.
# 
# For example, if your enclave is called "MyEnclave" it should have its
# EDL file at MyEnclave/MyEnclave.edl).
#
# If your enclaves have a parent directory somewhere other than the
# current directory, supply that path as the second argument.
#
# Examples: 
# 	SGX_ADD_ENCLAVES([ MyEnclave ]);
# 	SGX_ADD_ENCLAVES([ MyEnclave1 MyEnclave2 ], [ enclaves ]);

SGX_ADD_ENCLAVES(EnclaveQuote)

AC_SUBST(glib_incdir)

AC_CONFIG_FILES([Makefile])

if test "$SGX_HW_SIM" = "1"
then
	sim="-sim"
fi
	AC_CONFIG_FILES(EnclaveQuote/EnclaveQuote.edl:EnclaveQuote/EnclaveQuote-linux${sim}.edl.in)

AC_OUTPUT()

