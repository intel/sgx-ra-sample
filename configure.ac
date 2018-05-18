AC_INIT(sgxautosample, 1.0, john.p.mechalas@intel.com)

AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE([foreign])

AC_PROG_CXX
AC_PROG_CPP
AC_PROG_INSTALL
AM_PROG_CC_C_O
AC_PROG_RANLIB

AC_CONFIG_HEADERS([config.h])

SGX_INIT()

AC_ARG_WITH([openssl],
	[AC_HELP_STRING([--with-openssl=DIR], [Specify location of OpenSSL])],
	[openssl=$withval],[])

dnl Don't blindly add -lcrypto to LIBS
old_LDFLAGS="$LDFLAGS"
old_LIBS="$LIBS"
LDFLAGS="$LDFLAGS -L${openssl}/lib"
AC_SEARCH_LIBS([ECDSA_SIG_set0], [crypto], [], [
	AC_MSG_ERROR([Need OpenSSL v1.1.0 or later])
])
LDFLAGS="$old_LDFLAGS"
LIBS="$old_LIBS"

AS_IF([test "$openssl" != ""], [
	AC_SUBST([OPENSSL_CPPFLAGS], [-I$openssl/include])
	AC_SUBST([OPENSSL_LDFLAGS], [-L$openssl/lib])
])

dnl Find default CA bundle that works with OpenSSL apps, if possible. 
ac_cv_default_ca_bundle_auto="not found"
AC_MSG_CHECKING([CA bundle file])
trydirs="_/etc/ssl/certs _/etc/pki/tls"
tryfiles="ca-bundle.crt ca-certificates.crt cert.pem"
for dir in $trydirs; do
	for file in $tryfiles; do
		AS_IF([test -f $dir/$file],
			[ac_cv_default_ca_bundle_auto=$dir/$file; break 2])
	done
done
AC_MSG_RESULT([$ac_cv_default_ca_bundle_auto])
AS_IF([ test "$ac_cv_default_ca_bundle_auto" = "not found" ],
	[ac_cv_default_ca_bundle_auto=""])
AC_DEFINE_UNQUOTED([DEFAULT_CA_BUNDLE_AUTO], ["$ac_cv_default_ca_bundle_auto"],
	[Default CA bundle for OpenSSL-based applications])

AC_CONFIG_FILES([
	Makefile
	EnclaveQuote/Makefile
])

AC_OUTPUT

