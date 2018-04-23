# SGX_TSTDC_CHECK_TYPE([TYPE], [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND], [INCLUDES])
# ----------------------------------------------------------------------------------
# Works like AC_CHECK_TYPE only it uses includes from the
# SGX trusted C headers, not in the standard C library headers.
# We do this by saving the old compiler and preprocessor flags
# and replacing them with the flags used to compile a trusted
# library.
AC_DEFUN([SGX_TSTDC_CHECK_TYPE], [
	AS_IF([test "x${ac_cv_enable_sgx}" = "xyes"],[
		_SGX_TSTDC_COMPILER_FLAGS_SET
		AC_CHECK_TYPE([$1],[$2],[$3],[$4])
		_SGX_TSTDC_COMPILER_FLAGS_RESTORE
	],[
		AC_MSG_ERROR([Tried to call [SGX_TSTDC_CHECK_TYPE] on build without Intel SGX])
	])
]) # SGX_TSTDC_CHECK_TYPE

# SGX_TSTDC_CHECK_TYPES([TYPES], [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND], [INCLUDES])
# ----------------------------------------------------------------------------------
# Works like AC_CHECK_TYPE only it uses includes from the
# SGX trusted C headers, not in the standard C library headers.
# See SGX_TSTDC_CHECK_TYPE
AC_DEFUN([SGX_TSTDC_CHECK_TYPES], [
	AS_IF([test "x${ac_cv_enable_sgx}" = "xyes"],[
		_SGX_TSTDC_COMPILER_FLAGS_SET
		AC_CHECK_TYPES([$1],[$2],[$3],[$4])
		_SGX_TSTDC_COMPILER_FLAGS_RESTORE
	],[
		AC_MSG_ERROR([Tried to call [SGX_TSTDC_CHECK_TYPES] on build without Intel SGX])
	])
]) # SGX_TSTDC_CHECK_TYPES



# SGX_TSTDC_CHECK_DECL([SYMBOL], [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND], [INCLUDES])
# ------------------------------------------------------------------------
# Works like AC_CHECK_DECL only it looks for headers in the 
# SGX trusted C headers, not in the standard C library headers.
# We do this by saving the old compiler and preprocessor flags
# and replacing them with the flags used to compile a trusted
# library.
AC_DEFUN([SGX_TSTDC_CHECK_DECL], [
	AS_IF([test "x${ac_cv_enable_sgx}" = "xyes"],[
		_SGX_TSTDC_COMPILER_FLAGS_SET
		AC_CHECK_DECL([$1],[$2],[$3],[$4])
		_SGX_TSTDC_COMPILER_FLAGS_RESTORE
	],[
		AC_MSG_ERROR([Tried to call [SGX_TSTDC_CHECK_DECL] on build without Intel SGX])
	])
]) # SGX_TSTDC_CHECK_DECL

# SGX_TSTDC_CHECK_DECLS([SYMBOLS], [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND], [INCLUDES])
# ------------------------------------------------------------------------
# Works like AC_CHECK_DECLS only it looks for headers in the 
# SGX trusted C headers, not in the standard C library headers.
# See SGX_TSTDC_CHECK_DECL
AC_DEFUN([SGX_TSTDC_CHECK_DECLS], [
	AS_IF([test "x${ac_cv_enable_sgx}" = "xyes"],[
		_SGX_TSTDC_COMPILER_FLAGS_SET
		AC_CHECK_DECLS([$1],[$2],[$3],[$4])
		_SGX_TSTDC_COMPILER_FLAGS_RESTORE
	],[
		AC_MSG_ERROR([Tried to call [SGX_TSTDC_CHECK_DECLS] on build without Intel SGX])
	])
]) # SGX_TSTDC_CHECK_DECLS

# SGX_TSTDC_CHECK_DECLS_ONCE([SYMBOLS])
# -------------------------------------
# Works like AC_CHECK_DECLS_ONCE only it looks for headers in the 
# SGX trusted C headers, not in the standard C library headers.
# See SGX_TSTDC_CHECK_DECL
AC_DEFUN([SGX_TSTDC_CHECK_DECLS_ONCE], [
	AS_IF([test "x${ac_cv_enable_sgx}" = "xyes"],[
		_SGX_TSTDC_COMPILER_FLAGS_SET
		AC_CHECK_DECLS_ONCE([$1])
		_SGX_TSTDC_COMPILER_FLAGS_RESTORE
	],[
		AC_MSG_ERROR([Tried to call [SGX_TSTDC_CHECK_DECLS_ONCE] on build without Intel SGX])
	])
]) # SGX_TSTDC_CHECK_DECLS

# SGX_TSTDC_CHECK_HEADER(HEADER, [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
# ------------------------------------------------------------------------
# Works like AC_CHECK_HEADER only it looks for headers in the 
# SGX trusted C headers, not in the standard C library headers.
# We do this by saving the old compiler and preprocessor flags
# and replacing them with the flags used to compile a trusted
# library.
AC_DEFUN([SGX_TSTDC_CHECK_HEADER], [
	AS_IF([test "x${ac_cv_enable_sgx}" = "xyes"],[
		_SGX_TSTDC_COMPILER_FLAGS_SET
		AC_CHECK_HEADER([$1],[$2],[$3])
		_SGX_TSTDC_COMPILER_FLAGS_RESTORE
	],[
		AC_MSG_ERROR([Tried to call [SGX_TSTDC_CHECK_HEADER] on build without Intel SGX])
	])
]) # SGX_TSTDC_CHECK_HEADER

# SGX_TSTDC_CHECK_HEADERS(HEADER, [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
# ------------------------------------------------------------------------
# Works like AC_CHECK_HEADERS only it looks for headers in the 
# SGX trusted C headers, not in the standard C library headers.
# See SGX_TSTDC_CHECK_HEADER
AC_DEFUN([SGX_TSTDC_CHECK_HEADERS], [
	AS_IF([test "x${ac_cv_enable_sgx}" = "xyes"],[
		_SGX_TSTDC_COMPILER_FLAGS_SET
		AC_CHECK_HEADERS([$1],[$2],[$3])
		as_echo_n="echo -n"
		_SGX_TSTDC_COMPILER_FLAGS_RESTORE
	],[
		AC_MSG_ERROR([Tried to call [SGX_TSTDC_CHECK_HEADERS] on build without Intel SGX])
	])
]) # SGX_TSTDC_CHECK_HEADERS


# SGX_TSTDC_CHECK_FUNC(FUNCTION, [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
# ------------------------------------------------------------------------
# Works like AC_CHECK_FUNC only it looks for the function in the 
# SGX trusted C runtime library, not the standard C library. We do
# this by saving the old compiler flags and replacing them with the
# arguments needed for building a trusted library. We do the same 
# with the linker flags, only we use some of the flags needed to 
# create an enclave. We don't have to go all the way to creating
# an enclave, however: it's enough to produce an object file with
# --no-undefined that links against sgx_tstdc.
AC_DEFUN([SGX_TSTDC_CHECK_FUNC], [
	AS_IF([test "x${ac_cv_enable_sgx}" = "xyes"],[
		_SGX_TSTDC_BUILD_FLAGS_SET
		AC_CHECK_FUNC([$1],[$2],[$3])
		_SGX_TSTDC_BUILD_FLAGS_RESTORE
	],[
		AC_MSG_ERROR([Tried to call [SGX_TSTDC_CHECK_FUNC] on build without Intel SGX])
	])
]) # SGX_TSTDC_CHECK_FUNC

# SGX_TSTDC_CHECK_FUNCS(FUNCTION..., [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
# ----------------------------------------------------------------------------
# Works like AC_CHECK_FUNCS only it looks for the functions in the 
# SGX trusted runtime libraries, not the standard C library. See
# SGX_TSTDC_CHECK_FUNC.
AC_DEFUN([SGX_TSTDC_CHECK_FUNCS], [
	AS_IF([test "x${ac_cv_enable_sgx}" = "xyes"],[
		_SGX_TSTDC_BUILD_FLAGS_SET
		AC_CHECK_FUNCS([$1],[$2],[$3])
		_SGX_TSTDC_BUILD_FLAGS_RESTORE
	],[
		AC_MSG_ERROR([Tried to call [SGX_TSTDC_CHECK_FUNCS] on build without Intel SGX])
	])
]) # SGX_TSTDC_CHECK_FUNCS

AC_DEFUN([_SGX_TSTDC_COMPILER_FLAGS_SET],[
		old_CFLAGS="$CFLAGS"
		old_CPPFLAGS="$CPPFLAGS"
		old_CXXFLAGS="$CXXFLAGS"
		CFLAGS="${ac_cv_sgx_tlib_cflags}"
		CPPFLAGS="-nostdinc -nostdinc++ ${ac_cv_sgx_tlib_cppflags}"
		CXXFLAGS="${ac_cv_sgx_tlib_cxxflags}"
		old_echo_n="${as_echo_n}"
		as_echo_n='echo -n Intel SGX: '
])

AC_DEFUN([_SGX_TSTDC_COMPILER_FLAGS_RESTORE],[
		CFLAGS="${old_CFLAGS}"
		CPPFLAGS="${old_CPPFLAGS}"
		CXXFLAGS="${old_CXXFLAGS}"
		as_echo_n="${old_echo_n}"
])

AC_DEFUN([_SGX_TSTDC_BUILD_FLAGS_SET],[
		old_CFLAGS="$CFLAGS"
		old_CPPFLAGS="$CPPFLAGS"
		old_CXXFLAGS="$CXXFLAGS"
		old_LDFLAGS="$LDFLAGS"
		old_LIBS="$LIBS"
		CFLAGS="${ac_cv_sgx_tlib_cflags}"
		CPPFLAGS="${ac_cv_sgx_tlib_cppflags}"
		CXXFLAGS="${ac_cv_sgx_tlib_cxxflags}"
		dnl We have to do thiese a litte differently to ensure a clean
		dnl link. Remember, we are just trying to ensure the symbol
		dnl is found, not produce a usable object.
		LDFLAGS="${ac_cv_sgx_enclave_ldflags} -Wl,--defsym,__ImageBase=0 -Wl,--defsym,do_ecall=0 -Wl,--defsym,g_ecall_table=0 -Wl,--defsym,g_dyn_entry_table=0"
		LIBS="-Wl,--no-undefined -Wl,--start-group -lsgx_tstdc -lsgx_trts -lsgx_tcrypto -Wl,--end-group"
		old_echo_n="${as_echo_n}"
		as_echo_n='echo -n Intel SGX: '
])

AC_DEFUN([_SGX_TSTDC_BUILD_FLAGS_RESTORE],[
		CFLAGS="${old_CFLAGS}"
		CPPFLAGS="${old_CPPFLAGS}"
		CXXFLAGS="${old_CXXFLAGS}"
		LDFLAGS="${old_LDFLAGS}"
		LIBS="${old_LIBS}"
		as_echo_n="${old_echo_n}"
])
