# SGX_TSTDC_CHECK_TYPE_PREFIX([TYPE], [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND], [INCLUDES])
# -----------------------------------------------------------------------------
# Works like SGX_TSTDC_CHECK_TYPE, only assigns a prefix of "tstdc_" to
# the cache variable and "TSTDC_" to the CPP define (HAVE_TSTDC_x).
AC_DEFUN([SGX_TSTDC_CHECK_TYPE_PREFIX], [
	type=AS_TR_SH([$1])
	AS_VAR_SET_IF([ac_cv_type_$type], [
		AS_VAR_COPY([o_ac_cv_type_$type],[ac_cv_type_$type])
		AS_UNSET([ac_cv_type_$type])
	])
	SGX_TSTDC_CHECK_TYPE([$1], [$2], [$3], [$4])
	AS_VAR_COPY([ac_cv_tstdc_type_$type],[ac_cv_type_$type])
	AS_VAR_SET_IF([o_ac_cv_type_$type], [
		AS_VAR_COPY([ac_cv_type_$type],[o_ac_cv_type_$type])
		AS_UNSET([o_ac_cv_type_$type])
	],[
		AS_UNSET([ac_cv_type_$type])
	])
	AC_DEFINE(AS_TR_CPP([HAVE_TSTDC_$1]), 1)
]) # SGX_TSTDC_CHECK_TYPE_PREFIX


# SGX_TSTDC_CHECK_TYPES_PREFIX([TYPES], [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND], [INCLUDES])
# -----------------------------------------------------------------------------
# Works like SGX_TSTDC_CHECK_TYPES, only assigns a prefix of "tstdc_" to
# the cache variable and "TSTDC_" to the CPP define (HAVE_TSTDC_x).
AC_DEFUN([SGX_TSTDC_CHECK_TYPES_PREFIX], [
	m4_foreach_w([SGX_Type], [$1], [
		SGX_TSTDC_CHECK_TYPE_PREFIX(m4_defn([SGX_Type]), [$2], [$3])
	])
]) # SGX_TSTDC_CHECK_TYPES_PREIFX



# SGX_TSTDC_CHECK_DECL_PREFIX([SYMBOL], [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND], [INCLUDES])
# ------------------------------------------------------------------------
# Works like SGX_TSTDC_CHECK_DECL, only assigns a prefix of "tstdc_" to
# the cache variable and "TSTDC_" to the CPP define (HAVE_TSTDC_x).
AC_DEFUN([SGX_TSTDC_CHECK_DECL_PREFIX], [
	decl=AS_TR_SH([$1])
	AS_VAR_SET_IF([ac_cv_decl_$decl], [
		AS_VAR_COPY([o_ac_cv_decl_$decl],[ac_cv_decl_$decl])
		AS_UNSET([ac_cv_decl_$decl])
	])
	SGX_TSTDC_CHECK_DECL([$1], [$2], [$3], [$4])
	AS_VAR_COPY([ac_cv_tstdc_decl_$decl],[ac_cv_decl_$decl])
	AS_VAR_SET_IF([o_ac_cv_decl_$decl], [
		AS_VAR_COPY([ac_cv_decl_$decl],[o_ac_cv_decl_$decl])
		AS_UNSET([o_ac_cv_decl_$decl])
	],[
		AS_UNSET([ac_cv_decl_$decl])
	])
	AC_DEFINE(AS_TR_CPP([HAVE_TSTDC_$1]), 1)
]) # SGX_TSTDC_CHECK_DECL_PREFIX


# SGX_TSTDC_CHECK_DECLS_PREFIX([SYMBOLS], [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND], [INCLUDES])
# ------------------------------------------------------------------------
# Works like SGX_TSTDC_CHECK_DECLS, only assigns a prefix of "tstdc_" to
# the cache variable and "TSTDC_" to the CPP define (HAVE_TSTDC_x).
AC_DEFUN([SGX_TSTDC_CHECK_DECLS_PREFIX], [
	m4_foreach_w([SGX_Decl], [$1], [
		SGX_TSTDC_CHECK_DECL_PREFIX(m4_defn([SGX_Decl]), [$2], [$3])
	])
]) # SGX_TSTDC_CHECK_DECLS_PREFIX


# SGX_TSTDC_CHECK_DECLS_ONCE_PREFIX([SYMBOLS])
# -------------------------------------
# Works like SGX_TSTDC_CHECK_DECLS_ONCE, only assigns a prefix of "tstdc_" 
# to the cache variable and "TSTDC_" to the CPP define (HAVE_TSTDC_x).
AC_DEFUN([SGX_TSTDC_CHECK_DECLS_ONCE_PREFIX], [
	SGX_TSTDC_CHECK_DECLS_PREFIX([$1])
]) # SGX_TSTDC_CHECK_DECLS_PREFIX


# SGX_TSTDC_CHECK_HEADER_PREFIX(HEADER, [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
# ------------------------------------------------------------------------
# Works like SGX_TSTDC_CHECK_HEADER, only assigns a prefix of "tstdc_" to
# the cache variable and "TSTDC_" to the CPP define (HAVE_TSTDC_x).
AC_DEFUN([SGX_TSTDC_CHECK_HEADER_PREFIX], [
	header=AS_TR_SH([$1])
	AS_VAR_SET_IF([ac_cv_header_$header], [
		AS_VAR_COPY([o_ac_cv_header_$header],[ac_cv_header_$header])
		AS_UNSET([ac_cv_header_$header])
	])
	SGX_TSTDC_CHECK_HEADER([$1], [$2], [$3])
	AS_VAR_COPY([ac_cv_tstdc_header_$header],[ac_cv_header_$header])
	AS_VAR_SET_IF([o_ac_cv_header_$header], [
		AS_VAR_COPY([ac_cv_header_$header],[o_ac_cv_header_$header])
		AS_UNSET([o_ac_cv_header_$header])
	],[
		AS_UNSET([ac_cv_header_$header])
	])
	AH_TEMPLATE(AS_TR_CPP([HAVE_TSTDC_$1]),
		[Define to 1 if Intel SGX has the <$1> header file.])
	AC_DEFINE(AS_TR_CPP([HAVE_TSTDC_$1]), 1)
]) # SGX_TSTDC_CHECK_HEADER_PREFIX


# SGX_TSTDC_CHECK_HEADERS_PREFIX(HEADER, [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
# ------------------------------------------------------------------------
# Works like SGX_TSTDC_CHECK_HEADERS, only assigns a prefix of "tstdc_" to
# the cache variable and "TSTDC_" to the CPP define (HAVE_TSTDC_x).
AC_DEFUN([SGX_TSTDC_CHECK_HEADERS_PREFIX], [
	m4_foreach_w([SGX_Header], [$1], [
		SGX_TSTDC_CHECK_HEADER_PREFIX(m4_defn([SGX_Header]), [$2], [$3])
	])
]) # SGX_TSTDC_CHECK_HEADERS_PREFIX


# SGX_TSTDC_CHECK_FUNC_PREFIX(FUNCTION, [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
# ------------------------------------------------------------------------
# Works like SGX_TSTDC_CHECK_FUNC, only assigns a prefix of "tstdc_" to
# the cache variable and "TSTDC_" to the CPP define (HAVE_TSTDC_x).
AC_DEFUN([SGX_TSTDC_CHECK_FUNC_PREFIX], [
	func=AS_TR_SH([$1])
	AS_VAR_SET_IF([ac_cv_func_$func], [
		AS_VAR_COPY([o_ac_cv_func_$func],[ac_cv_func_$func])
		AS_UNSET([ac_cv_func_$func])
	])
	SGX_TSTDC_CHECK_FUNC([$1], [$2], [$3])
	AS_VAR_COPY([ac_cv_tstdc_func_$func],[ac_cv_func_$func])
	AS_VAR_SET_IF([o_ac_cv_func_$func], [
		AS_VAR_COPY([ac_cv_func_$func],[o_ac_cv_func_$func])
		AS_UNSET([o_ac_cv_func_$func])
	],[
		AS_UNSET([ac_cv_func_$func])
	])
	AC_DEFINE(AS_TR_CPP([HAVE_TSTDC_$1]), 1)
]) # SGX_TSTDC_CHECK_FUNC_PREFIX


# SGX_TSTDC_CHECK_FUNCS_PREFIX(FUNCTION..., [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
# ----------------------------------------------------------------------------
# Works like SGX_TSTDC_CHECK_FUNCS, only assigns a prefix of "tstdc_" to
# the cache variable and "TSTDC_" to the CPP define (HAVE_TSTDC_x).
AC_DEFUN([SGX_TSTDC_CHECK_FUNCS_PREFIX], [
	m4_foreach_w([SGX_Func], [$1], [
		SGX_TSTDC_CHECK_FUNC_PREFIX(m4_defn([SGX_Func]), [$2], [$3])
	])
]) # SGX_TSTDC_CHECK_FUNCS_PREFIX

