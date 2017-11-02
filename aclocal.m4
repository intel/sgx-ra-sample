# SGX_INIT()
# ------------------
AC_DEFUN([SGX_INIT],[
	AC_ARG_WITH([enclave-libdir],
		[AS_HELP_STRING([--with-enclave-libdir=path (default: EPREFIX/lib)],
			[Set the directory where enclave libraries should be installed])
		], [enclave_libdir=$withval], [enclave_libdir=\$\{exec_prefix\}/lib])
	AC_SUBST(enclave_libdir)
	AC_ARG_ENABLE([sgx-simulation],
		[AS_HELP_STRING([--enable-sgx-simulation (default: disabled)],
			[Use Intel SGX in simulation mode])
		], [_sgxsim=yes], [_sgxsim=no])
	AS_IF([test "x$_sgxsim" = "xyes"], [
			AC_SUBST(SGX_TRTS_LIB, [sgx_trts_sim])
			AC_SUBST(SGX_TSERVICE_LIB, [sgx_tservice_sim])
			AC_SUBST(SGX_UAE_SERVICE_LIB, [sgx_uae_service_sim])
			AC_SUBST(SGX_URTS_LIB, [sgx_urts_sim])
			AC_SUBST(LIBS_HW_SIMU, ["-lsgx_urts_sim -lsgx_uae_service_sim"])
			SGX_HW_SIM=1
			AC_DEFINE(SGX_HW_SIM, 1, [Enable hardware simulation mode])
		], [
			AC_SUBST(SGX_TRTS_LIB, [sgx_trts])
			AC_SUBST(SGX_TSERVICE_LIB, [sgx_tservice])
			AC_SUBST(SGX_UAE_SERVICE_LIB, [sgx_uae_service])
			AC_SUBST(SGX_URTS_LIB, [sgx_urts])
		]
	)
	AC_ARG_WITH([sgx-build],
		[AS_HELP_STRING([--with-sgx-build=debug|prerelease|release (default: debug)],
			[Set Intel SGX build mode])
		], [_sgxbuild=$withval], [_sgxbuild=debug])
	AS_IF([test "x$_sgxbuild" = "xdebug"], [
			AC_DEFINE(DEBUG, 1, [Enable debugging])
			AC_SUBST(ENCLAVE_SIGN_TARGET, [signed_enclave_dev])
		],
		[test "x$_sgxbuild" = "xprerelease"], [
			AC_DEFINE(NDEBUG, 1, [Flag set for prerelease and release builds])
			AC_DEFINE(EDEBUG, 1, [Flag set for prerelease builds])
			AC_SUBST(ENCLAVE_SIGN_TARGET, [signed_enclave_dev])
		],
		[test "x$_sgxbuild" = "xrelease"], [
			AS_IF(test "x$_sgxsim" = "xyes", [
				AC_MSG_ERROR([Can't build in both release and simulation mode])
			],
			[
				AC_DEFINE(NDEBUG, 1)
				AC_SUBST(ENCLAVE_SIGN_TARGET, [signed_enclave_rel])
			])
		],
		[AC_MSG_ERROR([Unknown build mode $_sgxbuild])]
	)
	AC_SUBST(SGX_DEBUG_FLAGS, [$_sgxdebug])
	AS_IF([test "x$SGX_SDK" = "x"], [SGXSDK=detect], [SGXSDK=env])
	AC_ARG_WITH([sgxsdk],
		[AS_HELP_STRING([--with-sgxsdk=path],
			[Set the path to your Intel SGX SDK directory])
		], [SGXSDK=$withval],[SGXSDK="detect"])
	AS_IF([test "x$SGXSDK" = "xenv"], [],
		[test "x$SGXSDK" != "xdetect"], [],
		[test -d /opt/intel/sgxsdk], [SGXSDK=/opt/intel/sgxsdk],
		[test -d ~/sgxsdk], [SGXSDK=~/sgxsdk],
		[test -d ./sgxsdk], [SGXSDK=./sgxsdk],
		[AC_ERROR([Can't detect your Intel SGX SDK installation directory])])
	AS_IF([test -d $SGXSDK/lib], [AC_SUBST(SGXSDK_LIBDIR, $SGXSDK/lib)],
        	[test -d $SGXSDK/lib64], [AC_SUBST(SGXSDK_LIBDIR, $SGXSDK/lib64)],
        	[AC_ERROR(Can't find Intel SGX SDK lib directory)])
	AS_IF([test -d $SGXSDK/bin/ia32], [AC_SUBST(SGXSDK_BINDIR, $SGXSDK/bin/ia32)],
        	[test -d $SGXSDK/bin/x64], [AC_SUBST(SGXSDK_BINDIR, $SGXSDK/bin/x64)],
        	[AC_ERROR(Can't find Intel SGX SDK bin directory)])
	AC_MSG_NOTICE([Found your Intel SGX SDK in $SGXSDK])
	AC_SUBST(SGXSDK_INCDIR, $SGXSDK/include)
	AC_SUBST(SGXSDK)
	AC_CONFIG_FILES([sgx_app.mk])
])

# SGX_ADD_ENCLAVES(ENCLAVES, [ENCLAVE PARENT DIRECTORY=.])
# ------------------
AC_DEFUN([SGX_ADD_ENCLAVES], [
	AS_IF([test "x$2" = "x"],
		[
			AS_VAR_APPEND([SGX_ENCLAVES], m4_map_args_w($1,[],[],[\ ]))
			AC_CONFIG_FILES($1/Makefile)
		],
		[
			AS_VAR_APPEND([SGX_ENCLAVES], m4_map_args_w($1,$2/,[],[\ ]))
			AC_CONFIG_FILES($2/$1/Makefile)
		]
	)
	AC_SUBST(SGX_ENCLAVES)
	AC_CONFIG_FILES([sgx_enclave.mk])
])

