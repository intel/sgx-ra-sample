:: NOTE: This file uses Windows batch file syntax because it is
:: executed via CALL from run-client.cmd and run-server.cmd

::======================================================================
:: Global options
::======================================================================

:: Set to non-zero to query the production IAS instead of development.
:: Note that the SPID and certificate are different for production
:: and development, so if you change this you'll need to change them,
:: too.

SET RA_QUERY_IAS_PRODUCTION=0


:: Your Service Provider ID. This should be a 32-character hex string.
:: [REQUIRED]

SET RA_SPID=0123456789ABCDEF0123456789ABCDEF


:: Set to a non-zero value if this SPID is associated with linkable 
:: quotes. If you change this, you'll need to change SPID and
:: IAS_CLIENT_CERT_FILE, too.

SET RA_LINKABLE=0


::======================================================================
:: Client options
::======================================================================

:: Set to non-zero to have the client generate a random nonce.

SET RA_RANDOM_NONCE=1


:: Set to non-zero to have the client generate a platform manifest.
:: This requires a PSE session, and thus support for platform
:: services.
::
:: (Note that server hardware does not have platform servces)

SET RA_USE_PLATFORM_SERVICES=0


::======================================================================
:: Service provider (server) options
::======================================================================


:: Your IAS client certificate file. [REQUIRED]

SET RA_IAS_CLIENT_CERT_FILE=""


:: Your IAS client certificate type. This defaults to PEM if you leave
:: it blank. Can be either PEM or P12.

:: SET RA_IAS_CLIENT_CERT_TYPE=


:: If your IAS client certificate's key is separate from your 
:: certificate, set the filename here. Otherwise, leave it 
:: blank.

SET RA_IAS_CLIENT_CERT_KEY_FILE=""


:: If your IAS client certificate's key is encrypted, put the password
:: in a file, and set the filename here.

SET RA_IAS_CLIENT_CERT_KEY_PASSWORD_FILE=""


:: The path to the Intel IAS SGX Report Signing CA file. You are sent 
:: this certificate when you apply for access to SGX Developer Services at 
:: http://software.intel.com/sgx [REQUIRED]


SET RA_IAS_REPORT_SIGNING_CA_FILE=""


:: Set to the URL for your proxy server to force the use of a proxy
:: when communicating with IAS (overriding any environment variables).

:: SET RA_IAS_PROXY_URL=


:: Set to non-zero to disable the use of a proxy server and force a
:: direct connection when communicating with IAS (overriding any
:: environment variables).

:: SET RA_IAS_DISABLE_PROXY=0


::======================================================================
:: Debugging options
::======================================================================

:: Set to non-zero for verbose output

SET RA_VERBOSE=0


:: Set to non-zero for debugging output

SET RA_DEBUG=0

