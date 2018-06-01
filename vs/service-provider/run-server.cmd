@ECHO OFF

SETLOCAL

CALL settings.cmd

IF "%RA_LINKABLE%" NEQ "0" SET ra_linkable=-l

IF "%RA_QUERY_IAS_PRODUCTION%" NEQ "0" SET sp_production=1

IF NOT "%RA_IAS_CLIENT_CERT_KEY_PASSWORD_FILE%"=="" SET sp_cert_passwd=--ias-cert-passwd=%RA_IAS_CLIENT_CERT_KEY_PASSWORD_FILE%

IF NOT "%RA_IAS_CLIENT_CERT_TYPE%"=="" SET sp_cert_type=--ias-cert-type=%RA_IAS_CLIENT_CERT_TYPE%

IF NOT "%IAS_PROXY_URL%"=="" SET sp_proxy=--proxy=%RA_IAS_PROXY_URL%

IF NOT "%IAS_DISABLE_PROXY%"=="" SET sp_noproxy=-x


@ECHO ON

sp.exe -s %RA_SPID% -A %RA_IAS_REPORT_SIGNING_CA_FILE% -C %RA_IAS_CLIENT_CERT_FILE% %sp_noproxy% %sp_proxy% %sp_cert_passwd% %sp_cert_type% %ra_linkable%

@ECHO OFF

PAUSE
EXIT /B 0
