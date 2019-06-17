@ECHO OFF

SETLOCAL

CALL settings.cmd

IF "%RA_LINKABLE%" NEQ "0" SET ra_link_opt=-l

IF "%RA_QUERY_IAS_PRODUCTION%" NEQ "0" SET sp_production=-P

IF NOT "%RA_IAS_PROXY_URL%"=="" SET sp_proxy=--proxy=%RA_IAS_PROXY_URL%

IF NOT "%IAS_DISABLE_PROXY%"=="" SET sp_noproxy=-x

IF "%RA_POLICY_STRICT_TRUST%" NEQ "0" SET strict_trust=-X

IF "%RA_VERBOSE%" NEQ "0" SET verbose=-v

IF "%RA_DEBUG%" NEQ "0" SET debug=-d


@ECHO ON

sp.exe -i %RA_IAS_PRIMARY_SUBSCRIPTION_KEY% -j %RA_IAS_SECONDARY_SUBSCRIPTION_KEY% -s %RA_SPID% -A %RA_IAS_REPORT_SIGNING_CA_FILE% -C %RA_IAS_CLIENT_CERT_FILE% %sp_production% %sp_noproxy% %sp_proxy% %ra_link_opt% %strict_trust% %verbose% %debug% %*

@ECHO OFF

PAUSE
EXIT /B 0
