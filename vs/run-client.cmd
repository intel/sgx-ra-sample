@ECHO OFF

SETLOCAL

CALL settings.cmd

IF "%RA_RANDOM_NONCE%" NEQ "0" SET cl_nonce=-r
IF "%RA_USE_PLATFORM_SERVICES%" NEQ "0" SET cl_pse=-m
IF "%RA_LINKABLE%" NEQ "0" SET ra_link=-l
IF "%RA_VERBOSE%" NEQ "0" SET verbose=-v
IF "%RA_DEBUG%" NEQ "0" SET debug=-d

@ECHO ON

client.exe -s %RA_SPID% %cl_nonce% %cl_pse% %ra_link% %verbose% %debug% %*

@ECHO OFF

PAUSE
EXIT /B 0
