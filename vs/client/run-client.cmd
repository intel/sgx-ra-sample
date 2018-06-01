@ECHO OFF

SETLOCAL

CALL settings.cmd

IF "%RA_RANDOM_NONCE%" NEQ "0" SET cl_nonce=-r
IF "%RA_USE_PLATFORM_SERVICES%" NEQ "0" SET cl_pse=-m
IF "%RA_LINKABLE%" NEQ "0" SET ra_linkable=-l

@ECHO ON

client.exe -s %RA_SPID% %cl_nonce% %cl_pse% %ra_linkable%

PAUSE
EXIT /B 0
