@echo off

SET reldir=..\..\..\..\
SET spidfile=%reldir%plse-dev.spid

REM '====================================================================='
REM 'You shouldn't have to change anything below here

SET server=localhost
:argsbegin
if [%1]==[] goto argsend
	SET _arg=%1
	SET fc=%_arg:~0,1%
	SET opt=%arg:~1%

	IF NOT %fc%=="/" ( IF NOT %fc%==- CALL USAGE )
	IF [%opt%]=[] CALL USAGE
	if %opt%==s (
		SHIFT
		IF [%1]==[] CALL usage
		SET server=%1
	) ELSE ( if %1==z (
		SET server=
	))
SHIFT
goto argsbegin
:argsend

IF [%server%]=[] (
	client.exe -S %spidfile%
) ELSE (
	ncat.exe 
)