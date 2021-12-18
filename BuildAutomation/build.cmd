@ECHO OFF

ECHO Initializing Qualys Log4jScanner Build Environment for Windows

REM Lets get this party started
SET BUILDDRIVE=%~d0
SET BUILDROOT=%~dps0
SET BUILDROOT=%BUILDROOT:\BUILDA~1\=%
 

REM
REM Set BUILDSYMSTORE is it has already been set by the build environment.
REM
REM qAgent's internal Jenkins cluster have set PATH_SYMSTORE to our own symbol store
REM which is seperate from the one we publish to with bamboo 
REM 
IF "%PATH_SYMSTORE%" == "" SET PATH_SYMSTORE=X:\build\qAgentSymbolStore
SET BUILDSYMSTORE=%PATH_SYMSTORE%

REM
REM Output should be like:
REM     1.2.17.0
REM
FOR /F usebackq^ tokens^=^3^ delims^=^,^"^  %%I IN (`TYPE "%BUILDROOT%\version.info"`) DO (
    SET VERSION=%%I
)

ECHO Product Version: %VERSION%

IF EXIST ..\build (
rd /s /q ..\build
    IF EXIST ..\build (
    ECHO
    ECHO One or more files or folders are in use by another process. 
    ECHO Close all files and folders contained within '..\build' before starting a build.
    ECHO
    GOTO END )
)


md ..\build

IF NOT EXIST ..\build (
ECHO Build location '..\build' was not found.
GOTO END
)


call "%VS140COMNTOOLS%"..\..\vc\bin\vcvars32.bat


ECHO Adding symbol store binaries to the search path
SET PATH=%PATH%;%BUILDROOT%\BuildAutomation\bin;

IF DEFINED JENKINS (
REM Logically #define JENKINS_BUILD
    ECHO Adding JENKINS_BUILD Preprocessor Definition
    set ExternalCPPBuildDefines=/DJENKINS_BUILD
) ELSE (
    ECHO Not adding JENKINS_BUILD Preprocessor Definition
)

REM 32-Bit Builds - BEGIN
REM 32-bit Release Build - BEGIN

set BUILD_TARGET=x86.release
set LOG_FILE=..\build\%BUILD_TARGET%.log
set BUILD_OUTPUT=..\build\x86\release\output
set PACKAGE_FILE=..\build\%BUILD_TARGET%.zip

ECHO Building - %BUILD_TARGET%
MSBuild ..\Log4jScanner.sln /m /nodeReuse:false /t:Clean,Rebuild /p:Configuration=Release,Platform=x86 >%LOG_FILE%
SET BUILD_STATUS=%ERRORLEVEL%

REM Sign executable binaries 
C:\qbin\sign.bat "%PACKAGE_OUTPUT%\Log4jScanner.exe"

rem Postbuild
xcopy /vy %BUILD_OUTPUT%\*.pdb %BUILD_OUTPUT%\symbols\ >>%LOG_FILE%
del /q %BUILD_OUTPUT%\*.pdb >>%LOG_FILE%
bin\7z.exe a %PACKAGE_FILE% %BUILD_OUTPUT%\* >>%LOG_FILE%
SET ARCHIVE_STATUS=%ERRORLEVEL%

SET /a STATUS=%BUILD_STATUS%+%ARCHIVE_STATUS%
IF %STATUS%==0 (
    ECHO Building completed successfully for %BUILD_TARGET%. See log for details: %LOG_FILE%
) ELSE (
    TYPE %LOG_FILE% | FINDSTR /si /c:"FAIL"
    ECHO Building failed for %BUILD_TARGET%. See log for details: %LOG_FILE%
    GOTO END
)

REM 32-bit Release Build - END

REM 64-Bit Builds - BEGIN
REM 64-bit Release Build - BEGIN

set BUILD_TARGET=x64.release
set LOG_FILE=..\build\%BUILD_TARGET%.log
set BUILD_OUTPUT=..\build\x64\release\output
set PACKAGE_FILE=..\build\%BUILD_TARGET%.zip

ECHO Building - %BUILD_TARGET%
MSBuild ..\Log4jScanner.sln /m /nodeReuse:false /t:Clean,Rebuild /p:Configuration=Release,Platform=x64 >%LOG_FILE%
SET BUILD_STATUS=%ERRORLEVEL%

REM Sign executable binaries 
C:\qbin\sign.bat "%PACKAGE_OUTPUT%\Log4jScanner.exe"

rem Postbuild
xcopy /vy %BUILD_OUTPUT%\*.pdb %BUILD_OUTPUT%\symbols\ >>%LOG_FILE%
del /q %BUILD_OUTPUT%\*.pdb >>%LOG_FILE%
bin\7z.exe a %PACKAGE_FILE% %BUILD_OUTPUT%\* >>%LOG_FILE%
SET ARCHIVE_STATUS=%ERRORLEVEL%

SET /a STATUS=%BUILD_STATUS%+%ARCHIVE_STATUS%
IF %STATUS%==0 (
    ECHO Building completed successfully for %BUILD_TARGET%. See log for details: %LOG_FILE%
) ELSE (
    TYPE %LOG_FILE% | FINDSTR /si /c:"FAIL"
    ECHO Building failed for %BUILD_TARGET%. See log for details: %LOG_FILE%
    GOTO END
)

REM 64-bit Release Build - END

REM 64-Bit Builds - END

set ExternalCPPBuildDefines=

exit /B 0

:END
exit /B 1
