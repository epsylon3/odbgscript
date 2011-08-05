@echo off
zip -u -1 ..\backup.zip *.* doc\*.txt 2>NUL

REM COMMENT THIS LINE IF YOU ARE ON WIN x64
SET ProgramFiles(x86)=%ProgramFiles%

SET ODBG_PATH=%ProgramFiles(x86)%\_Dev\ODBG

copy /y Release\ODbgScript.dll "%ODBG_PATH%\plugins\" 1>NUL
copy /y Doc\ODbgScript.txt "%ODBG_PATH%\plugins\" 1>NUL

rem copy /y Release\ODbgScript.dll "%ODBG_PATH%\plugins\" 1>NUL