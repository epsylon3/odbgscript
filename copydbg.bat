@echo off
zip -u -1 ..\backup.zip *.*

SET ProgramFiles_x86=%ProgramFiles%

SET ODBG_PATH=%ProgramFiles_x86%\_Dev\ODBG

copy /y Debug\ODbgScript.dll "%ODBG_PATH%\plugins\" 1>NUL
rem copy /y Debug\ODbgScript.dll "%ODBG_PATH%\plugins\" 1>NUL