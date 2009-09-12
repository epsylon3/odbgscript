@echo off
zip -u -1 ..\backup.zip *.* doc\*.txt 2>NULL

copy /y Release\ODbgScript.dll "%ProgramFiles(x86)%\_Dev\ODBG\plugins" 1>NULL
rem copy /y Release\ODbgScript.dll "%PROGRAMFILES%\_Dev\ODBG\plugins" 1>NULL