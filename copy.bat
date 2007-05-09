@echo off
zip -u -1 ..\backup.zip *.* doc\*.txt 2>null
copy /y Release\ODbgScript.dll "%PROGRAMFILES%\_Dev\ODBG\plugins" 1>NUL