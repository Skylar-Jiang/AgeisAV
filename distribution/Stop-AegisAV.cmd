@echo off
"%~dp0runtime\python.exe" -I -B -m aegisav.desktop stop %*
if errorlevel 1 pause
