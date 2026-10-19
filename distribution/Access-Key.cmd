@echo off
"%~dp0runtime\python.exe" -I -B -m aegisav.desktop key %*
if errorlevel 1 pause
