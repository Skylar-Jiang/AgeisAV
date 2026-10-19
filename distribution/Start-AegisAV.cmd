@echo off
"%~dp0runtime\python.exe" -I -B -m aegisav.desktop start %*
if errorlevel 1 pause
