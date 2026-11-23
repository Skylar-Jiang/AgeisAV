@echo off
"%~dp0runtime\python.exe" -I -B -m aegisav.desktop verify
if errorlevel 1 pause
