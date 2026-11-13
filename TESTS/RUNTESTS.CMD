@echo off
rem Build and run the host-side tests (no BBS needed).  Exit code 0 = pass.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0RUNTESTS.PS1"
exit /b %ERRORLEVEL%
