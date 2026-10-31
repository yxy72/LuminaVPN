@echo off
setlocal DisableDelayedExpansion
cd /d "%~dp0"
if errorlevel 1 exit /b 1
"%~dp0netlaunch.exe" up %*
set "netlaunch_exit=%errorlevel%"
echo.
echo Command finished with exit code %netlaunch_exit%.
pause
exit /b %netlaunch_exit%
