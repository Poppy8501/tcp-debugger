@echo off
setlocal
set "SCRIPT=%~dp0tcp_debugger.py"
set "PY="

if not exist "%SCRIPT%" (
    echo [ERROR] tcp_debugger.py not found in this folder.
    pause
    exit /b 1
)

rem Try candidate interpreters and keep the first one that really has tkinter.
call :try "D:\Python\python.exe"
if defined PY goto run
for /f "delims=" %%I in ('where python.exe 2^>nul') do (
    if not defined PY call :try "%%I"
)

if not defined PY (
    echo.
    echo [ERROR] No Python interpreter with tkinter was found.
    echo.
    echo Please install Python 3.8 or newer and make sure the
    echo "tcl/tk and IDLE" component is checked during setup.
    echo.
    pause
    exit /b 1
)

:run
set "PYW=%PY:python.exe=pythonw.exe%"
if not exist "%PYW%" set "PYW=%PY%"
start "" "%PYW%" "%SCRIPT%"
exit /b 0

:try
if defined PY exit /b
"%~1" -c "import tkinter" >nul 2>&1
if not errorlevel 1 set "PY=%~1"
exit /b
