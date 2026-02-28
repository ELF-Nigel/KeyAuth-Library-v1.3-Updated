@echo off
setlocal enabledelayedexpansion

REM sign.bat - code signing helper (requires installed cert + signtool)
REM Usage: sign.bat "path\to\binary.exe"

if "%~1"=="" (
  echo Usage: sign.bat "path\to\binary.exe"
  exit /b 1
)

set BIN=%~1
set SIGNTOOL="C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe"
set TIMESTAMP_URL=http://timestamp.digicert.com

if not exist %SIGNTOOL% (
  echo signtool not found at %SIGNTOOL%
  exit /b 1
)

REM Update these to match your cert (store + subject)
set CERT_STORE=My
set CERT_SUBJECT=YOUR COMPANY NAME

%SIGNTOOL% sign /fd SHA256 /a /sm /s %CERT_STORE% /n "%CERT_SUBJECT%" /tr %TIMESTAMP_URL% /td SHA256 "%BIN%"
if errorlevel 1 (
  echo Sign failed.
  exit /b 1
)

echo Signed %BIN%
exit /b 0
