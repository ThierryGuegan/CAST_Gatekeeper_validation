@echo off
cd /d "%~dp0"
rem Settings of YOUR environment live in run.local.bat, which is NOT committed (see .gitignore).
rem It only needs these lines (do not put the password in it unless you accept it sits in clear text on your disk):
rem   set CAST_REST_URL=http://<server>:<port>/<webservice>/rest
rem   set CAST_DOMAIN=<domain>
rem   set CAST_USER=<user>
rem   set CAST_APP=<application name>
if exist run.local.bat call run.local.bat
if "%CAST_REST_URL%"=="" goto missing
if "%CAST_DOMAIN%"=="" goto missing
if "%CAST_USER%"=="" goto missing
if "%CAST_APP%"=="" goto missing
if "%CAST_REST_PASSWORD%"=="" set /p CAST_REST_PASSWORD=Password for %CAST_USER%: 
python gatekeeper_validate.py --rest-url %CAST_REST_URL% --domain %CAST_DOMAIN% --user %CAST_USER% --app "%CAST_APP%" --rule-ids auto --no-true-positives --out report.csv %*
exit /b %errorlevel%
:missing
echo Create run.local.bat next to this file, with: set CAST_REST_URL=... / set CAST_DOMAIN=... / set CAST_USER=... / set CAST_APP=...
exit /b 1
