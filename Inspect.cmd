@echo off
setlocal
cd /d "%~dp0"
set "USB_EXE=%~1"
if not defined USB_EXE set /p "USB_EXE=EXE or DLL path: "
set "USB_EXE=%USB_EXE:"=%"
set "USB_OUT=static_%RANDOM%_%RANDOM%"
py -3 -m usb_recovery inspect-pe "%USB_EXE%" --out "%USB_OUT%"
if errorlevel 1 goto failed
echo Result: %USB_OUT%\pe_report.md
pause
exit /b 0
:failed
echo Inspection failed. Python 3.10+ required. See the error above.
pause
exit /b 1
