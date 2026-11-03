@echo off
setlocal
cd /d "%~dp0"
set "USB_RESULT=%~1"
if not defined USB_RESULT set /p "USB_RESULT=Result ZIP or PCAP path: "
set "USB_RESULT=%USB_RESULT:"=%"
set "USB_OUT=analysis_%RANDOM%_%RANDOM%"
py -3 -m usb_recovery analyze "%USB_RESULT%" --out "%USB_OUT%"
if errorlevel 1 goto failed
echo Result: %USB_OUT%\report.md
pause
exit /b 0
:failed
echo Analysis failed. Python 3.10+ required. See the error above.
pause
exit /b 1
