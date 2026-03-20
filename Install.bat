@echo off
title Whitehat Security - Installer
echo.
echo   =============================================
echo    All-in-One Whitehat Security Tool - Setup
echo   =============================================
echo.
echo   Requesting administrator privileges...
echo.
powershell -Command "Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -Command \"[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; iwr https://raw.githubusercontent.com/xyzwebmaster/All-in-One-Whitehat-Security-Tool/master/Install.ps1 -OutFile $env:TEMP\WHS_Install.ps1 -UseBasicParsing; & $env:TEMP\WHS_Install.ps1\"' -Verb RunAs"
