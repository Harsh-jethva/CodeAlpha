@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
set "PORT=8765"

net session >nul 2>&1
if %errorlevel% neq 0 (
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath powershell.exe -Verb RunAs -ArgumentList @('-NoExit','-NoProfile','-ExecutionPolicy','Bypass','-File','%SCRIPT_DIR%start_packet_tracer.ps1','-Port','%PORT%')"
  exit /b
)

powershell -NoExit -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%start_packet_tracer.ps1" -Port %PORT%