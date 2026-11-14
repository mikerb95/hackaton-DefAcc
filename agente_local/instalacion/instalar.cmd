@echo off
rem Instalador del agente local del radar. Uso: doble clic.
rem Pide permiso de administrador y llama a instalar.ps1, que muestra el codigo de activacion.

net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0instalar.ps1"
