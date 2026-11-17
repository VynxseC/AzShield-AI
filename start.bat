@echo off
title AzShield IQ v6.1 Launcher
cd /d "%~dp0"

echo [*] Kohne prosesler temizlenir...
taskkill /F /IM python.exe >nul 2>&1

echo [*] AzShield Backend Server basladilir...
start "AzShield Backend (Port 8000)" cmd /k "python app.py"

timeout /t 2 /nobreak >nul

echo [*] Telegram SOC Bot aktiv edilir...
start "AzShield Telegram Bot" cmd /k "python telegram_bot.py"

timeout /t 2 /nobreak >nul
start http://127.0.0.1:8000
exit