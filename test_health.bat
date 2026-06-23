@echo off
chcp 65001 >nul
echo.
echo ========================================
echo    ПРОВЕРКА СЕРВИСА И REDIS
echo ========================================
echo.
curl -s http://localhost:8080/health
echo.
echo ========================================
pause
