@echo off
chcp 65001 >nul
echo.
echo ========================================
echo    МЕТРИКИ PROMETHEUS
echo ========================================
echo.
curl -s http://localhost:8080/metrics
echo.
echo ========================================
pause
