@echo off
chcp 65001 >nul
echo.
echo ========================================
echo    ТЕСТЫ БЕЗОПАСНОСТИ
echo ========================================
echo.

echo [1/3] UNIT ТЕСТЫ SECURITY MONITOR
echo ----------------------------------------
go test ./... -run TestSecurityMonitor -v
go test ./... -run TestOnAuthFailure -v
go test ./... -run TestOnRateLimit -v
go test ./... -run TestClearSuspicious -v
go test ./... -run TestListSuspicious -v
go test ./... -run TestCleanup -v
go test ./... -run TestSecurityMiddleware -v
echo.

echo [2/3] СИМУЛЯЦИЯ БРУТФОРСА
echo ----------------------------------------
echo шлём 10 запросов с неверным токеном...
for /L %%i in (1,1,10) do (
    curl -s -o nul -w "попытка %%i  статус: %%{http_code}\n" ^
    -X POST http://localhost:8080/api/v1/admin/update_domain ^
    -H "Authorization: Bearer неверный-токен" ^
    -H "Content-Type: application/json" ^
    -d "{\"primary_domain\":\"example.com\",\"redirect_target\":\"https://example.com\"}"
    echo.
)
echo.

echo [3/3] СИМУЛЯЦИЯ DDOS
echo ----------------------------------------
echo шлём 60 запросов быстро...
for /L %%i in (1,1,60) do (
    curl -s -o nul http://localhost:8080/health
)
echo готово  проверь логи в logs.json
echo.

echo ========================================
echo    ПРОВЕРЬ logs.json НА НАЛИЧИЕ:
echo    - POSSIBLE BRUTEFORCE DETECTED
echo    - POSSIBLE DDOS DETECTED
echo ========================================
pause
