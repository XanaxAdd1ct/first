@echo off
chcp 65001 >nul
echo.
echo ========================================
echo    ПРОВЕРКА БЕЗОПАСНОСТИ
echo ========================================
echo.
echo без токена (ожидаем 401):
curl -s -o nul -w "статус: %%{http_code}" ^
  -X POST http://localhost:8080/api/v1/admin/update_domain
echo.
echo.
echo неверный токен (ожидаем 403):
curl -s -o nul -w "статус: %%{http_code}" ^
  -X POST http://localhost:8080/api/v1/admin/update_domain ^
  -H "Authorization: Bearer непра вильный-токен"
echo.
echo ========================================
pause
