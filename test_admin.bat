@echo off
chcp 65001 >nul
set TOKEN=впиши_свой_токен_сюда

echo.
echo ========================================
echo    ADMIN API
echo ========================================
echo.
echo обновление домена:
curl -s -X POST http://localhost:8080/api/v1/admin/update_domain ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "Content-Type: application/json" ^
  -d "{\"primary_domain\":\"example.com\",\"redirect_target\":\"https://mirror.example.com\"}"
echo.
echo.
echo ротация ключа:
curl -s -X POST http://localhost:8080/api/v1/admin/rotate_key ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "Content-Type: application/json" ^
  -d "{\"new_secret\":\"new-secret-minimum-32-characters!!\"}"
echo.
echo ========================================
pause
