@echo off
chcp 65001 >nul
echo.
echo ========================================
echo    CHECKIN АГЕНТА
echo ========================================
echo.
echo без agent_id:
curl -s -X POST http://localhost:8080/api/v1/agent/checkin
echo.
echo.
echo с agent_id:
curl -s -X POST "http://localhost:8080/api/v1/agent/checkin?agent_id=test-agent-001"
echo.
echo ========================================
pause
