@echo off
REM ============================================================
REM  Threat Intelligence Platform – Run All Tests
REM  Run from the root /Microservices directory
REM ============================================================

set ROOT=%~dp0
set PASS=0
set FAIL=0
set RESULTS=

REM ── Load environment variables from .env ──────────────────────
if exist "%ROOT%.env" (
    echo Loading secrets from .env...
    for /f "usebackq tokens=1,* delims==" %%A in ("%ROOT%.env") do (
        if not "%%A"=="" if not "%%A:~0,1%"=="#" (
            set "%%A=%%B"
        )
    )
    echo Secrets loaded.
) else (
    echo [WARNING] .env file not found. Tests requiring DB_PASSWORD may fail.
    echo Copy .env.example to .env and fill in your values.
    echo.
)

echo.
echo =========================================================
echo  Running Tests for All Microservices
echo  NOTE: Tests are mocked - Docker/Kafka/MySQL not needed
echo =========================================================

call :run_tests "Ingestion Service"   "services\ingestion-service\ingestion"
call :run_tests "Extraction Service"  "services\extraction-service\extraction"
call :run_tests "Processing Service"  "services\processing-service\processing"
call :run_tests "Ranking Service"     "services\ranking-service\ranking"
call :run_tests "Database Service"    "services\database-service\database"
call :run_tests "Analytics Service"   "services\analytics-service\analytics"
call :run_tests "API Gateway"         "services\api-gateway\api"

echo.
echo =========================================================
echo  FINAL RESULTS
echo =========================================================
echo  Passed : %PASS% / 7
echo  Failed : %FAIL% / 7
echo.
if %FAIL% == 0 (
    echo  ALL TESTS PASSED
) else (
    echo  SOME TESTS FAILED
    echo  Check: services\[name]\target\surefire-reports\
)
echo =========================================================
echo.
pause
goto :eof


:run_tests
set SERVICE_NAME=%~1
set SERVICE_DIR=%ROOT%%~2

echo.
echo ---------------------------------------------------------
echo  Testing: %SERVICE_NAME%
echo ---------------------------------------------------------

cd /d "%SERVICE_DIR%"
call mvnw test 2>&1

if %ERRORLEVEL% == 0 (
    set /a PASS+=1
    set "RESULTS=%RESULTS% [PASS] %SERVICE_NAME%"
    echo  [PASS] %SERVICE_NAME%
) else (
    set /a FAIL+=1
    set "RESULTS=%RESULTS% [FAIL] %SERVICE_NAME%"
    echo  [FAIL] %SERVICE_NAME%
    echo         See: %SERVICE_DIR%\target\surefire-reports\
)

cd /d "%ROOT%"
goto :eof
