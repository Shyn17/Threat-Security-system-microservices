@echo off
REM ============================================================
REM  Threat Intelligence Platform – Start All Services
REM  Run from the root /Microservices directory
REM ============================================================

REM ── Load environment variables from .env ──────────────────────
if exist .env (
    echo Loading secrets from .env...
    for /f "usebackq tokens=1,* delims==" %%A in (`findstr /v "^#" .env`) do (
        if not "%%A"=="" set "%%A=%%B"
    )
) else (
    echo [WARNING] .env file not found! Copy .env.example to .env and fill in your keys.
    echo.
)

echo.
echo =========================================================
echo  STEP 1: Starting Kafka + MySQL via Docker Compose
echo =========================================================
docker-compose up -d zookeeper kafka mysql kafka-setup

echo Waiting for Kafka broker to become healthy (this may take 60-90 seconds)...

:wait_kafka
docker inspect --format="{{.State.Health.Status}}" kafka 2>nul | findstr /i "healthy" >nul
if errorlevel 1 (
    timeout /t 5 /nobreak >nul
    echo   ... still waiting for Kafka broker...
    goto wait_kafka
)
echo [OK] Kafka broker is healthy.

echo Waiting for kafka-setup (topic creation) to complete...
:wait_topics
docker inspect --format="{{.State.Status}}" kafka-setup 2>nul | findstr /i "exited" >nul
if errorlevel 1 (
    timeout /t 3 /nobreak >nul
    echo   ... waiting for topics to be created...
    goto wait_topics
)
echo [OK] Kafka topics created.

echo Giving services an extra 5 seconds buffer...
timeout /t 5 /nobreak >nul

echo.
echo =========================================================
echo  STEP 2: Starting Microservices (each in new terminal)
echo =========================================================

REM Ingestion Service (port 8081)
start "Ingestion Service" cmd /k "cd services\ingestion-service\ingestion && mvnw spring-boot:run"

REM Extraction Service (port 8082)
start "Extraction Service" cmd /k "cd services\extraction-service\extraction && mvnw spring-boot:run"

REM Processing Service (port 8083)
start "Processing Service" cmd /k "cd services\processing-service\processing && mvnw spring-boot:run"

REM Ranking Service (port 8084)
start "Ranking Service" cmd /k "cd services\ranking-service\ranking && mvnw spring-boot:run"

REM Database Service (port 8085)
start "Database Service" cmd /k "cd services\database-service\database && mvnw spring-boot:run"

REM Analytics Service (port 8086)
start "Analytics Service" cmd /k "cd services\analytics-service\analytics && mvnw spring-boot:run"

REM API Gateway (port 8080)
start "API Gateway" cmd /k "cd services\api-gateway\api && mvnw spring-boot:run"

echo.
echo =========================================================
echo  All services starting...
echo.
echo  Service Ports:
echo    API Gateway: http://localhost:8080/gateway/health
echo    API Gateway: http://localhost:8080/gateway/routes
echo.
echo    Ingestion  : http://localhost:8081/api/v1/ingest/health
echo    Extraction : http://localhost:8082 (Kafka consumer)
echo    Processing : http://localhost:8083/api/v1/processing/health
echo    Ranking    : http://localhost:8084/api/v1/rank/health
echo    Database   : http://localhost:8085/api/v1/db/health
echo    Analytics  : http://localhost:8086/api/v1/analytics/health
echo.
echo  All routes also accessible via API Gateway on port 8080:
echo    curl http://localhost:8080/api/v1/ingest/all
echo    curl http://localhost:8080/api/v1/analytics/summary
echo =========================================================
