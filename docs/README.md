# Threat Intelligence Processing Platform

> COMP-370 – Software Construction and Development | CCP Assignment  
> PAF-IAST, School of Computing Sciences  
> Batch: Fall 2023 | Instructor: Dr. Malik Nabeel Ahmed Awan


## Architecture Overview

```
External APIs                Kafka Topics              MySQL (CCP DB)
─────────────    ─────────────────────────────────    ─────────────
AbuseIPDB    ──► [raw-threat-data]  ──►  [extracted-iocs]  ──►  ioc_records
AlienVault   ──►                                            ◄──  (shared)
```

### Microservices Pipeline

| # | Service | Port | Role | Protocol |
|---|---------|------|------|----------|
| 1 | **Ingestion Service**  | 8081 | Fetches raw data from AbuseIPDB & AlienVault | REST (external) → Kafka |
| 2 | **Extraction Service** | 8082 | Parses JSON, extracts IPs & domains | Kafka consumer → Kafka producer |
| 3 | **Processing Service** | 8083 | Validates, de-duplicates, stores to MySQL | Kafka consumer + REST |
| 4 | **Ranking Service**    | 8084 | Queries AbuseIPDB `/check`, assigns severity | REST + Scheduler |
| 5 | **Database Service**   | 8085 | Dedicated read/query layer | REST |
| 6 | **Analytics Service**  | 8086 | Aggregated statistics & reporting | REST |

---

##  Data Flow

```
1. GET /api/v1/ingest/all
        │
        ▼
2. IngestionService fetches AbuseIPDB blacklist + AlienVault OTX data
        │
        ▼ (Kafka: raw-threat-data)
3. ExtractionService parses JSON
   ├── AbuseIPDB format: data[].ipAddress, data[].domain
   └── AlienVault format: results[].indicator (type: IPv4|domain)
        │
        ▼ (Kafka: extracted-iocs)
4. ProcessingService validates format, filters private IPs, de-duplicates
   └── Saves IocRecord with status=VALIDATED to MySQL
        │
        ▼ (REST: scheduled every 60s)
5. RankingService queries AbuseIPDB /check for each IP
   ├── Gets abuseConfidenceScore (0-100)
   ├── Assigns severity: LOW/MEDIUM/HIGH/CRITICAL
   └── Calls PATCH /api/v1/processing/iocs/{id}/severity
        │
        ▼
6. IocRecord updated: status=RANKED, severity, countryCode, reportCount
        │
        ▼ (REST query)
7. DatabaseService / AnalyticsService serve enriched data
```

---

##  Quick Start

### Prerequisites
- Java 17+
- Maven 3.8+
- Docker Desktop

### 1. Start Infrastructure
```bash
docker-compose up -d zookeeper kafka mysql kafka-setup
```

### 2. Start Services (individual terminals)
```bash
# Terminal 1 – Ingestion
cd services/ingestion-service/ingestion && mvnw spring-boot:run

# Terminal 2 – Extraction
cd services/extraction-service/extraction && mvnw spring-boot:run

# Terminal 3 – Processing
cd services/processing-service/processing && mvnw spring-boot:run

# Terminal 4 – Ranking
cd services/ranking-service/ranking && mvnw spring-boot:run

# Terminal 5 – Database
cd services/database-service/database && mvnw spring-boot:run

# Terminal 6 – Analytics
cd services/analytics-service/analytics && mvnw spring-boot:run
```

**Or on Windows:** double-click `start-all.bat`

### 3. Trigger Ingestion
```bash
# Ingest from both sources
curl http://localhost:8081/api/v1/ingest/all

# Ingest from AbuseIPDB only
curl http://localhost:8081/api/v1/ingest/abuseipdb

# Ingest from AlienVault only
curl http://localhost:8081/api/v1/ingest/alienvault
```

---

## 📡 REST API Reference

### Ingestion Service (8081)
| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/ingest/abuseipdb` | Fetch & stream AbuseIPDB blacklist |
| `GET /api/v1/ingest/alienvault` | Fetch & stream AlienVault OTX |
| `GET /api/v1/ingest/all` | Fetch from all sources |
| `GET /api/v1/ingest/health` | Health check |

### Processing Service (8083)
| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/processing/iocs` | All IOCs (sorted by severity) |
| `GET /api/v1/processing/iocs/{id}` | Get single IOC |
| `GET /api/v1/processing/iocs/status/{status}` | Filter by PENDING/VALIDATED/RANKED |
| `GET /api/v1/processing/iocs/type/{type}` | Filter by IP or DOMAIN |
| `GET /api/v1/processing/iocs/severity/{severity}` | Filter by severity level |
| `GET /api/v1/processing/iocs/source/{source}` | Filter by source |
| `GET /api/v1/processing/iocs/top?minScore=75` | Top threats |
| `PATCH /api/v1/processing/iocs/{id}/severity` | Update severity score |
| `GET /api/v1/processing/stats` | IOC statistics |

### Ranking Service (8084)
| Endpoint | Description |
|----------|-------------|
| `POST /api/v1/rank?iocId=1&value=1.2.3.4&type=IP` | Rank and update IOC |
| `GET /api/v1/rank/check/ip?ip=1.2.3.4` | Quick IP check |
| `GET /api/v1/rank/check/domain?domain=example.com` | Quick domain check |

### Database Service (8085)
| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/db/iocs` | All IOCs |
| `GET /api/v1/db/iocs/ranked` | Fully ranked IOCs |
| `GET /api/v1/db/iocs/top?minScore=75` | Critical threats |
| `GET /api/v1/db/iocs/country/{code}` | Filter by country |
| `GET /api/v1/db/iocs/recent?hours=24` | Recent IOCs |
| `GET /api/v1/db/stats` | Complete stats |

### Analytics Service (8086)
| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/analytics/summary` | Full dashboard summary |
| `GET /api/v1/analytics/by-severity` | Distribution by severity |
| `GET /api/v1/analytics/by-type` | IP vs DOMAIN breakdown |
| `GET /api/v1/analytics/by-source` | Source breakdown |
| `GET /api/v1/analytics/by-country?limit=10` | Top threat countries |
| `GET /api/v1/analytics/top-threats?limit=20` | Highest scoring IOCs |
| `GET /api/v1/analytics/trend?hours=24` | Recent activity trend |

---

## 🗄 Database Schema

```sql
Table: ioc_records
┌──────────────┬─────────────┬──────────────────────────────────┐
│ Column       │ Type        │ Description                      │
├──────────────┼─────────────┼──────────────────────────────────┤
│ id           │ BIGINT PK   │ Auto-increment primary key       │
│ value        │ VARCHAR(255)│ IP address or domain name        │
│ type         │ VARCHAR(20) │ IP | DOMAIN                      │
│ source       │ VARCHAR(50) │ AbuseIPDB | AlienVault           │
│ status       │ VARCHAR(20) │ PENDING|VALIDATED|RANKED|FAILED  │
│ severity_score│ INT        │ 0–100 (from AbuseIPDB /check)    │
│ severity     │ VARCHAR(20) │ LOW|MEDIUM|HIGH|CRITICAL         │
│ country_code │ VARCHAR(5)  │ ISO country code (IPs)           │
│ report_count │ INT         │ Number of abuse reports          │
│ created_at   │ DATETIME    │ Ingestion timestamp              │
│ updated_at   │ DATETIME    │ Last update timestamp            │
└──────────────┴─────────────┴──────────────────────────────────┘
```

---

## 🔑 API Keys Configuration

| Service | Property | Key Location |
|---------|----------|--------------|
| AbuseIPDB | `abuseipdb.api.key` | ingestion-service & ranking-service `application.properties` |
| AlienVault OTX | `alienvault.api.key` | ingestion-service `application.properties` |

---

## 📊 IOC Severity Scale

| Score | Severity | Color |
|-------|----------|-------|
| 0–25  | LOW      | 🟢    |
| 26–50 | MEDIUM   | 🟡    |
| 51–75 | HIGH     | 🟠    |
| 76–100| CRITICAL | 🔴    |

---

## 🛠 Technology Stack

- **Language**: Java 17
- **Framework**: Spring Boot 3.2.5
- **Message Broker**: Apache Kafka 7.4.0 (via Confluent Platform)
- **Database**: MySQL 8.0
- **ORM**: Spring Data JPA / Hibernate
- **Container**: Docker + Docker Compose
- **External APIs**: AbuseIPDB v2, AlienVault OTX v1

---

## 📁 Project Structure

```
Microservices/
├── docker-compose.yml              # Infrastructure (Kafka, MySQL)
├── start-all.bat                   # Windows startup script
├── infrastructure/
│   └── schema.sql                  # MySQL schema reference
└── services/
    ├── ingestion-service/          # Port 8081
    ├── extraction-service/         # Port 8082
    ├── processing-service/         # Port 8083
    ├── ranking-service/            # Port 8084
    ├── database-service/           # Port 8085
    └── analytics-service/          # Port 8086
```
