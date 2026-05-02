-- ============================================================
--  Threat Intelligence Platform – MySQL Schema
--  Database: CCP
--  Created by: Processing Service (ddl-auto=update)
--  This script is for reference / manual setup only.
-- ============================================================

CREATE DATABASE IF NOT EXISTS CCP;
USE CCP;

-- ── IOC Records ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ioc_records (
    id              BIGINT       NOT NULL AUTO_INCREMENT,
    value           VARCHAR(255) NOT NULL,
    type            VARCHAR(20)  NOT NULL COMMENT 'IP | DOMAIN',
    source          VARCHAR(50)  NOT NULL COMMENT 'AbuseIPDB | AlienVault',
    status          VARCHAR(20)  NOT NULL DEFAULT 'PENDING'
                                 COMMENT 'PENDING | VALIDATED | RANKED | FAILED',
    severity_score  INT          NOT NULL DEFAULT 0 COMMENT '0-100',
    severity        VARCHAR(20)           COMMENT 'LOW | MEDIUM | HIGH | CRITICAL',
    country_code    VARCHAR(5),
    report_count    INT          NOT NULL DEFAULT 0,
    created_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    UNIQUE KEY uk_value_source (value, source),
    INDEX idx_type      (type),
    INDEX idx_status    (status),
    INDEX idx_severity  (severity),
    INDEX idx_source    (source),
    INDEX idx_score     (severity_score DESC),
    INDEX idx_created   (created_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── Sample verification query ─────────────────────────────────
-- SELECT type, severity, COUNT(*) as count
-- FROM ioc_records
-- WHERE status = 'RANKED'
-- GROUP BY type, severity
-- ORDER BY count DESC;
