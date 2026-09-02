-- STIG Engine schema (MySQL 8). Minimal but complete domain for the API + engine.

CREATE TABLE IF NOT EXISTS collection (
  collectionId   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  name           VARCHAR(255) NOT NULL,
  description    TEXT,
  metadata       JSON,
  createdAt      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (collectionId),
  UNIQUE KEY uq_collection_name (name)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS stig (
  benchmarkId    VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL,
  title          VARCHAR(512),
  PRIMARY KEY (benchmarkId)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS asset (
  assetId        BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  collectionId   BIGINT UNSIGNED NOT NULL,
  name           VARCHAR(255) NOT NULL,
  fqdn           VARCHAR(255),
  ip             VARCHAR(64),
  metadata       JSON,
  createdAt      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (assetId),
  UNIQUE KEY uq_asset (collectionId, name),
  CONSTRAINT fk_asset_collection FOREIGN KEY (collectionId)
    REFERENCES collection (collectionId) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS review (
  reviewId       BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  assetId        BIGINT UNSIGNED NOT NULL,
  benchmarkId    VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL,
  ruleId         VARCHAR(128) COLLATE utf8mb4_0900_as_cs NOT NULL,
  groupId        VARCHAR(64),
  ruleVersion    VARCHAR(128),
  severity       ENUM('high','medium','low','unknown') NOT NULL DEFAULT 'unknown',
  title          VARCHAR(1024),
  result         ENUM('pass','fail','notapplicable','notchecked','informational') NOT NULL,
  detail         MEDIUMTEXT,
  comment        MEDIUMTEXT,
  status         ENUM('saved','submitted','accepted','rejected') NOT NULL DEFAULT 'saved',
  username       VARCHAR(255),
  ts             TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (reviewId),
  UNIQUE KEY uq_review (assetId, ruleId),
  KEY idx_review_result (assetId, result),
  CONSTRAINT fk_review_asset FOREIGN KEY (assetId)
    REFERENCES asset (assetId) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS ingest_run (
  ingestId       BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  collectionId   BIGINT UNSIGNED NOT NULL,
  assetId        BIGINT UNSIGNED,
  source         ENUM('ckl','cklb','xccdf') NOT NULL,
  benchmarkId    VARCHAR(255) COLLATE utf8mb4_0900_as_cs,
  reviewCount    INT NOT NULL DEFAULT 0,
  username       VARCHAR(255),
  ts             TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (ingestId),
  KEY idx_ingest_collection (collectionId)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS remediation_run (
  remediationId  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  assetId        BIGINT UNSIGNED NOT NULL,
  tool           VARCHAR(128) NOT NULL,          -- e.g. 'STIG-CKL-Remediation-Toolkit'
  applied        INT NOT NULL DEFAULT 0,
  manual         INT NOT NULL DEFAULT 0,
  skipped        INT NOT NULL DEFAULT 0,
  notes          TEXT,
  username       VARCHAR(255),
  ts             TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (remediationId),
  CONSTRAINT fk_remediation_asset FOREIGN KEY (assetId)
    REFERENCES asset (assetId) ON DELETE CASCADE
) ENGINE=InnoDB;
