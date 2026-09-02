-- ============================================================================
-- Phase 0 — Additive Foundation Migration
-- ============================================================================
-- Migrates the 6-table ERIC schema.sql toward schema.target.sql in a strictly
-- additive way. No existing tables, columns, indexes, or constraints are
-- dropped or renamed. All new tables use CREATE TABLE IF NOT EXISTS. All new
-- columns use ALTER TABLE ... ADD COLUMN (MySQL 8).
--
-- Apply order matters: lookup tables -> identity tables -> collection expansion
-- -> collection_grant -> asset expansion -> revision -> review expansion ->
-- review_history -> stig_asset_map -> ingest_run/remediation_run expansion.
-- ============================================================================

SET NAMES utf8mb4;

-- ============================================================================
-- SECTION 0 — LOOKUP / REFERENCE TABLES
-- (result, status, severity_cat_map, cci, cci_reference_map)
-- Created first so FKs from later tables can reference them. No existing ERIC
-- equivalents — these are wholly new. Seed data is deferred to a Phase 1
-- seed script; the review ENUM columns remain the authority until then.
-- ============================================================================

CREATE TABLE IF NOT EXISTS result (
  resultId  INT NOT NULL,
  api       VARCHAR(32)  NOT NULL,
  ckl       VARCHAR(32),
  cklb      VARCHAR(32),
  abbr      VARCHAR(2),
  en        VARCHAR(64),
  PRIMARY KEY (resultId),
  UNIQUE KEY uq_result_api (api)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS status (
  statusId  INT NOT NULL,
  api       VARCHAR(16) NOT NULL,
  en        VARCHAR(16),
  PRIMARY KEY (statusId),
  UNIQUE KEY uq_status_api (api)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS severity_cat_map (
  id        INT NOT NULL AUTO_INCREMENT,
  severity  ENUM('high','medium','low') NOT NULL,
  cat       INT NOT NULL,
  roman     VARCHAR(4) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_severity (severity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS cci (
  cci                 VARCHAR(20) NOT NULL,
  status              VARCHAR(32),
  publishdate         DATE,
  contributor         VARCHAR(255),
  type                VARCHAR(64),
  definition          TEXT,
  apAcronym           VARCHAR(64),
  implementation      TEXT,
  assessmentProcedure TEXT,
  PRIMARY KEY (cci)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS cci_reference_map (
  cciRefId      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  cci           VARCHAR(20) NOT NULL,
  creator       VARCHAR(255),
  title         VARCHAR(512),
  version       VARCHAR(45),
  location      VARCHAR(512),
  indexDisa     VARCHAR(255),
  textRefNist   VARCHAR(255),
  parentControl VARCHAR(45),
  PRIMARY KEY (cciRefId),
  KEY idx_ccirefmap_cci (cci),
  CONSTRAINT fk_ccirefmap_cci FOREIGN KEY (cci)
    REFERENCES cci (cci) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- SECTION 1 — IDENTITY TABLES
-- (user_data, user_group, user_group_user_map)
-- Must exist before the ALTER TABLE statements that add createdUserId /
-- stateUserId FK columns to collection and asset.
-- ============================================================================

CREATE TABLE IF NOT EXISTS user_data (
  userId         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  sub            VARCHAR(255) NOT NULL DEFAULT '',
  username       VARCHAR(255) NOT NULL,
  created        DATETIME DEFAULT CURRENT_TIMESTAMP,
  lastAccess     DATETIME,
  lastClaims     JSON NOT NULL,
  status         ENUM('available','unavailable') NOT NULL DEFAULT 'available',
  statusDate     DATETIME,
  statusUser     BIGINT UNSIGNED,
  webPreferences JSON NOT NULL,
  PRIMARY KEY (userId),
  UNIQUE KEY uq_user_sub (sub),
  UNIQUE KEY uq_user_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS user_group (
  userGroupId    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  name           VARCHAR(255) NOT NULL,
  description    VARCHAR(512),
  createdUserId  BIGINT UNSIGNED,
  createdDate    DATETIME DEFAULT CURRENT_TIMESTAMP,
  modifiedUserId BIGINT UNSIGNED,
  modifiedDate   DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (userGroupId),
  UNIQUE KEY uq_usergroup_name (name),
  CONSTRAINT fk_usergroup_creator FOREIGN KEY (createdUserId)
    REFERENCES user_data (userId) ON DELETE SET NULL,
  CONSTRAINT fk_usergroup_modifier FOREIGN KEY (modifiedUserId)
    REFERENCES user_data (userId) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS user_group_user_map (
  ugumId      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  userGroupId BIGINT UNSIGNED NOT NULL,
  userId      BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (ugumId),
  UNIQUE KEY uq_ugum (userGroupId, userId),
  CONSTRAINT fk_ugum_group FOREIGN KEY (userGroupId)
    REFERENCES user_group (userGroupId) ON DELETE CASCADE,
  CONSTRAINT fk_ugum_user FOREIGN KEY (userId)
    REFERENCES user_data (userId) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- SECTION 2 — COLLECTION EXPANSION
-- Existing columns kept as-is: collectionId, name, description, metadata,
-- createdAt, and UNIQUE KEY uq_collection_name(name).
-- The name-based unique key swap to isNameUnavailable is Phase 1.
-- Seven new columns added; two new FK constraints added unconditionally.
-- ============================================================================

ALTER TABLE collection
  ADD COLUMN settings JSON;

-- DEFAULT 'enabled' ensures existing rows are immediately valid.
ALTER TABLE collection
  ADD COLUMN state ENUM('enabled','disabled','cloning') NOT NULL DEFAULT 'enabled';

ALTER TABLE collection
  ADD COLUMN createdUserId BIGINT UNSIGNED;

ALTER TABLE collection
  ADD COLUMN stateDate DATETIME;

ALTER TABLE collection
  ADD COLUMN stateUserId BIGINT UNSIGNED;

-- STORED generated columns. isEnabled is 1 only for enabled rows (used by Phase 1
-- soft-delete-aware uniqueness key). isNameUnavailable is the Phase 1 uniqueness
-- column; adding it now is harmless — the key swap is deferred.
ALTER TABLE collection
  ADD COLUMN isEnabled TINYINT GENERATED ALWAYS AS (IF(state = 'enabled', 1, NULL)) STORED;

ALTER TABLE collection
  ADD COLUMN isNameUnavailable VARCHAR(255) GENERATED ALWAYS AS (IF(state <> 'disabled', name, NULL)) STORED;

-- FK constraints (unconditional — will error if already present; safe on fresh apply).
ALTER TABLE collection
  ADD CONSTRAINT fk_collection_creator FOREIGN KEY (createdUserId)
    REFERENCES user_data (userId) ON DELETE SET NULL;

ALTER TABLE collection
  ADD CONSTRAINT fk_collection_stateuser FOREIGN KEY (stateUserId)
    REFERENCES user_data (userId) ON DELETE SET NULL;

-- ============================================================================
-- SECTION 3 — COLLECTION_GRANT (new table)
-- Depends on collection, user_data, user_group.
-- Per spec: NO FK constraint added for collection_grant.userId (user_data may
-- be unpopulated). The userId -> user_data FK is deferred to Phase 1.
-- ============================================================================

CREATE TABLE IF NOT EXISTS collection_grant (
  grantId      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  collectionId BIGINT UNSIGNED NOT NULL,
  userId       BIGINT UNSIGNED,
  userGroupId  BIGINT UNSIGNED,
  roleId       INT NOT NULL,
  PRIMARY KEY (grantId),
  UNIQUE KEY uq_grant_user (userId, collectionId),
  UNIQUE KEY uq_grant_group (userGroupId, collectionId),
  KEY idx_grant_collection (collectionId),
  CONSTRAINT chk_grant_role CHECK (roleId BETWEEN 1 AND 4),
  CONSTRAINT chk_grant_target CHECK (
    (userId IS NOT NULL AND userGroupId IS NULL) OR
    (userId IS NULL AND userGroupId IS NOT NULL)
  ),
  CONSTRAINT fk_grant_collection FOREIGN KEY (collectionId)
    REFERENCES collection (collectionId) ON DELETE CASCADE,
  CONSTRAINT fk_grant_group FOREIGN KEY (userGroupId)
    REFERENCES user_group (userGroupId) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- SECTION 4 — ASSET EXPANSION
-- Existing columns kept: assetId, collectionId, name, fqdn, ip, metadata,
-- createdAt, UNIQUE KEY uq_asset(collectionId, name), fk_asset_collection.
-- The soft-delete-aware uniqueness key swap is Phase 1.
-- Six new columns added; stateUserId FK added unconditionally.
-- ============================================================================

ALTER TABLE asset
  ADD COLUMN mac VARCHAR(255);

ALTER TABLE asset
  ADD COLUMN description VARCHAR(255);

-- BIT DEFAULT b'0' for new rows; existing rows get 0.
ALTER TABLE asset
  ADD COLUMN noncomputing BIT(1) NOT NULL DEFAULT b'0';

-- DEFAULT 'enabled' ensures existing rows are immediately valid.
ALTER TABLE asset
  ADD COLUMN state ENUM('enabled','disabled') NOT NULL DEFAULT 'enabled';

ALTER TABLE asset
  ADD COLUMN stateDate DATETIME;

ALTER TABLE asset
  ADD COLUMN stateUserId BIGINT UNSIGNED;

-- STORED generated: 1 when enabled, NULL otherwise (allows Phase 1 uniqueness key).
ALTER TABLE asset
  ADD COLUMN isEnabled TINYINT GENERATED ALWAYS AS (IF(state = 'enabled', 1, NULL)) STORED;

ALTER TABLE asset
  ADD CONSTRAINT fk_asset_stateuser FOREIGN KEY (stateUserId)
    REFERENCES user_data (userId) ON DELETE SET NULL;

-- ============================================================================
-- SECTION 5 — REVISION TABLE (new, parallel to existing stig.revision column)
-- Points at the existing stig(benchmarkId) PK. The stig table is NOT altered
-- here; benchmarkId remains in stig until Phase 1 restructures the PK.
-- The revision table FK references stig(benchmarkId). Because the existing stig
-- PK is (benchmarkId, revision), we reference it on benchmarkId alone using the
-- implicit behavior — but stig does NOT have a single-column unique key on
-- benchmarkId in the ERIC schema. We therefore create the revision table with
-- benchmarkId as a plain KEY and defer the FK to Phase 1 after stig is
-- restructured.
-- ============================================================================

CREATE TABLE IF NOT EXISTS revision (
  revId           VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL,
  benchmarkId     VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL,
  version         INT NOT NULL,
  `release`         VARCHAR(45) NOT NULL,
  revisionStr     VARCHAR(255) GENERATED ALWAYS AS (CONCAT('V', version, 'R', `release`)) STORED,
  benchmarkDate   VARCHAR(45),
  benchmarkDateSql DATE,
  status          VARCHAR(45),
  statusDate      DATE,
  marking         VARCHAR(255),
  description     TEXT,
  groupCount      INT NOT NULL DEFAULT 0,
  checkCount      INT NOT NULL DEFAULT 0,
  fixCount        INT NOT NULL DEFAULT 0,
  lowCount        INT NOT NULL DEFAULT 0,
  mediumCount     INT NOT NULL DEFAULT 0,
  highCount       INT NOT NULL DEFAULT 0,
  ruleCount       INT GENERATED ALWAYS AS (lowCount + mediumCount + highCount) STORED,
  PRIMARY KEY (revId),
  KEY idx_revision_benchmark (benchmarkId)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- SECTION 6 — REVIEW EXPANSION
-- Existing columns kept: reviewId, assetId, benchmarkId, ruleId, groupId,
-- ruleVersion, severity, title, result (ENUM), detail, comment, status (ENUM),
-- username, ts, UNIQUE KEY uq_review, KEY idx_review_result, fk_review_asset.
-- Seven new columns added with ADD COLUMN IF NOT EXISTS.
-- statusId DEFAULT 0 matches 'saved' so existing rows are immediately valid.
-- resultId is NULL so existing rows need no back-fill (ENUM drives logic until
-- Phase 1 seeds result and back-fills this column).
-- statusTs is added as DATETIME NULL; the touchTs generated column that depends
-- on it is a Phase 1 addition (after NOT NULL status is confirmed).
-- An additional covering index on assetId alone guards against the existing
-- composite idx_review_result(assetId, result) being the only assetId index.
-- ============================================================================

ALTER TABLE review
  ADD COLUMN statusId INT NOT NULL DEFAULT 0;

ALTER TABLE review
  ADD COLUMN resultId INT NULL;

ALTER TABLE review
  ADD COLUMN metadata JSON;

ALTER TABLE review
  ADD COLUMN resultEngine JSON;

ALTER TABLE review
  ADD COLUMN statusText VARCHAR(512);

ALTER TABLE review
  ADD COLUMN statusUserId BIGINT UNSIGNED NULL;

ALTER TABLE review
  ADD COLUMN statusTs DATETIME NULL;

-- Guard: create idx_review_assetId only if it does not already exist.
CREATE INDEX idx_review_assetId ON review (assetId);

-- ============================================================================
-- SECTION 7 — REVIEW_HISTORY (new table)
-- Full definition from target. VIRTUAL generated columns (reProduct, reType,
-- reAuthority) and the stored touchTs are safe inside CREATE TABLE because they
-- reference columns defined in the same statement. FK points at existing review.
-- ============================================================================

CREATE TABLE IF NOT EXISTS review_history (
  historyId    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  reviewId     BIGINT UNSIGNED NOT NULL,
  resultId     INT NOT NULL,
  detail       MEDIUMTEXT,
  comment      MEDIUMTEXT,
  autoResult   BIT(1),
  ts           DATETIME,
  userId       BIGINT UNSIGNED,
  statusId     INT NOT NULL,
  statusText   VARCHAR(512),
  statusUserId BIGINT UNSIGNED,
  statusTs     DATETIME,
  touchTs      DATETIME,
  resultEngine JSON,
  reProduct    VARCHAR(255) GENERATED ALWAYS AS (JSON_UNQUOTE(JSON_EXTRACT(resultEngine, '$.product'))) VIRTUAL,
  reType       VARCHAR(255) GENERATED ALWAYS AS (JSON_UNQUOTE(JSON_EXTRACT(resultEngine, '$.type'))) VIRTUAL,
  reAuthority  VARCHAR(255) GENERATED ALWAYS AS (JSON_UNQUOTE(JSON_EXTRACT(resultEngine, '$.authority'))) VIRTUAL,
  ruleId       VARCHAR(255) COLLATE utf8mb4_0900_as_cs,
  PRIMARY KEY (historyId),
  KEY idx_revhist_review (reviewId),
  CONSTRAINT fk_revhist_review FOREIGN KEY (reviewId)
    REFERENCES review (reviewId) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- SECTION 8 — STIG_ASSET_MAP STUB (new table)
-- Full column list from target. All rollup counts default to 0. No triggers,
-- no back-fill. FK on benchmarkId references stig(benchmarkId). In the ERIC
-- schema the stig PK is (benchmarkId, revision), so there is no single-column
-- unique constraint on benchmarkId alone that a FK can reference. We therefore
-- create this table with benchmarkId as a plain KEY and defer the FK to Phase 1
-- after stig is restructured to a single-column PK.
-- FK on assetId references the existing asset(assetId) PK.
-- Phase 4 will add maintenance triggers and populate rows from review.
-- ============================================================================

CREATE TABLE IF NOT EXISTS stig_asset_map (
  saId                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  benchmarkId         VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL,
  assetId             BIGINT UNSIGNED NOT NULL,
  userIds             JSON,
  minTs               DATETIME,
  maxTs               DATETIME,
  maxTouchTs          DATETIME,
  saved               INT NOT NULL DEFAULT 0,
  submitted           INT NOT NULL DEFAULT 0,
  rejected            INT NOT NULL DEFAULT 0,
  accepted            INT NOT NULL DEFAULT 0,
  pass                INT NOT NULL DEFAULT 0,
  fail                INT NOT NULL DEFAULT 0,
  notchecked          INT NOT NULL DEFAULT 0,
  notapplicable       INT NOT NULL DEFAULT 0,
  unknown             INT NOT NULL DEFAULT 0,
  error               INT NOT NULL DEFAULT 0,
  notselected         INT NOT NULL DEFAULT 0,
  informational       INT NOT NULL DEFAULT 0,
  fixed               INT NOT NULL DEFAULT 0,
  lowCount            INT NOT NULL DEFAULT 0,
  mediumCount         INT NOT NULL DEFAULT 0,
  highCount           INT NOT NULL DEFAULT 0,
  assessedLowCount    INT NOT NULL DEFAULT 0,
  assessedMediumCount INT NOT NULL DEFAULT 0,
  assessedHighCount   INT NOT NULL DEFAULT 0,
  PRIMARY KEY (saId),
  UNIQUE KEY uq_sam (benchmarkId, assetId),
  KEY idx_sam_benchmarkId (benchmarkId),
  KEY idx_sam_asset (assetId),
  CONSTRAINT fk_sam_asset FOREIGN KEY (assetId)
    REFERENCES asset (assetId) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- SECTION 9 — INGEST_RUN EXPANSION
-- Existing columns kept: ingestId, collectionId, assetId, source, benchmarkId,
-- reviewCount, username, ts, KEY idx_ingest_collection.
-- One new column (userId) and its FK added.
-- ============================================================================

ALTER TABLE ingest_run
  ADD COLUMN userId BIGINT UNSIGNED;

ALTER TABLE ingest_run
  ADD CONSTRAINT fk_ingest_user FOREIGN KEY (userId)
    REFERENCES user_data (userId) ON DELETE SET NULL;

-- ============================================================================
-- SECTION 10 — REMEDIATION_RUN EXPANSION
-- Existing columns kept: remediationId, assetId, tool, applied, manual,
-- skipped, notes, username, ts, fk_remediation_asset.
-- One new column (userId) and its FK added.
-- ============================================================================

ALTER TABLE remediation_run
  ADD COLUMN userId BIGINT UNSIGNED;

ALTER TABLE remediation_run
  ADD CONSTRAINT fk_remediation_user FOREIGN KEY (userId)
    REFERENCES user_data (userId) ON DELETE SET NULL;

-- Phase 0 migration complete.
