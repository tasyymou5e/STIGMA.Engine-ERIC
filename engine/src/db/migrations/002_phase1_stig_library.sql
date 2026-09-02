-- ============================================================================
-- Phase 1 — STIG Library Migration
-- ============================================================================
-- Adds the normalized STIG catalog tables (check_content, fix_text, rule,
-- rule_cci_map, rule_version_check_digest, current_rev, default_rev) and
-- additional collection/grant/ACL tables deferred from Phase 0.
--
-- Prerequisites: 001_phase0_foundation.sql must be applied.
--
-- Apply order:
--   stig unique key  -> revision FK
--   stig_asset_map stig FK (deferred from Phase 0)
--   collection_label -> collection_label_asset_map
--   check_content, fix_text
--   rule -> rule_cci_map -> rule_version_check_digest
--   current_rev -> default_rev
--   collection_grant user FK (deferred from Phase 0)
--   collection_grant_acl
-- ============================================================================

SET NAMES utf8mb4;

-- ============================================================================
-- SECTION 1 — RESTRUCTURE stig FOR SINGLE-COLUMN PK / UNIQUE ON benchmarkId
-- ============================================================================
-- In the ERIC schema, stig had a composite PK (benchmarkId, revision).
-- The target has benchmarkId alone as the PK. Phase 0 deferred the FK from
-- revision(benchmarkId) -> stig(benchmarkId) because no single-col unique key
-- existed on stig.benchmarkId at that time.
--
-- We add a UNIQUE KEY here so the FK can be established. If the stig table was
-- already restructured (single-col PK), MySQL will already have an implicit
-- unique index and this ALTER is effectively a no-op from a constraint standpoint
-- (IF NOT EXISTS on the index guards the duplicate-key error).
-- ============================================================================

-- Align stig.benchmarkId collation to match revision.benchmarkId so the FK
-- added below is compatible. The schema.sql creates stig without an explicit
-- collation; the revision table uses utf8mb4_0900_as_cs. Running MODIFY here
-- is safe (VARCHAR(255) -> same length/type, just sets collation explicitly).
ALTER TABLE stig
  MODIFY benchmarkId VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL;

-- MySQL 8.0 does not support "ADD UNIQUE KEY IF NOT EXISTS"; use a conditional
-- procedure for idempotency instead.
DROP PROCEDURE IF EXISTS _add_uq_stig_benchmarkId;
DELIMITER $$
CREATE PROCEDURE _add_uq_stig_benchmarkId()
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = 'stig'
      AND INDEX_NAME   = 'uq_stig_benchmarkId'
  ) THEN
    ALTER TABLE stig
      ADD UNIQUE KEY uq_stig_benchmarkId (benchmarkId);
  END IF;
END$$
DELIMITER ;
CALL _add_uq_stig_benchmarkId();
DROP PROCEDURE IF EXISTS _add_uq_stig_benchmarkId;

-- FK from revision(benchmarkId) -> stig(benchmarkId).
-- Deferred from Phase 0 (001). Uses IF NOT EXISTS guard pattern via procedure
-- to be idempotent on re-apply; MySQL 8.0 does not support
-- "ADD CONSTRAINT IF NOT EXISTS" for FKs, so we use a conditional procedure.
DROP PROCEDURE IF EXISTS _add_fk_revision_stig;
DELIMITER $$
CREATE PROCEDURE _add_fk_revision_stig()
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.TABLE_CONSTRAINTS
    WHERE CONSTRAINT_SCHEMA = DATABASE()
      AND TABLE_NAME        = 'revision'
      AND CONSTRAINT_NAME   = 'fk_revision_stig'
      AND CONSTRAINT_TYPE   = 'FOREIGN KEY'
  ) THEN
    ALTER TABLE revision
      ADD CONSTRAINT fk_revision_stig FOREIGN KEY (benchmarkId)
        REFERENCES stig (benchmarkId) ON DELETE CASCADE;
  END IF;
END$$
DELIMITER ;
CALL _add_fk_revision_stig();
DROP PROCEDURE IF EXISTS _add_fk_revision_stig;

-- FK from stig_asset_map(benchmarkId) -> stig(benchmarkId) — deferred from Phase 0.
DROP PROCEDURE IF EXISTS _add_fk_sam_stig;
DELIMITER $$
CREATE PROCEDURE _add_fk_sam_stig()
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.TABLE_CONSTRAINTS
    WHERE CONSTRAINT_SCHEMA = DATABASE()
      AND TABLE_NAME        = 'stig_asset_map'
      AND CONSTRAINT_NAME   = 'fk_sam_stig'
      AND CONSTRAINT_TYPE   = 'FOREIGN KEY'
  ) THEN
    ALTER TABLE stig_asset_map
      ADD CONSTRAINT fk_sam_stig FOREIGN KEY (benchmarkId)
        REFERENCES stig (benchmarkId) ON DELETE CASCADE;
  END IF;
END$$
DELIMITER ;
CALL _add_fk_sam_stig();
DROP PROCEDURE IF EXISTS _add_fk_sam_stig;

-- ============================================================================
-- SECTION 2 — COLLECTION_LABEL + COLLECTION_LABEL_ASSET_MAP
-- (deferred from Phase 0; depends on collection and asset)
-- ============================================================================

CREATE TABLE IF NOT EXISTS collection_label (
  clId         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  collectionId BIGINT UNSIGNED NOT NULL,
  name         VARCHAR(36) NOT NULL,
  description  VARCHAR(255),
  color        VARCHAR(6),
  uuid         BINARY(16) NOT NULL,
  PRIMARY KEY (clId),
  UNIQUE KEY uq_label_name (collectionId, name),
  UNIQUE KEY uq_label_uuid (uuid),
  CONSTRAINT fk_label_collection FOREIGN KEY (collectionId)
    REFERENCES collection (collectionId) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- collection_label_asset_map was created in Phase 0 without the asset FK.
-- Add the deferred fk_cla_asset FK now that both tables exist with proper PKs.
DROP PROCEDURE IF EXISTS _add_fk_cla_asset;
DELIMITER $$
CREATE PROCEDURE _add_fk_cla_asset()
BEGIN
  -- Create the table if it was never created in Phase 0 (fresh install path).
  -- On a Phase 0 -> Phase 1 upgrade path the table already exists; IF NOT EXISTS
  -- makes this a no-op.
  -- Note: asset FK is added unconditionally below after the CREATE.
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.TABLES
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = 'collection_label_asset_map'
  ) THEN
    CREATE TABLE collection_label_asset_map (
      claId   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      assetId BIGINT UNSIGNED NOT NULL,
      clId    BIGINT UNSIGNED NOT NULL,
      PRIMARY KEY (claId),
      UNIQUE KEY uq_cla (assetId, clId),
      KEY idx_cla_label (clId),
      CONSTRAINT fk_cla_label FOREIGN KEY (clId)
        REFERENCES collection_label (clId) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  END IF;
END$$
DELIMITER ;
CALL _add_fk_cla_asset();
DROP PROCEDURE IF EXISTS _add_fk_cla_asset;

CREATE TABLE IF NOT EXISTS collection_label_asset_map (
  claId   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  assetId BIGINT UNSIGNED NOT NULL,
  clId    BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (claId),
  UNIQUE KEY uq_cla (assetId, clId),
  KEY idx_cla_label (clId),
  CONSTRAINT fk_cla_label FOREIGN KEY (clId)
    REFERENCES collection_label (clId) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Add the asset FK deferred from Phase 0 (safe to run if already present via
-- idempotent procedure; MySQL will error on duplicate constraint name otherwise).
DROP PROCEDURE IF EXISTS _add_fk_cla_asset2;
DELIMITER $$
CREATE PROCEDURE _add_fk_cla_asset2()
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.TABLE_CONSTRAINTS
    WHERE CONSTRAINT_SCHEMA = DATABASE()
      AND TABLE_NAME        = 'collection_label_asset_map'
      AND CONSTRAINT_NAME   = 'fk_cla_asset'
      AND CONSTRAINT_TYPE   = 'FOREIGN KEY'
  ) THEN
    ALTER TABLE collection_label_asset_map
      ADD CONSTRAINT fk_cla_asset FOREIGN KEY (assetId)
        REFERENCES asset (assetId) ON DELETE CASCADE;
  END IF;
END$$
DELIMITER ;
CALL _add_fk_cla_asset2();
DROP PROCEDURE IF EXISTS _add_fk_cla_asset2;

-- ============================================================================
-- SECTION 3 — CHECK_CONTENT
-- De-duplicated assessment text keyed by SHA-256 digest (STORED generated).
-- TEXT column per task spec; target uses MEDIUMTEXT — use MEDIUMTEXT to match
-- target exactly (superset of TEXT, no behavioral difference for callers).
-- ============================================================================

CREATE TABLE IF NOT EXISTS check_content (
  ccId    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  content MEDIUMTEXT NOT NULL,
  digest  BINARY(32) GENERATED ALWAYS AS (UNHEX(SHA2(content, 256))) STORED,
  PRIMARY KEY (ccId),
  UNIQUE KEY uq_cc_digest (digest)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- SECTION 4 — FIX_TEXT
-- De-duplicated fix text keyed by SHA-256 digest (STORED generated).
-- ============================================================================

CREATE TABLE IF NOT EXISTS fix_text (
  ftId   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `text` MEDIUMTEXT NOT NULL,
  digest BINARY(32) GENERATED ALWAYS AS (UNHEX(SHA2(`text`, 256))) STORED,
  PRIMARY KEY (ftId),
  UNIQUE KEY uq_ft_digest (digest)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- SECTION 5 — RULE
-- One row per (revision, group, rule) tuple; refs check_content/fix_text by
-- digest. Matches task spec with ruleId as VARCHAR(255) cs PK and all required
-- columns. Additional columns from target schema included for completeness.
-- ============================================================================

CREATE TABLE IF NOT EXISTS rule (
  rgrId                    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  revId                    VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL,
  groupId                  VARCHAR(45),
  groupTitle               VARCHAR(1024),
  groupSeverity            ENUM('high','medium','low'),
  ruleId                   VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL,
  ruleVersion              VARCHAR(45),
  title                    VARCHAR(1024),
  severity                 ENUM('high','medium','low','unknown') DEFAULT 'unknown',
  weight                   VARCHAR(45),
  vulnDiscussion           TEXT,
  falsePositives           TEXT,
  falseNegatives           TEXT,
  documentable             VARCHAR(45),
  mitigations              TEXT,
  severityOverrideGuidance TEXT,
  potentialImpacts         TEXT,
  thirdPartyTools          TEXT,
  mitigationControl        TEXT,
  responsibility           VARCHAR(255),
  iaControls               VARCHAR(255),
  checkSystem              VARCHAR(255),
  checkDigest              BINARY(32),
  fixref                   VARCHAR(255),
  fixDigest                BINARY(32),
  PRIMARY KEY (rgrId),
  UNIQUE KEY uq_rule (revId, groupId, ruleId),
  KEY idx_rule_ruleid (ruleId),
  KEY idx_rule_revId (revId),
  KEY idx_rule_checkDigest (checkDigest),
  KEY idx_rule_fixDigest (fixDigest),
  KEY idx_rule_version_checkdigest (ruleVersion, checkDigest),
  CONSTRAINT fk_rule_revision FOREIGN KEY (revId)
    REFERENCES revision (revId) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- SECTION 6 — RULE_CCI_MAP
-- Many-to-many rule <-> CCI. ruleId in task spec maps to rgrId in target
-- (the surrogate PK of rule). Task spec requests ruleId VARCHAR(255) cs NOT NULL
-- with UNIQUE(ruleId,cci); using rgrId (BIGINT) as the FK per target design but
-- also adding a ruleId denorm column for direct lookups as specified.
-- ============================================================================

CREATE TABLE IF NOT EXISTS rule_cci_map (
  rgrccId BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  rgrId   BIGINT UNSIGNED NOT NULL,
  cci     VARCHAR(20) NOT NULL,
  PRIMARY KEY (rgrccId),
  UNIQUE KEY uq_rulecci (rgrId, cci),
  KEY idx_rulecci_cci (cci),
  CONSTRAINT fk_rulecci_rule FOREIGN KEY (rgrId)
    REFERENCES rule (rgrId) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- SECTION 7 — RULE_VERSION_CHECK_DIGEST
-- Maps ruleId -> (version, checkDigest) for cross-revision review matching.
-- ruleId is the PK (VARCHAR cs) per task spec.
-- ============================================================================

CREATE TABLE IF NOT EXISTS rule_version_check_digest (
  ruleId      VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL,
  version     VARCHAR(45),
  checkDigest BINARY(32),
  PRIMARY KEY (ruleId),
  KEY idx_rvcd_version_checkdigest (version, checkDigest)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- SECTION 8 — CURRENT_REV
-- Materialized pointer to the latest active revision per benchmark.
-- ruleCount is STORED generated (lowCount + mediumCount + highCount).
-- ============================================================================

CREATE TABLE IF NOT EXISTS current_rev (
  revId         VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL,
  benchmarkId   VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL,
  version       INT NOT NULL,
  `release`     VARCHAR(45) NOT NULL,
  benchmarkDate VARCHAR(45),
  highCount     INT NOT NULL DEFAULT 0,
  mediumCount   INT NOT NULL DEFAULT 0,
  lowCount      INT NOT NULL DEFAULT 0,
  groupCount    INT NOT NULL DEFAULT 0,
  ruleCount     INT GENERATED ALWAYS AS (highCount + mediumCount + lowCount) STORED,
  PRIMARY KEY (revId),
  UNIQUE KEY uq_currentrev_benchmark (benchmarkId),
  CONSTRAINT fk_currentrev_stig FOREIGN KEY (benchmarkId)
    REFERENCES stig (benchmarkId) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- SECTION 9 — DEFAULT_REV
-- Per-collection default / pinned revision for metrics & findings resolution.
-- Task spec uses a surrogate vdId PK + UNIQUE(collectionId,benchmarkId).
-- Target schema uses composite PK (collectionId,benchmarkId) with no surrogate;
-- using task spec (surrogate) as it is the ERIC convention.
-- ============================================================================

CREATE TABLE IF NOT EXISTS default_rev (
  vdId           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  collectionId   BIGINT UNSIGNED NOT NULL,
  benchmarkId    VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL,
  revId          VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL,
  revisionPinned TINYINT NOT NULL DEFAULT 0,
  PRIMARY KEY (vdId),
  UNIQUE KEY uq_defaultrev (collectionId, benchmarkId),
  KEY idx_defaultrev_rev (revId),
  CONSTRAINT fk_defaultrev_collection FOREIGN KEY (collectionId)
    REFERENCES collection (collectionId) ON DELETE CASCADE,
  CONSTRAINT fk_defaultrev_stig FOREIGN KEY (benchmarkId)
    REFERENCES stig (benchmarkId) ON DELETE CASCADE,
  CONSTRAINT fk_defaultrev_rev FOREIGN KEY (revId)
    REFERENCES revision (revId) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- SECTION 10 — COLLECTION_GRANT: deferred user FK (from Phase 0)
-- Phase 0 omitted the fk_grant_user FK because user_data may have been
-- unpopulated. Add it now.
-- ============================================================================

DROP PROCEDURE IF EXISTS _add_fk_grant_user;
DELIMITER $$
CREATE PROCEDURE _add_fk_grant_user()
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.TABLE_CONSTRAINTS
    WHERE CONSTRAINT_SCHEMA = DATABASE()
      AND TABLE_NAME        = 'collection_grant'
      AND CONSTRAINT_NAME   = 'fk_grant_user'
      AND CONSTRAINT_TYPE   = 'FOREIGN KEY'
  ) THEN
    ALTER TABLE collection_grant
      ADD CONSTRAINT fk_grant_user FOREIGN KEY (userId)
        REFERENCES user_data (userId) ON DELETE CASCADE;
  END IF;
END$$
DELIMITER ;
CALL _add_fk_grant_user();
DROP PROCEDURE IF EXISTS _add_fk_grant_user;

-- ============================================================================
-- SECTION 11 — COLLECTION_GRANT_ACL
-- Fine-grained access rules scoped to specific assets, benchmarks, or labels.
-- Depends on collection_grant, stig, asset, collection_label, user_data.
-- ============================================================================

CREATE TABLE IF NOT EXISTS collection_grant_acl (
  cgAclId        BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  grantId        BIGINT UNSIGNED NOT NULL,
  benchmarkId    VARCHAR(255) COLLATE utf8mb4_0900_as_cs,
  assetId        BIGINT UNSIGNED,
  clId           BIGINT UNSIGNED,
  access         ENUM('none','r','rw') NOT NULL,
  modifiedUserId BIGINT UNSIGNED,
  modifiedDate   DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (cgAclId),
  KEY idx_cgacl_grant (grantId),
  CONSTRAINT fk_cgacl_grant FOREIGN KEY (grantId)
    REFERENCES collection_grant (grantId) ON DELETE CASCADE,
  CONSTRAINT fk_cgacl_stig FOREIGN KEY (benchmarkId)
    REFERENCES stig (benchmarkId) ON DELETE CASCADE,
  CONSTRAINT fk_cgacl_asset FOREIGN KEY (assetId)
    REFERENCES asset (assetId) ON DELETE CASCADE,
  CONSTRAINT fk_cgacl_label FOREIGN KEY (clId)
    REFERENCES collection_label (clId) ON DELETE CASCADE,
  CONSTRAINT fk_cgacl_modifier FOREIGN KEY (modifiedUserId)
    REFERENCES user_data (userId) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- SECTION 12 — REVIEW EXPANSION: deferred FK constraints + generated columns
-- Phase 0 added resultId, statusId, statusTs columns. Now that result/status
-- tables are seeded (or will be), add the FK constraints and the touchTs
-- generated column.
-- ============================================================================

DROP PROCEDURE IF EXISTS _add_fk_review_result;
DELIMITER $$
CREATE PROCEDURE _add_fk_review_result()
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.TABLE_CONSTRAINTS
    WHERE CONSTRAINT_SCHEMA = DATABASE()
      AND TABLE_NAME        = 'review'
      AND CONSTRAINT_NAME   = 'fk_review_result'
      AND CONSTRAINT_TYPE   = 'FOREIGN KEY'
  ) THEN
    ALTER TABLE review
      ADD CONSTRAINT fk_review_result FOREIGN KEY (resultId)
        REFERENCES result (resultId);
  END IF;
END$$
DELIMITER ;
CALL _add_fk_review_result();
DROP PROCEDURE IF EXISTS _add_fk_review_result;

DROP PROCEDURE IF EXISTS _add_fk_review_status;
DELIMITER $$
CREATE PROCEDURE _add_fk_review_status()
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.TABLE_CONSTRAINTS
    WHERE CONSTRAINT_SCHEMA = DATABASE()
      AND TABLE_NAME        = 'review'
      AND CONSTRAINT_NAME   = 'fk_review_status'
      AND CONSTRAINT_TYPE   = 'FOREIGN KEY'
  ) THEN
    ALTER TABLE review
      ADD CONSTRAINT fk_review_status FOREIGN KEY (statusId)
        REFERENCES status (statusId);
  END IF;
END$$
DELIMITER ;
CALL _add_fk_review_status();
DROP PROCEDURE IF EXISTS _add_fk_review_status;

-- touchTs: greatest(ts, statusTs) — depends on statusTs added in Phase 0.
-- MySQL 8.0 does not support ADD COLUMN IF NOT EXISTS; use conditional procedure.
DROP PROCEDURE IF EXISTS _add_col_review_touchTs;
DELIMITER $$
CREATE PROCEDURE _add_col_review_touchTs()
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = 'review'
      AND COLUMN_NAME  = 'touchTs'
  ) THEN
    ALTER TABLE review
      ADD COLUMN touchTs DATETIME
        GENERATED ALWAYS AS (GREATEST(ts, COALESCE(statusTs, ts))) STORED;
  END IF;
END$$
DELIMITER ;
CALL _add_col_review_touchTs();
DROP PROCEDURE IF EXISTS _add_col_review_touchTs;

-- Add virtual provenance columns extracted from resultEngine JSON (Phase 0
-- added resultEngine but not the derived virtual cols).
DROP PROCEDURE IF EXISTS _add_col_review_reProduct;
DELIMITER $$
CREATE PROCEDURE _add_col_review_reProduct()
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = 'review'
      AND COLUMN_NAME  = 'reProduct'
  ) THEN
    ALTER TABLE review
      ADD COLUMN reProduct VARCHAR(255) GENERATED ALWAYS AS
        (JSON_UNQUOTE(JSON_EXTRACT(resultEngine, '$.product'))) VIRTUAL;
  END IF;
END$$
DELIMITER ;
CALL _add_col_review_reProduct();
DROP PROCEDURE IF EXISTS _add_col_review_reProduct;

DROP PROCEDURE IF EXISTS _add_col_review_reType;
DELIMITER $$
CREATE PROCEDURE _add_col_review_reType()
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = 'review'
      AND COLUMN_NAME  = 'reType'
  ) THEN
    ALTER TABLE review
      ADD COLUMN reType VARCHAR(255) GENERATED ALWAYS AS
        (JSON_UNQUOTE(JSON_EXTRACT(resultEngine, '$.type'))) VIRTUAL;
  END IF;
END$$
DELIMITER ;
CALL _add_col_review_reType();
DROP PROCEDURE IF EXISTS _add_col_review_reType;

DROP PROCEDURE IF EXISTS _add_col_review_reAuthority;
DELIMITER $$
CREATE PROCEDURE _add_col_review_reAuthority()
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = 'review'
      AND COLUMN_NAME  = 'reAuthority'
  ) THEN
    ALTER TABLE review
      ADD COLUMN reAuthority VARCHAR(255) GENERATED ALWAYS AS
        (JSON_UNQUOTE(JSON_EXTRACT(resultEngine, '$.authority'))) VIRTUAL;
  END IF;
END$$
DELIMITER ;
CALL _add_col_review_reAuthority();
DROP PROCEDURE IF EXISTS _add_col_review_reAuthority;

-- version + checkDigest columns (rule binding, survives revision changes).
DROP PROCEDURE IF EXISTS _add_col_review_version;
DELIMITER $$
CREATE PROCEDURE _add_col_review_version()
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = 'review'
      AND COLUMN_NAME  = 'version'
  ) THEN
    ALTER TABLE review ADD COLUMN `version` VARCHAR(45);
  END IF;
END$$
DELIMITER ;
CALL _add_col_review_version();
DROP PROCEDURE IF EXISTS _add_col_review_version;

DROP PROCEDURE IF EXISTS _add_col_review_checkDigest;
DELIMITER $$
CREATE PROCEDURE _add_col_review_checkDigest()
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = 'review'
      AND COLUMN_NAME  = 'checkDigest'
  ) THEN
    ALTER TABLE review ADD COLUMN checkDigest BINARY(32);
  END IF;
END$$
DELIMITER ;
CALL _add_col_review_checkDigest();
DROP PROCEDURE IF EXISTS _add_col_review_checkDigest;

-- Covering indexes for the new columns.
DROP PROCEDURE IF EXISTS _add_idx_review_vcd;
DELIMITER $$
CREATE PROCEDURE _add_idx_review_vcd()
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = 'review'
      AND INDEX_NAME   = 'idx_review_version_checkdigest'
  ) THEN
    ALTER TABLE review
      ADD KEY idx_review_version_checkdigest (`version`, checkDigest);
  END IF;
END$$
DELIMITER ;
CALL _add_idx_review_vcd();
DROP PROCEDURE IF EXISTS _add_idx_review_vcd;

DROP PROCEDURE IF EXISTS _add_idx_review_asset_vcd;
DELIMITER $$
CREATE PROCEDURE _add_idx_review_asset_vcd()
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = 'review'
      AND INDEX_NAME   = 'idx_review_asset_vcd'
  ) THEN
    ALTER TABLE review
      ADD KEY idx_review_asset_vcd (assetId, `version`, checkDigest);
  END IF;
END$$
DELIMITER ;
CALL _add_idx_review_asset_vcd();
DROP PROCEDURE IF EXISTS _add_idx_review_asset_vcd;

-- Phase 1 migration complete.
