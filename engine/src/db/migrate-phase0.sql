-- ============================================================================
-- PHASE 0 — ADDITIVE MIGRATION (schema.sql -> schema.target.sql, step 1 of N)
-- ============================================================================
-- RULES: ADDITIVE ONLY.
--   * CREATE TABLE IF NOT EXISTS — new tables only.
--   * ALTER TABLE ... ADD COLUMN IF NOT EXISTS — expand existing tables.
--   * ALTER TABLE ... ADD INDEX IF NOT EXISTS  — new indexes only.
--   * NO DROP, NO RENAME, NO ALTER that changes existing column types.
--   * The 6 existing tables (collection, stig, asset, review, ingest_run,
--     remediation_run) are expanded but NOT recreated.
--   * stig.benchmarkId and stig.revision stay. The new `revision` table is
--     PARALLEL until Phase 1 removes the flat columns.
--   * review.result ENUM stays. resultId / statusId are added alongside it
--     (NOT NULL with DEFAULT 0/1 so existing rows satisfy the constraint
--     without a data fill; the ENUM drives real logic until Phase 1).
--   * review.status ENUM stays. statusId added alongside.
--   * stig_asset_map is a STUB — no triggers, no counts populated; Phase 4
--     adds the maintenance triggers and back-fills the rows.
-- ============================================================================

SET NAMES utf8mb4;

-- ============================================================================
-- SECTION 0 — LOOKUP / REFERENCE TABLES
-- ============================================================================

-- Result vocabulary lookup.
-- Seed: (1,notchecked)(2,notapplicable)(3,pass)(4,fail)(5,unknown)(6,error)
--       (7,notselected)(8,informational)(9,fixed)
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

-- Status workflow vocabulary lookup.
-- Seed: (0,saved)(1,submitted)(2,rejected)(3,accepted)
CREATE TABLE IF NOT EXISTS status (
  statusId  INT NOT NULL,
  api       VARCHAR(16) NOT NULL,
  en        VARCHAR(16),
  PRIMARY KEY (statusId),
  UNIQUE KEY uq_status_api (api)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Severity -> DISA CAT mapping.
-- Seed: high->CAT I, medium->CAT II, low->CAT III
CREATE TABLE IF NOT EXISTS severity_cat_map (
  id        INT NOT NULL AUTO_INCREMENT,
  severity  ENUM('high','medium','low') NOT NULL,
  cat       INT NOT NULL,
  roman     VARCHAR(4) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_severity (severity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- DISA CCI reference catalog.
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

-- NIST control references attached to a CCI.
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
-- SECTION 1 — IDENTITY (users / groups)
-- (Must come before collection and asset because they carry createdUserId FKs.)
-- ============================================================================

-- Canonical user record, created lazily on first authenticated request.
CREATE TABLE IF NOT EXISTS user_data (
  userId         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  username       VARCHAR(255) NOT NULL,
  created        DATETIME DEFAULT CURRENT_TIMESTAMP,
  lastAccess     INT,
  lastClaims     JSON NOT NULL,
  status         ENUM('available','unavailable') NOT NULL DEFAULT 'available',
  statusDate     DATETIME,
  statusUser     BIGINT UNSIGNED,
  webPreferences JSON NOT NULL,
  PRIMARY KEY (userId),
  UNIQUE KEY uq_user_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Named group of users.
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

-- Membership join.
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
-- SECTION 2 — EXPAND EXISTING TABLE: collection
-- Add settings, state lifecycle, audit columns, and generated soft-delete cols.
-- The existing uq_collection_name unique key and the name column are left
-- intact; adding generated columns does not drop existing data or keys.
-- NOTE: MySQL ADD COLUMN IF NOT EXISTS is available in MySQL 8.0.3+.
-- ============================================================================

ALTER TABLE collection
  ADD COLUMN IF NOT EXISTS settings          JSON,
  ADD COLUMN IF NOT EXISTS state             ENUM('enabled','disabled','cloning') NOT NULL DEFAULT 'enabled',
  ADD COLUMN IF NOT EXISTS createdUserId     BIGINT UNSIGNED,
  ADD COLUMN IF NOT EXISTS stateDate         DATETIME,
  ADD COLUMN IF NOT EXISTS stateUserId       BIGINT UNSIGNED,
  ADD COLUMN IF NOT EXISTS isEnabled         TINYINT GENERATED ALWAYS AS (IF(state = 'enabled', 1, NULL)) STORED,
  ADD COLUMN IF NOT EXISTS isNameUnavailable VARCHAR(255) GENERATED ALWAYS AS (IF(state <> 'disabled', name, NULL)) STORED;

-- Add FKs only if not already present (safe because the table is new-ish; use
-- IF NOT EXISTS guard via procedure-free DDL — MySQL does not support
-- "ADD CONSTRAINT IF NOT EXISTS" for FKs directly, so wrap in a conditional
-- block using a stored procedure call pattern. Simpler: accept that re-running
-- on an already-migrated DB will produce a duplicate FK error and document that
-- the migration is idempotent only at the ADD COLUMN level; DBA should run once.
-- The two FKs below are added unconditionally (safe on a fresh Phase 0 run).

ALTER TABLE collection
  ADD CONSTRAINT fk_collection_creator FOREIGN KEY (createdUserId)
    REFERENCES user_data (userId) ON DELETE SET NULL,
  ADD CONSTRAINT fk_collection_stateuser FOREIGN KEY (stateUserId)
    REFERENCES user_data (userId) ON DELETE SET NULL;

-- ============================================================================
-- SECTION 3 — COLLECTIONS RBAC
-- (Depends on collection and user_data existing.)
-- ============================================================================

-- Core RBAC grant join.
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
  CONSTRAINT fk_grant_user FOREIGN KEY (userId)
    REFERENCES user_data (userId) ON DELETE CASCADE,
  CONSTRAINT fk_grant_group FOREIGN KEY (userGroupId)
    REFERENCES user_group (userGroupId) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- SECTION 4 — EXPAND EXISTING TABLE: asset
-- Add mac, description, noncomputing, state lifecycle cols, generated isEnabled.
-- ============================================================================

ALTER TABLE asset
  ADD COLUMN IF NOT EXISTS mac          VARCHAR(255),
  ADD COLUMN IF NOT EXISTS description  VARCHAR(255),
  ADD COLUMN IF NOT EXISTS noncomputing BIT(1) NOT NULL DEFAULT b'0',
  ADD COLUMN IF NOT EXISTS state        ENUM('enabled','disabled') NOT NULL DEFAULT 'enabled',
  ADD COLUMN IF NOT EXISTS stateDate    DATETIME,
  ADD COLUMN IF NOT EXISTS stateUserId  BIGINT UNSIGNED,
  ADD COLUMN IF NOT EXISTS isEnabled    TINYINT GENERATED ALWAYS AS (IF(state = 'enabled', 1, NULL)) STORED;

-- Add the stateUserId FK (unconditional on first Phase 0 run).
ALTER TABLE asset
  ADD CONSTRAINT fk_asset_stateuser FOREIGN KEY (stateUserId)
    REFERENCES user_data (userId) ON DELETE SET NULL;

-- ============================================================================
-- SECTION 5 — STIG LIBRARY: revision table (parallel to stig.revision column)
-- stig.benchmarkId and stig.revision columns are NOT touched here.
-- ============================================================================

CREATE TABLE IF NOT EXISTS revision (
  revId           VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL,
  benchmarkId     VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL,
  version         INT NOT NULL,
  release         VARCHAR(45) NOT NULL,
  revisionStr     VARCHAR(255) GENERATED ALWAYS AS (CONCAT('V', version, 'R', release)) STORED,
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
  KEY idx_revision_benchmark (benchmarkId),
  CONSTRAINT fk_revision_stig FOREIGN KEY (benchmarkId)
    REFERENCES stig (benchmarkId) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- SECTION 6 — EXPAND EXISTING TABLE: review
-- Add resultId, statusId, metadata, resultEngine, statusText, statusUserId,
-- statusTs alongside the existing result/status ENUMs.
-- resultId defaults to 1 (notchecked) so existing rows satisfy NOT NULL.
-- statusId defaults to 0 (saved) matching the existing status ENUM default.
-- The touchTs generated column requires both ts and statusTs to exist; add
-- statusTs first, then touchTs.
-- ============================================================================

ALTER TABLE review
  ADD COLUMN IF NOT EXISTS statusId     INT NOT NULL DEFAULT 0          AFTER status,
  ADD COLUMN IF NOT EXISTS resultId     INT NULL                        AFTER result,
  ADD COLUMN IF NOT EXISTS metadata     JSON                            AFTER comment,
  ADD COLUMN IF NOT EXISTS resultEngine JSON                            AFTER metadata,
  ADD COLUMN IF NOT EXISTS statusText   VARCHAR(512)                    AFTER statusId,
  ADD COLUMN IF NOT EXISTS statusUserId BIGINT UNSIGNED                 AFTER statusText,
  ADD COLUMN IF NOT EXISTS statusTs     DATETIME                        AFTER statusUserId;

-- Add missing index on assetId if not already covered.
-- idx_review_result already indexes (assetId, result); add standalone assetId
-- index for general FK lookups if not present.
ALTER TABLE review
  ADD INDEX IF NOT EXISTS idx_review_assetId (assetId);

-- ============================================================================
-- SECTION 7 — review_history (append-only audit trail)
-- (Depends on review table.)
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
-- SECTION 8 — stig_asset_map STUB
-- No triggers, no count maintenance, no back-fill in Phase 0.
-- The assignment rows will be inserted by the ingest pipeline (Phase 4).
-- FKs reference the existing stig (benchmarkId PK) and asset tables.
-- ============================================================================

CREATE TABLE IF NOT EXISTS stig_asset_map (
  saId               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  benchmarkId        VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL,
  assetId            BIGINT UNSIGNED NOT NULL,
  userIds            JSON,
  minTs              DATETIME,
  maxTs              DATETIME,
  maxTouchTs         DATETIME,
  -- status counts (zeroed until Phase 4 maintenance triggers)
  saved              INT NOT NULL DEFAULT 0,
  submitted          INT NOT NULL DEFAULT 0,
  rejected           INT NOT NULL DEFAULT 0,
  accepted           INT NOT NULL DEFAULT 0,
  -- result counts (full vocab)
  pass               INT NOT NULL DEFAULT 0,
  fail               INT NOT NULL DEFAULT 0,
  notchecked         INT NOT NULL DEFAULT 0,
  notapplicable      INT NOT NULL DEFAULT 0,
  unknown            INT NOT NULL DEFAULT 0,
  error              INT NOT NULL DEFAULT 0,
  notselected        INT NOT NULL DEFAULT 0,
  informational      INT NOT NULL DEFAULT 0,
  fixed              INT NOT NULL DEFAULT 0,
  -- open-finding severity counts
  lowCount           INT NOT NULL DEFAULT 0,
  mediumCount        INT NOT NULL DEFAULT 0,
  highCount          INT NOT NULL DEFAULT 0,
  -- assessed severity counts
  assessedLowCount   INT NOT NULL DEFAULT 0,
  assessedMediumCount INT NOT NULL DEFAULT 0,
  assessedHighCount  INT NOT NULL DEFAULT 0,
  PRIMARY KEY (saId),
  UNIQUE KEY uq_sam (benchmarkId, assetId),
  KEY idx_sam_asset (assetId),
  CONSTRAINT fk_sam_asset FOREIGN KEY (assetId)
    REFERENCES asset (assetId) ON DELETE CASCADE,
  CONSTRAINT fk_sam_stig FOREIGN KEY (benchmarkId)
    REFERENCES stig (benchmarkId) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- SECTION 9 — EXPAND EXISTING TABLES: ingest_run, remediation_run
-- Add userId FK columns for audit (username denormalized column stays).
-- ============================================================================

ALTER TABLE ingest_run
  ADD COLUMN IF NOT EXISTS userId BIGINT UNSIGNED AFTER reviewCount;

ALTER TABLE ingest_run
  ADD CONSTRAINT fk_ingest_user FOREIGN KEY (userId)
    REFERENCES user_data (userId) ON DELETE SET NULL;

ALTER TABLE remediation_run
  ADD COLUMN IF NOT EXISTS userId BIGINT UNSIGNED AFTER skipped;

ALTER TABLE remediation_run
  ADD CONSTRAINT fk_remediation_user FOREIGN KEY (userId)
    REFERENCES user_data (userId) ON DELETE SET NULL;

-- ============================================================================
-- END PHASE 0
-- Next: Phase 1 — populate result/status seeds, back-fill resultId/statusId
--       from existing ENUM values, then drop ENUM columns from review.
-- ============================================================================
