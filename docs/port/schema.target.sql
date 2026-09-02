-- ============================================================================
-- STIGMA.Engine (ERIC) — TARGET SCHEMA at parity with NUWCDIVNPT/stig-manager
-- ============================================================================
-- DESIGN ARTIFACT. Do NOT apply directly over engine/src/db/schema.sql.
-- This file is the destination state for the port; migrations should be cut
-- from the diff between the live schema.sql and this target.
--
-- Conventions (kept from ERIC, NOT copied verbatim from upstream):
--   * Surrogate ids are BIGINT UNSIGNED AUTO_INCREMENT (upstream uses INT).
--   * Timestamps are MySQL TIMESTAMP/DATETIME (upstream mixes datetime + epoch).
--   * MySQL 8, InnoDB, utf8mb4. benchmarkId/ruleId use a case-sensitive
--     collation (utf8mb4_0900_as_cs) so e.g. "RHEL_8_STIG" != "rhel_8_stig".
--   * Result/Status are modeled as LOOKUP TABLES (result, status) + an FK on
--     review, replacing ERIC's narrow ENUMs. This is required to carry the full
--     upstream vocabulary and CKL/CKLB mappings. Severity stays an ENUM.
--   * Soft-delete is modeled with a `state` ENUM + a STORED generated `isEnabled`
--     column folded into the uniqueness key (upstream pattern).
--
-- Table inventory vs upstream:
--   Kept/expanded from ERIC : collection, asset, review, ingest_run, remediation_run
--   Split                   : stig -> stig + revision (+ current_rev, default_rev)
--   Added (new to ERIC)     : collection_grant, collection_grant_acl,
--                             collection_label, collection_label_asset_map,
--                             user_data, user_group, user_group_user_map,
--                             result, status, severity_cat_map,
--                             revision, current_rev, default_rev,
--                             rule (rev_group_rule_map equiv), rule_cci_map,
--                             check_content, fix_text, rule_version_check_digest,
--                             cci, cci_reference_map,
--                             stig_asset_map (rollup), review_history
-- ============================================================================

SET NAMES utf8mb4;

-- ============================================================================
-- SECTION 0 — LOOKUP / REFERENCE TABLES (seeded, see 20-static seed)
-- ============================================================================

-- Result vocabulary. Replaces ERIC's ENUM('pass','fail','notapplicable',
-- 'notchecked','informational'). Full upstream set + CKL/CKLB/abbr/en mappings.
-- Seed: (1,notchecked)(2,notapplicable)(3,pass)(4,fail)(5,unknown)(6,error)
--       (7,notselected)(8,informational)(9,fixed). resultId=4 == fail (findings).
CREATE TABLE IF NOT EXISTS result (
  resultId  INT NOT NULL,
  api       VARCHAR(32)  NOT NULL,            -- canonical API name (pass, fail, ...)
  ckl       VARCHAR(32),                      -- CKL <STATUS> string
  cklb      VARCHAR(32),                      -- CKLB status string
  abbr      VARCHAR(2),                       -- short label (P, F, NA, ...)
  en        VARCHAR(64),                      -- English label
  PRIMARY KEY (resultId),
  UNIQUE KEY uq_result_api (api)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Status workflow vocabulary. Seed: (0,saved)(1,submitted)(2,rejected)(3,accepted).
CREATE TABLE IF NOT EXISTS status (
  statusId  INT NOT NULL,
  api       VARCHAR(16) NOT NULL,             -- saved/submitted/rejected/accepted
  en        VARCHAR(16),
  PRIMARY KEY (statusId),
  UNIQUE KEY uq_status_api (api)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Severity -> DISA CAT mapping. Seed: high->CAT I, medium->CAT II, low->CAT III.
CREATE TABLE IF NOT EXISTS severity_cat_map (
  id        INT NOT NULL AUTO_INCREMENT,
  severity  ENUM('high','medium','low') NOT NULL,
  cat       INT NOT NULL,                     -- 1,2,3
  roman     VARCHAR(4) NOT NULL,              -- I, II, III
  PRIMARY KEY (id),
  UNIQUE KEY uq_severity (severity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- DISA CCI reference catalog (loaded from the DISA CCI list, not per-import).
CREATE TABLE IF NOT EXISTS cci (
  cci                 VARCHAR(20) NOT NULL,
  status              VARCHAR(32),
  publishdate         DATE,
  contributor         VARCHAR(255),
  type                VARCHAR(64),
  definition          TEXT,
  apAcronym           VARCHAR(64),            -- needed for POA&M EMASS/MCCAST
  implementation      TEXT,
  assessmentProcedure TEXT,
  PRIMARY KEY (cci)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- NIST control references attached to a CCI. crm.parentControl -> POA&M control col.
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
-- ============================================================================

-- Canonical user record, created lazily on first authenticated request.
-- Replaces ERIC's stateless-token model; review/ingest/remediation username
-- columns are kept (denormalized) but new audit FKs reference user_data.userId.
CREATE TABLE IF NOT EXISTS user_data (
  userId         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  username       VARCHAR(255) NOT NULL,
  created        DATETIME DEFAULT CURRENT_TIMESTAMP,
  lastAccess     INT,                          -- epoch seconds, throttled update
  lastClaims     JSON NOT NULL,                -- whole decoded token payload
  status         ENUM('available','unavailable') NOT NULL DEFAULT 'available',
  statusDate     DATETIME,
  statusUser     BIGINT UNSIGNED,
  webPreferences JSON NOT NULL,                -- e.g. {"darkMode":true,"lastWhatsNew":"2000-01-01"}
  PRIMARY KEY (userId),
  UNIQUE KEY uq_user_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Named group of users that can receive a single collection_grant.
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

-- Membership join. Members inherit the group's collection grants.
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
-- SECTION 2 — COLLECTIONS + RBAC
-- ============================================================================

-- Expanded from ERIC's thin collection table. Adds settings, lifecycle state,
-- audit columns, and the generated soft-delete-aware uniqueness columns.
CREATE TABLE IF NOT EXISTS collection (
  collectionId      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  name              VARCHAR(255) NOT NULL,
  description       TEXT,
  settings          JSON NOT NULL,
  metadata          JSON NOT NULL,
  state             ENUM('enabled','disabled','cloning') NOT NULL DEFAULT 'enabled',
  createdUserId     BIGINT UNSIGNED,
  createdAt         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,   -- kept from ERIC
  stateDate         DATETIME,
  stateUserId       BIGINT UNSIGNED,
  -- Generated columns enforce soft-delete + state-aware name uniqueness
  isEnabled         TINYINT GENERATED ALWAYS AS (IF(state = 'enabled', 1, NULL)) STORED,
  isNameUnavailable VARCHAR(255) GENERATED ALWAYS AS (IF(state <> 'disabled', name, NULL)) STORED,
  PRIMARY KEY (collectionId),
  -- Disabled collections do not block name reuse
  UNIQUE KEY uq_collection_name (isNameUnavailable),
  CONSTRAINT fk_collection_creator FOREIGN KEY (createdUserId)
    REFERENCES user_data (userId) ON DELETE SET NULL,
  CONSTRAINT fk_collection_stateuser FOREIGN KEY (stateUserId)
    REFERENCES user_data (userId) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Core RBAC join. Grants a role to EITHER a user OR a user group on a collection.
-- roleId convention (NOT a lookup table upstream): 1=Restricted 2=Full 3=Manage 4=Owner.
CREATE TABLE IF NOT EXISTS collection_grant (
  grantId      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  collectionId BIGINT UNSIGNED NOT NULL,
  userId       BIGINT UNSIGNED,               -- exactly one of userId / userGroupId
  userGroupId  BIGINT UNSIGNED,
  roleId       INT NOT NULL,                  -- 1..4, CHECK below
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

-- Named/colored labels within a collection. Used for organization AND as ACL targets.
CREATE TABLE IF NOT EXISTS collection_label (
  clId         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  collectionId BIGINT UNSIGNED NOT NULL,
  name         VARCHAR(36) NOT NULL,
  description  VARCHAR(255),
  color        VARCHAR(6),                    -- hex without '#'
  uuid         BINARY(16) NOT NULL,
  PRIMARY KEY (clId),
  UNIQUE KEY uq_label_name (collectionId, name),
  UNIQUE KEY uq_label_uuid (uuid),
  CONSTRAINT fk_label_collection FOREIGN KEY (collectionId)
    REFERENCES collection (collectionId) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Many-to-many label <-> asset. Resolves which assets a label-scoped ACL covers.
-- (asset FK declared after asset table; see SECTION 3.)
CREATE TABLE IF NOT EXISTS collection_label_asset_map (
  claId   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  assetId BIGINT UNSIGNED NOT NULL,
  clId    BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (claId),
  UNIQUE KEY uq_cla (assetId, clId),
  KEY idx_cla_label (clId),
  CONSTRAINT fk_cla_label FOREIGN KEY (clId)
    REFERENCES collection_label (clId) ON DELETE CASCADE
  -- fk_cla_asset added in SECTION 3 once asset exists
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- SECTION 3 — ASSETS
-- ============================================================================

-- Expanded from ERIC's thin asset table. Adds mac, description, noncomputing,
-- soft-delete state + generated isEnabled, and state-aware uniqueness.
CREATE TABLE IF NOT EXISTS asset (
  assetId      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  collectionId BIGINT UNSIGNED NOT NULL,
  name         VARCHAR(255) NOT NULL,
  fqdn         VARCHAR(255),
  ip           VARCHAR(255),
  mac          VARCHAR(255),
  description  VARCHAR(255),
  noncomputing BIT(1) NOT NULL DEFAULT b'0',
  metadata     JSON NOT NULL,
  state        ENUM('enabled','disabled') NOT NULL DEFAULT 'enabled',
  stateDate    DATETIME,
  stateUserId  BIGINT UNSIGNED,
  createdAt    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,         -- kept from ERIC
  isEnabled    TINYINT GENERATED ALWAYS AS (IF(state = 'enabled', 1, NULL)) STORED,
  PRIMARY KEY (assetId),
  -- Soft-delete-aware uniqueness: disabled assets don't block name reuse
  UNIQUE KEY uq_asset (name, collectionId, isEnabled),
  KEY idx_asset_collection (collectionId),
  CONSTRAINT fk_asset_collection FOREIGN KEY (collectionId)
    REFERENCES collection (collectionId) ON DELETE CASCADE,
  CONSTRAINT fk_asset_stateuser FOREIGN KEY (stateUserId)
    REFERENCES user_data (userId) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Deferred FK from the label-asset map now that asset exists.
ALTER TABLE collection_label_asset_map
  ADD CONSTRAINT fk_cla_asset FOREIGN KEY (assetId)
    REFERENCES asset (assetId) ON DELETE CASCADE;

-- ============================================================================
-- SECTION 4 — STIG LIBRARY (catalog)
-- ============================================================================
-- ERIC's flat stig(benchmarkId,title,revision) is split into stig + revision and
-- the normalized rule/check/fix/cci catalog is added.

-- One row per distinct benchmark. Case-sensitive collation on benchmarkId.
CREATE TABLE IF NOT EXISTS stig (
  benchmarkId VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL,
  title       VARCHAR(512),
  PRIMARY KEY (benchmarkId)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- De-duplicated check (assessment) text keyed by SHA-256 digest.
CREATE TABLE IF NOT EXISTS check_content (
  ccId    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  content MEDIUMTEXT NOT NULL,
  digest  BINARY(32) GENERATED ALWAYS AS (UNHEX(SHA2(content, 256))) STORED,
  PRIMARY KEY (ccId),
  UNIQUE KEY uq_cc_digest (digest)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- De-duplicated fix text keyed by SHA-256 digest.
CREATE TABLE IF NOT EXISTS fix_text (
  ftId   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  text   MEDIUMTEXT NOT NULL,
  digest BINARY(32) GENERATED ALWAYS AS (UNHEX(SHA2(text, 256))) STORED,
  PRIMARY KEY (ftId),
  UNIQUE KEY uq_ft_digest (digest)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- One row per published revision of a benchmark. Holds precomputed counts that
-- supply the metrics "assessments" denominators.
CREATE TABLE IF NOT EXISTS revision (
  revId           VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL, -- <benchmarkId>-<version>-<release>
  benchmarkId     VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL,
  version         INT NOT NULL,
  release         VARCHAR(45) NOT NULL,
  revisionStr     VARCHAR(255) GENERATED ALWAYS AS (CONCAT('V', version, 'R', release)) STORED,
  benchmarkDate   VARCHAR(45),
  benchmarkDateSql DATE,
  status          VARCHAR(45),
  statusDate      DATE,
  marking         VARCHAR(255),
  description      TEXT,
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

-- Materialized pointer to the latest active revision per benchmark.
CREATE TABLE IF NOT EXISTS current_rev (
  revId       VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL,
  benchmarkId VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL,
  version     INT NOT NULL,
  release     VARCHAR(45) NOT NULL,
  benchmarkDate VARCHAR(45),
  status      VARCHAR(45),
  groupCount  INT NOT NULL DEFAULT 0,
  checkCount  INT NOT NULL DEFAULT 0,
  fixCount    INT NOT NULL DEFAULT 0,
  lowCount    INT NOT NULL DEFAULT 0,
  mediumCount INT NOT NULL DEFAULT 0,
  highCount   INT NOT NULL DEFAULT 0,
  ruleCount   INT GENERATED ALWAYS AS (lowCount + mediumCount + highCount) STORED,
  PRIMARY KEY (revId),
  UNIQUE KEY uq_currentrev_benchmark (benchmarkId),
  CONSTRAINT fk_currentrev_stig FOREIGN KEY (benchmarkId)
    REFERENCES stig (benchmarkId) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Per-collection default / pinned revision resolution for metrics & findings.
CREATE TABLE IF NOT EXISTS default_rev (
  collectionId   BIGINT UNSIGNED NOT NULL,
  benchmarkId    VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL,
  revId          VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL,
  revisionPinned TINYINT NOT NULL DEFAULT 0,
  PRIMARY KEY (collectionId, benchmarkId),
  KEY idx_defaultrev_rev (revId),
  CONSTRAINT fk_defaultrev_collection FOREIGN KEY (collectionId)
    REFERENCES collection (collectionId) ON DELETE CASCADE,
  CONSTRAINT fk_defaultrev_stig FOREIGN KEY (benchmarkId)
    REFERENCES stig (benchmarkId) ON DELETE CASCADE,
  CONSTRAINT fk_defaultrev_rev FOREIGN KEY (revId)
    REFERENCES revision (revId) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- rev_group_rule_map equivalent (named `rule` for ERIC simplicity). Every
-- (revision, group, rule) tuple with all rule/group metadata; references
-- check_content/fix_text by digest.
CREATE TABLE IF NOT EXISTS rule (
  rgrId            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  revId            VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL,
  groupId          VARCHAR(45),
  groupTitle       VARCHAR(1024),
  groupSeverity    ENUM('high','medium','low'),
  ruleId           VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL,
  version          VARCHAR(45),               -- STIGID
  title            VARCHAR(1024),
  severity         ENUM('high','medium','low'),
  weight           VARCHAR(45),
  vulnDiscussion   TEXT,
  falsePositives   TEXT,
  falseNegatives   TEXT,
  documentable     VARCHAR(45),
  mitigations      TEXT,
  severityOverrideGuidance TEXT,
  potentialImpacts TEXT,
  thirdPartyTools  TEXT,
  mitigationControl TEXT,
  responsibility   VARCHAR(255),
  iaControls       VARCHAR(255),
  checkSystem      VARCHAR(255),
  checkDigest      BINARY(32),
  fixref           VARCHAR(255),
  fixDigest        BINARY(32),
  PRIMARY KEY (rgrId),
  UNIQUE KEY uq_rule (revId, groupId, ruleId),
  KEY idx_rule_ruleid (ruleId),
  KEY idx_rule_version_checkdigest (version, checkDigest),
  CONSTRAINT fk_rule_revision FOREIGN KEY (revId)
    REFERENCES revision (revId) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Many-to-many rule <-> CCI (rev_group_rule_cci_map equivalent).
CREATE TABLE IF NOT EXISTS rule_cci_map (
  rgrccId BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  rgrId   BIGINT UNSIGNED NOT NULL,
  cci     VARCHAR(20) NOT NULL,
  PRIMARY KEY (rgrccId),
  UNIQUE KEY uq_rulecci (rgrId, cci),
  KEY idx_rulecci_cci (cci),
  CONSTRAINT fk_rulecci_rule FOREIGN KEY (rgrId)
    REFERENCES rule (rgrId) ON DELETE CASCADE
  -- cci is reference data; intentionally NOT FK-constrained so a rule can cite
  -- a CCI not yet present in the loaded reference list (matches upstream).
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Maps ruleId -> (version, checkDigest) so a review row keyed by version+
-- checkDigest can be matched across revisions and back to the rule catalog.
CREATE TABLE IF NOT EXISTS rule_version_check_digest (
  ruleId      VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL,
  version     VARCHAR(45),
  checkDigest BINARY(32),
  PRIMARY KEY (ruleId),
  KEY idx_rvcd_version_checkdigest (version, checkDigest)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- SECTION 5 — ASSET <-> STIG ASSIGNMENT + ROLLUP
-- ============================================================================

-- stig_asset_map: the central assignment join AND the materialized per-asset/
-- per-STIG rollup that metrics read directly. ENTIRELY ABSENT in ERIC.
-- Counts are maintained on ingest/review write (or recomputed in SQL).
CREATE TABLE IF NOT EXISTS stig_asset_map (
  saId               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  benchmarkId        VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL,
  assetId            BIGINT UNSIGNED NOT NULL,
  userIds            JSON,
  minTs              DATETIME,
  maxTs              DATETIME,
  maxTouchTs         DATETIME,
  -- status counts
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
-- SECTION 6 — REVIEWS + WORKFLOW + HISTORY
-- ============================================================================

-- Expanded from ERIC's review table. Result/status now FK into lookup tables
-- (full vocabulary). Adds workflow actor/timestamps, version+checkDigest rule
-- binding, autoResult, metadata JSON, resultEngine JSON + derived virtual cols,
-- and the generated touchTs. ERIC's denormalized benchmarkId/severity/title and
-- free-text username columns are kept for transitional compatibility.
CREATE TABLE IF NOT EXISTS review (
  reviewId     BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  assetId      BIGINT UNSIGNED NOT NULL,
  ruleId       VARCHAR(255) COLLATE utf8mb4_0900_as_cs NOT NULL,
  resultId     INT NOT NULL,                  -- FK result
  detail       MEDIUMTEXT,
  comment      MEDIUMTEXT,
  autoResult   BIT(1) NOT NULL DEFAULT b'0',
  ts           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  userId       BIGINT UNSIGNED,               -- author of last result edit
  username     VARCHAR(255),                  -- kept (denormalized, transitional)
  statusId     INT NOT NULL DEFAULT 0,        -- FK status
  statusText   VARCHAR(512),
  statusUserId BIGINT UNSIGNED,
  statusTs     DATETIME,
  metadata     JSON NOT NULL,
  resultEngine JSON,
  -- Provenance fields extracted from resultEngine JSON
  reProduct    VARCHAR(255) GENERATED ALWAYS AS (JSON_UNQUOTE(JSON_EXTRACT(resultEngine, '$.product'))) VIRTUAL,
  reType       VARCHAR(255) GENERATED ALWAYS AS (JSON_UNQUOTE(JSON_EXTRACT(resultEngine, '$.type'))) VIRTUAL,
  reAuthority  VARCHAR(255) GENERATED ALWAYS AS (JSON_UNQUOTE(JSON_EXTRACT(resultEngine, '$.authority'))) VIRTUAL,
  -- rule binding (survives rule revision changes that share check content)
  version      VARCHAR(45),
  checkDigest  BINARY(32),
  -- greatest of result-edit ts and status-change ts
  touchTs      DATETIME GENERATED ALWAYS AS (GREATEST(ts, COALESCE(statusTs, ts))) STORED,
  -- denormalized (transitional, populated from rule catalog)
  benchmarkId  VARCHAR(255) COLLATE utf8mb4_0900_as_cs,
  groupId      VARCHAR(64),
  ruleVersion  VARCHAR(128),
  severity     ENUM('high','medium','low','unknown') NOT NULL DEFAULT 'unknown',
  title        VARCHAR(1024),
  PRIMARY KEY (reviewId),
  UNIQUE KEY uq_review (assetId, ruleId),
  KEY idx_review_result (assetId, resultId),
  KEY idx_review_status (assetId, statusId),
  KEY idx_review_version_checkdigest (version, checkDigest),
  KEY idx_review_asset_vcd (assetId, version, checkDigest),
  CONSTRAINT fk_review_asset FOREIGN KEY (assetId)
    REFERENCES asset (assetId) ON DELETE CASCADE,
  CONSTRAINT fk_review_result FOREIGN KEY (resultId)
    REFERENCES result (resultId),
  CONSTRAINT fk_review_status FOREIGN KEY (statusId)
    REFERENCES status (statusId),
  CONSTRAINT fk_review_user FOREIGN KEY (userId)
    REFERENCES user_data (userId) ON DELETE SET NULL,
  CONSTRAINT fk_review_statususer FOREIGN KEY (statusUserId)
    REFERENCES user_data (userId) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Append-only audit trail of prior review states. A row is written on each update.
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
-- SECTION 7 — RBAC FINE-GRAINED ACL (depends on collection_grant, asset, stig, label)
-- ============================================================================

-- Fine-grained access rules attached to a grant (primarily Restricted/roleId=1),
-- scoping access to specific assets, benchmarks, or labels. Drives effective-ACL.
CREATE TABLE IF NOT EXISTS collection_grant_acl (
  cgAclId      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  grantId      BIGINT UNSIGNED NOT NULL,
  benchmarkId  VARCHAR(255) COLLATE utf8mb4_0900_as_cs,
  assetId      BIGINT UNSIGNED,
  clId         BIGINT UNSIGNED,
  access       ENUM('none','r','rw') NOT NULL,
  modifiedUserId BIGINT UNSIGNED,
  modifiedDate DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
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
-- SECTION 8 — ENGINE AUDIT TABLES (kept from ERIC, lightly extended)
-- ============================================================================

-- Records each checklist/benchmark ingest run. Extended with a userId audit FK.
CREATE TABLE IF NOT EXISTS ingest_run (
  ingestId     BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  collectionId BIGINT UNSIGNED NOT NULL,
  assetId      BIGINT UNSIGNED,
  source       ENUM('ckl','cklb','xccdf') NOT NULL,
  benchmarkId  VARCHAR(255) COLLATE utf8mb4_0900_as_cs,
  reviewCount  INT NOT NULL DEFAULT 0,
  userId       BIGINT UNSIGNED,
  username     VARCHAR(255),
  ts           TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (ingestId),
  KEY idx_ingest_collection (collectionId),
  CONSTRAINT fk_ingest_user FOREIGN KEY (userId)
    REFERENCES user_data (userId) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Records automated/manual remediation runs against an asset. Kept from ERIC.
CREATE TABLE IF NOT EXISTS remediation_run (
  remediationId BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  assetId       BIGINT UNSIGNED NOT NULL,
  tool          VARCHAR(128) NOT NULL,
  applied       INT NOT NULL DEFAULT 0,
  manual        INT NOT NULL DEFAULT 0,
  skipped       INT NOT NULL DEFAULT 0,
  notes         TEXT,
  userId        BIGINT UNSIGNED,
  username      VARCHAR(255),
  ts            TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (remediationId),
  KEY idx_remediation_asset (assetId),
  CONSTRAINT fk_remediation_asset FOREIGN KEY (assetId)
    REFERENCES asset (assetId) ON DELETE CASCADE,
  CONSTRAINT fk_remediation_user FOREIGN KEY (userId)
    REFERENCES user_data (userId) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- SEED (reference data) — informational; implement in a separate seed script.
-- ============================================================================
-- INSERT IGNORE INTO result (resultId,api,ckl,cklb,abbr,en) VALUES
--   (1,'notchecked','Not_Reviewed','not_reviewed','NR','Not Checked'),
--   (2,'notapplicable','Not_Applicable','not_applicable','NA','Not Applicable'),
--   (3,'pass','NotAFinding','not_a_finding','NF','Pass'),
--   (4,'fail','Open','open','O','Fail'),
--   (5,'unknown',NULL,NULL,'U','Unknown'),
--   (6,'error',NULL,NULL,'E','Error'),
--   (7,'notselected',NULL,NULL,'NS','Not Selected'),
--   (8,'informational','Not_Reviewed','not_reviewed','I','Informational'),
--   (9,'fixed',NULL,NULL,'FX','Fixed');
-- INSERT IGNORE INTO status (statusId,api,en) VALUES
--   (0,'saved','saved'),(1,'submitted','submitted'),
--   (2,'rejected','rejected'),(3,'accepted','accepted');
-- INSERT IGNORE INTO severity_cat_map (severity,cat,roman) VALUES
--   ('high',1,'I'),('medium',2,'II'),('low',3,'III');
-- CCI catalog (cci, cci_reference_map) loaded from the DISA U_CCI_List XML.
-- ============================================================================
