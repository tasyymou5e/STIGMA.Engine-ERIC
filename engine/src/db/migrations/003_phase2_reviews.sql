-- Migration 003: Phase 2 review columns
-- Adds version, checkDigest, autoResult, userId, touchTs to review table,
-- backfills resultId from legacy result ENUM, adds touchTs index,
-- and adds settings JSON column to collection.

ALTER TABLE review ADD COLUMN version VARCHAR(45) NOT NULL DEFAULT '';

ALTER TABLE review ADD COLUMN checkDigest BINARY(32) NULL;

ALTER TABLE review ADD COLUMN autoResult BIT(1) NOT NULL DEFAULT 0;

ALTER TABLE review ADD COLUMN userId BIGINT UNSIGNED NULL;

ALTER TABLE review ADD COLUMN touchTs DATETIME GENERATED ALWAYS AS (GREATEST(ts, COALESCE(statusTs, ts))) STORED;

UPDATE review r
  JOIN result res ON res.api = r.result
  SET r.resultId = res.resultId
  WHERE r.resultId IS NULL;

ALTER TABLE review ADD KEY idx_review_touchTs (touchTs);

ALTER TABLE collection ADD COLUMN settings JSON NULL;
