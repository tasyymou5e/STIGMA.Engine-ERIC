-- Migration 008: Fix review.ruleId collation to match rule.ruleId (utf8mb4_0900_as_cs)
-- This resolves a collation mismatch that caused the DeleteUnmappedReviews job to fail
-- with "Illegal mix of collations" error on the LEFT JOIN review rv ... JOIN rule r.

ALTER TABLE review
  MODIFY COLUMN ruleId VARCHAR(128) COLLATE utf8mb4_0900_as_cs NOT NULL;

ALTER TABLE review_history
  MODIFY COLUMN ruleId VARCHAR(128) COLLATE utf8mb4_0900_as_cs NOT NULL;
