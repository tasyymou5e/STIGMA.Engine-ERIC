-- Migration 007: restructure stig table to single-column PK.
-- The original schema had PRIMARY KEY (benchmarkId, revision) because ERIC tracked
-- one revision per STIG inline. Phase 1 added a dedicated `revision` table.
-- This migration removes the redundant `revision` column and makes benchmarkId the sole PK.

DELIMITER $$

DROP PROCEDURE IF EXISTS _migrate_stig_007 $$
CREATE PROCEDURE _migrate_stig_007()
BEGIN
  -- Only run if the old `revision` column still exists on the stig table.
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'stig' AND column_name = 'revision'
  ) THEN
    -- 1. Deduplicate: keep only one row per benchmarkId (the one with the latest revision string).
    DELETE s1 FROM stig s1
    INNER JOIN stig s2
      ON s1.benchmarkId = s2.benchmarkId
    WHERE s1.revision < s2.revision;

    -- 2. Drop the composite primary key.
    ALTER TABLE stig DROP PRIMARY KEY;

    -- 3. Remove the revision column.
    ALTER TABLE stig DROP COLUMN revision;

    -- 4. Add the new single-column primary key.
    ALTER TABLE stig ADD PRIMARY KEY (benchmarkId);
  END IF;
END $$

DELIMITER ;
CALL _migrate_stig_007();
DROP PROCEDURE IF EXISTS _migrate_stig_007;
