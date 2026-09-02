-- Migration 010: STIG revision pinning per collection.
--
-- Allows a collection to be pinned to a specific STIG revision (benchmarkId +
-- revisionStr).  When no pin row exists the collection tracks the latest
-- revision via current_rev.

CREATE TABLE IF NOT EXISTS collection_stig_pin (
  collectionId  BIGINT UNSIGNED  NOT NULL,
  benchmarkId   VARCHAR(255)     NOT NULL COLLATE utf8mb4_0900_as_cs,
  revisionStr   VARCHAR(64)      NOT NULL COMMENT 'e.g. V2R1 — matches CONCAT(V,version,R,release)',
  pinnedAt      DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
  pinnedBy      VARCHAR(255),
  PRIMARY KEY (collectionId, benchmarkId),
  CONSTRAINT fk_csp_collection FOREIGN KEY (collectionId)
    REFERENCES collection (collectionId) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;
