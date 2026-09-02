-- Migration 006: Review aging rule + review_history enhancements
-- Adds review_aging_rule table for collection-level aging configuration.
-- Also ensures review_history has the collectionId-join-able structure needed
-- for listCollectionReviewHistory (no schema changes needed to review_history
-- itself; the JOIN path goes through review → asset → collectionId).
-- Depends on: 000_init (collection, asset, review), 003_phase2_reviews (review_history)

CREATE TABLE IF NOT EXISTS `review_aging_rule` (
  `agingId`         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `collectionId`    BIGINT UNSIGNED NOT NULL,
  `ordinal`         SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  `enabled`         TINYINT(1) NOT NULL DEFAULT 1,
  `triggerInterval` SMALLINT UNSIGNED NOT NULL DEFAULT 365
                    COMMENT 'Days after triggerField before action fires',
  `triggerField`    ENUM('ts','statusTs','touchTs') NOT NULL DEFAULT 'ts'
                    COMMENT 'Which review timestamp column to measure age from',
  `triggerAction`   ENUM('delete','update') NOT NULL DEFAULT 'update'
                    COMMENT 'delete removes review row, update sets a field value',
  `updateField`     VARCHAR(64) NULL DEFAULT NULL
                    COMMENT 'Column to set when triggerAction=update (e.g. result, status)',
  `updateValue`     VARCHAR(128) NULL DEFAULT NULL
                    COMMENT 'Value to write into updateField',
  PRIMARY KEY (`agingId`),
  KEY `idx_rar_collection` (`collectionId`),
  UNIQUE KEY `uq_rar_collection_ordinal` (`collectionId`, `ordinal`),
  CONSTRAINT `fk_rar_collection`
    FOREIGN KEY (`collectionId`) REFERENCES `collection` (`collectionId`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
