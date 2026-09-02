-- Migration 004: Phase 5 Admin
-- Adds collection_label, collection_label_asset_map, collection_grant_acl tables
-- and alters user_data to add taskId column.
-- Depends on: 000_init (collection, asset), 001_phase2 (collection_grant, user_data)

CREATE TABLE IF NOT EXISTS `collection_label` (
  `clId`         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `collectionId` BIGINT UNSIGNED NOT NULL,
  `name`         VARCHAR(36)     NOT NULL,
  `description`  VARCHAR(45)              DEFAULT NULL,
  `color`        VARCHAR(6)      NOT NULL DEFAULT '000000',
  `uuid`         BINARY(16)      NOT NULL,
  PRIMARY KEY (`clId`),
  UNIQUE KEY `uq_collection_label_name` (`collectionId`, `name`),
  CONSTRAINT `fk_cl_collection`
    FOREIGN KEY (`collectionId`) REFERENCES `collection` (`collectionId`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `collection_label_asset_map` (
  `claId`   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `assetId` BIGINT UNSIGNED NOT NULL,
  `clId`    BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (`claId`),
  UNIQUE KEY `uq_cla_asset_label` (`assetId`, `clId`),
  CONSTRAINT `fk_cla_asset`
    FOREIGN KEY (`assetId`) REFERENCES `asset` (`assetId`) ON DELETE CASCADE,
  CONSTRAINT `fk_cla_label`
    FOREIGN KEY (`clId`) REFERENCES `collection_label` (`clId`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `collection_grant_acl` (
  `cgAclId`      BIGINT UNSIGNED   NOT NULL AUTO_INCREMENT,
  `grantId`      BIGINT UNSIGNED   NOT NULL,
  `benchmarkId`  VARCHAR(255) COLLATE utf8mb4_0900_as_cs DEFAULT NULL,
  `assetId`      BIGINT UNSIGNED            DEFAULT NULL,
  `clId`         BIGINT UNSIGNED            DEFAULT NULL,
  `access`       ENUM('none','r','rw')      NOT NULL,
  `modifiedDate` DATETIME                   DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`cgAclId`),
  KEY `idx_cga_grantId` (`grantId`),
  CONSTRAINT `fk_cga_grant`
    FOREIGN KEY (`grantId`) REFERENCES `collection_grant` (`grantId`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

ALTER TABLE `user_data`
  ADD COLUMN `taskId` BIGINT UNSIGNED NULL DEFAULT NULL;
