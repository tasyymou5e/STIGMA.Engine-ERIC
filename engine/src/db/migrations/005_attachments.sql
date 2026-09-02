-- Migration 005: Review attachments
-- Stores file evidence attached to reviews as MEDIUMBLOB in MySQL.
-- Cascades deletes from the parent review row.

CREATE TABLE IF NOT EXISTS review_attachment (
  attachmentId BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  reviewId     BIGINT UNSIGNED NOT NULL,
  filename     VARCHAR(255) NOT NULL,
  mimetype     VARCHAR(100) NOT NULL DEFAULT 'application/octet-stream',
  size         INT NOT NULL DEFAULT 0,
  content      MEDIUMBLOB NOT NULL,
  uploadedBy   VARCHAR(255),
  uploadedAt   DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (attachmentId),
  KEY idx_att_review (reviewId),
  CONSTRAINT fk_att_review FOREIGN KEY (reviewId) REFERENCES review (reviewId) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
