CREATE TABLE IF NOT EXISTS eval_stig_job (
  jobId         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  collectionId  BIGINT UNSIGNED NOT NULL,
  status        ENUM('pending','running','completed','failed','cancelled') NOT NULL DEFAULT 'pending',
  targetHosts   JSON NOT NULL COMMENT 'Array of hostnames to scan',
  selectedStigs    JSON COMMENT 'Array of STIG short names, NULL = all applicable',
  outputPath       VARCHAR(512) DEFAULT 'C:\\Temp\\EvalSTIG-Results',
  winrmPort        SMALLINT UNSIGNED NOT NULL DEFAULT 5986 COMMENT 'WinRM port: 5986=HTTPS (default), 5985=HTTP',
  winrmUseSSL      TINYINT(1) NOT NULL DEFAULT 1 COMMENT '1=HTTPS (port 5986), 0=HTTP (port 5985)',
  winrmSkipCert    TINYINT(1) NOT NULL DEFAULT 1 COMMENT 'Skip WinRM cert validation (lab use)',
  importedCount INT NOT NULL DEFAULT 0 COMMENT 'CKLBs auto-imported into ERIC',
  createdBy     VARCHAR(255),
  startedAt     DATETIME,
  completedAt   DATETIME,
  errorMsg      TEXT,
  jobFile       VARCHAR(512) COMMENT 'Path to the .json job file on shared volume',
  PRIMARY KEY (jobId),
  KEY idx_esj_collection (collectionId),
  KEY idx_esj_status (status),
  CONSTRAINT fk_esj_collection FOREIGN KEY (collectionId)
    REFERENCES collection(collectionId) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
