-- Application structured log table.
-- The engine writes every log entry here; the /op/logs API reads from here.
-- Auto-purge: a scheduled job (or the engine itself) deletes rows older than 14 days.

CREATE TABLE IF NOT EXISTS app_log (
  id         BIGINT UNSIGNED  NOT NULL AUTO_INCREMENT,
  ts         DATETIME(3)      NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  level      ENUM('debug','info','warn','error') NOT NULL DEFAULT 'info',
  category   VARCHAR(32)      NOT NULL DEFAULT 'system',
  msg        TEXT             NOT NULL,
  data_json  JSON,
  err_text   MEDIUMTEXT,
  user_id    VARCHAR(255),
  ms         INT UNSIGNED,
  PRIMARY KEY (id),
  KEY idx_al_ts       (ts),
  KEY idx_al_level    (level),
  KEY idx_al_category (category),
  KEY idx_al_ts_level (ts, level)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
