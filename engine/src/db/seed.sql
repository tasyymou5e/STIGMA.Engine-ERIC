-- Phase 0 seed data — matches nuwcdivnpt/stig-manager 20-stigman-static.sql
-- INSERT IGNORE is idempotent (safe to re-run).

-- result: columns match migration Section 0 definition
--   resultId, api, ckl, cklb, abbr, en
INSERT IGNORE INTO result (resultId, api, ckl, cklb, abbr, en) VALUES
(1, 'notchecked',    'Not_Reviewed',   'not_reviewed',   'NR', 'Not checked'),
(2, 'notapplicable', 'Not_Applicable', 'not_applicable', 'NA', 'Not Applicable'),
(3, 'pass',          'NotAFinding',    'not_a_finding',  'NF', 'Not a Finding'),
(4, 'fail',          'Open',           'open',           'O',  'Open'),
(5, 'unknown',       'Not_Reviewed',   'not_reviewed',   'U',  'Unknown'),
(6, 'error',         'Not_Reviewed',   'not_reviewed',   'E',  'Error'),
(7, 'notselected',   'Not_Reviewed',   'not_reviewed',   'NS', 'Not selected'),
(8, 'informational', 'Not_Reviewed',   'not_reviewed',   'I',  'Informational'),
(9, 'fixed',         'NotAFinding',    'not_a_finding',  'NF', 'Fixed');

-- status: columns match migration Section 0 definition
--   statusId, api, en
INSERT IGNORE INTO status (statusId, api, en) VALUES
(0, 'saved',     'Saved'),
(1, 'submitted', 'Submitted'),
(2, 'rejected',  'Rejected'),
(3, 'accepted',  'Accepted');

-- severity_cat_map: columns match migration Section 0 definition
--   id (AUTO_INCREMENT, omit), severity, cat, roman
INSERT IGNORE INTO severity_cat_map (severity, cat, roman) VALUES
('high',   1, 'I'),
('medium', 2, 'II'),
('low',    3, 'III');
