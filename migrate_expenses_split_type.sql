USE evenup;

-- Existing databases may have split_type as NOT NULL without a default.
-- Existing rows are normalized before the default is applied.
UPDATE expenses
SET split_type = 'equal'
WHERE split_type IS NULL OR split_type = '';

ALTER TABLE expenses
  MODIFY COLUMN split_type VARCHAR(20) NOT NULL DEFAULT 'equal';
