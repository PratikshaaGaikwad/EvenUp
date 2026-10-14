USE evenup;

-- Run once on an existing database.
ALTER TABLE expenses
  ADD COLUMN receipt_path VARCHAR(500) NULL AFTER split_type;

CREATE TABLE IF NOT EXISTS expense_items (
  id INT PRIMARY KEY AUTO_INCREMENT,
  expense_id INT NOT NULL,
  item_name VARCHAR(255) NOT NULL,
  amount DECIMAL(12, 2) NOT NULL,
  CONSTRAINT fk_items_expense
    FOREIGN KEY (expense_id) REFERENCES expenses(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS expense_item_shares (
  item_id INT NOT NULL,
  user_id INT NOT NULL,
  amount DECIMAL(12, 2) NOT NULL,
  PRIMARY KEY (item_id, user_id),
  CONSTRAINT fk_item_shares_item
    FOREIGN KEY (item_id) REFERENCES expense_items(id) ON DELETE CASCADE,
  CONSTRAINT fk_item_shares_user
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
