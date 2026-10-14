

"""MySQL database layer for EvenUp."""
import os
import mysql.connector

DATABASE_CONFIG = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("MYSQL_PORT", "3306")),
    "user": os.getenv("MYSQL_USER", "root"),
    "password": os.getenv("MYSQL_PASSWORD", "Pratiksha@14"),
    "database": os.getenv("MYSQL_DATABASE", "evenup"),
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(120) NOT NULL, handle VARCHAR(80) UNIQUE, email VARCHAR(255) NOT NULL UNIQUE, password_hash VARCHAR(255) NOT NULL, gender VARCHAR(40), bio TEXT, avatar_url VARCHAR(500), created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS groups_tbl (id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(160) NOT NULL, group_type VARCHAR(80) NOT NULL DEFAULT 'Other', currency CHAR(3) NOT NULL DEFAULT 'INR', description TEXT, created_by INT NOT NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, CONSTRAINT fk_groups_owner FOREIGN KEY (created_by) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS group_members (group_id INT NOT NULL, user_id INT NOT NULL, PRIMARY KEY (group_id, user_id), CONSTRAINT fk_members_group FOREIGN KEY (group_id) REFERENCES groups_tbl(id) ON DELETE CASCADE, CONSTRAINT fk_members_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS expenses (id INT PRIMARY KEY AUTO_INCREMENT, group_id INT NOT NULL, paid_by INT NOT NULL, description VARCHAR(255) NOT NULL, amount DECIMAL(12, 2) NOT NULL, category VARCHAR(80) NOT NULL DEFAULT 'Other', split_type VARCHAR(20) NOT NULL DEFAULT 'equal', receipt_path VARCHAR(500) NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, CONSTRAINT fk_expenses_group FOREIGN KEY (group_id) REFERENCES groups_tbl(id) ON DELETE CASCADE, CONSTRAINT fk_expenses_payer FOREIGN KEY (paid_by) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS expense_shares (expense_id INT NOT NULL, user_id INT NOT NULL, share_amount DECIMAL(12, 2) NOT NULL, PRIMARY KEY (expense_id, user_id), CONSTRAINT fk_shares_expense FOREIGN KEY (expense_id) REFERENCES expenses(id) ON DELETE CASCADE, CONSTRAINT fk_shares_user FOREIGN KEY (user_id) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS expense_items (id INT PRIMARY KEY AUTO_INCREMENT, expense_id INT NOT NULL, item_name VARCHAR(255) NOT NULL, amount DECIMAL(12, 2) NOT NULL, CONSTRAINT fk_items_expense FOREIGN KEY (expense_id) REFERENCES expenses(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS expense_item_shares (item_id INT NOT NULL, user_id INT NOT NULL, amount DECIMAL(12, 2) NOT NULL, PRIMARY KEY (item_id, user_id), CONSTRAINT fk_item_shares_item FOREIGN KEY (item_id) REFERENCES expense_items(id) ON DELETE CASCADE, CONSTRAINT fk_item_shares_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS group_messages (id INT PRIMARY KEY AUTO_INCREMENT, group_id INT NOT NULL, user_id INT NOT NULL, message TEXT NOT NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, CONSTRAINT fk_messages_group FOREIGN KEY (group_id) REFERENCES groups_tbl(id) ON DELETE CASCADE, CONSTRAINT fk_messages_user FOREIGN KEY (user_id) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS settlements (id INT PRIMARY KEY AUTO_INCREMENT, group_id INT NOT NULL, from_user_id INT NOT NULL, to_user_id INT NOT NULL, amount DECIMAL(12, 2) NOT NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, CONSTRAINT fk_settlements_group FOREIGN KEY (group_id) REFERENCES groups_tbl(id) ON DELETE CASCADE, CONSTRAINT fk_settlements_from FOREIGN KEY (from_user_id) REFERENCES users(id), CONSTRAINT fk_settlements_to FOREIGN KEY (to_user_id) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS contact_messages (id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(160) NOT NULL, email VARCHAR(255) NOT NULL, message TEXT NOT NULL, status VARCHAR(20) NOT NULL DEFAULT 'new', created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP);
"""

def configure_database(config):
    for key in DATABASE_CONFIG:
        env_key = "MYSQL_" + key.upper()
        if env_key in config:
            DATABASE_CONFIG[key] = config[env_key]

class Cursor:
    def __init__(self, cursor, dictionary=False): self._cursor, self.dictionary = cursor, dictionary
    def execute(self, query, params=None):
        self._cursor.execute(query, params or ())
        return self
    def fetchone(self):
        row = self._cursor.fetchone()
        if row is None or not self.dictionary:
            return row
        columns = [column[0] for column in self._cursor.description]
        return dict(zip(columns, row))
    def fetchall(self):
        rows = self._cursor.fetchall()
        if not self.dictionary:
            return rows
        columns = [column[0] for column in self._cursor.description]
        return [dict(zip(columns, row)) for row in rows]
    @property
    def lastrowid(self): return self._cursor.lastrowid
    def close(self): self._cursor.close()

class Connection:
    def __init__(self):
        self._connection = mysql.connector.connect(**DATABASE_CONFIG)
        schema_cursor = self._connection.cursor()
        for statement in SCHEMA.split(";"):
            statement = statement.strip()
            if statement:
                schema_cursor.execute(statement)
        # Upgrade databases created by older EvenUp versions without making
        # developers run a separate migration before saving an expense.
        for statement in (
            "ALTER TABLE expenses ADD COLUMN split_type VARCHAR(20) NOT NULL DEFAULT 'equal'",
            "ALTER TABLE expenses ADD COLUMN receipt_path VARCHAR(500) NULL",
        ):
            try:
                schema_cursor.execute(statement)
            except mysql.connector.Error as error:
                if error.errno not in (1060, 1061):
                    schema_cursor.close()
                    self._connection.close()
                    raise
        try:
            schema_cursor.execute(
                "ALTER TABLE expense_shares CHANGE COLUMN amount share_amount DECIMAL(12, 2) NOT NULL"
            )
        except mysql.connector.Error as error:
            # Existing MySQL installations may already use share_amount.
            if error.errno not in (1054, 1060):
                schema_cursor.close()
                self._connection.close()
                raise
        schema_cursor.close()
        self._connection.commit()
    def cursor(self, dictionary=False): return Cursor(self._connection.cursor(), dictionary)
    def commit(self): self._connection.commit()
    def close(self): self._connection.close()

def get_db_connection(): return Connection()
