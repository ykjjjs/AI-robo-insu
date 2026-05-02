-- Users table with SSN hash, name, mobile, login credentials
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  pin TEXT NOT NULL,
  name TEXT NOT NULL,
  mobile TEXT NOT NULL,
  ssn_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- User prediction history (per-user, per-stage)
CREATE TABLE IF NOT EXISTS user_predictions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  stage TEXT NOT NULL,
  result_data TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_up_user ON user_predictions(user_id);
CREATE INDEX IF NOT EXISTS idx_up_stage ON user_predictions(user_id, stage);
