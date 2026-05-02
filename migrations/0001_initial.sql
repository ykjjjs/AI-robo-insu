CREATE TABLE IF NOT EXISTS predictions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  model TEXT NOT NULL,
  features TEXT NOT NULL,
  probability REAL NOT NULL,
  risk_level TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_predictions_model ON predictions(model);
CREATE INDEX IF NOT EXISTS idx_predictions_created ON predictions(created_at DESC);
