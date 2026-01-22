export interface ThreatLog {
  id: number;
  url: string;
  timestamp: string;
  riskScore: number;
  detectedPatterns: string; // JSON string
  verdict: string;
}

export interface DynamicPattern {
  id: number;
  patternType: 'keyword' | 'tld' | 'file_ext';
  value: string;
  riskWeight: number;
  confidence: number;
  lastUpdated: string;
}

export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS threat_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  url TEXT NOT NULL,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  riskScore INTEGER,
  detectedPatterns TEXT,
  verdict TEXT
);

CREATE TABLE IF NOT EXISTS dynamic_patterns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  patternType TEXT,
  value TEXT,
  riskWeight INTEGER,
  confidence REAL,
  lastUpdated DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_patterns_value ON dynamic_patterns(value);
`;
