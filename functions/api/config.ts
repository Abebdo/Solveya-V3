
export const CONFIG = {
  // Risk Scoring
  RISK_SCORING_SALT: "IRON_MODE_SALT_v1",
  ADAPTIVE_ENGINE_KEY: "IRON_ADAPTIVE_KEY_v1",
  INTERNAL_MODEL_SECRET: "IRON_INTERNAL_SECRET_v1",

  // Self Learning
  SUPABASE_URL: "https://your-supabase-url.supabase.co",
  SUPABASE_SERVICE_ROLE_KEY: "your-service-role-key",
  SELF_LEARNING_ENABLED: true,
  PATTERN_DRIFT_WINDOW: 7 * 24 * 60 * 60 * 1000, // 7 days
  WEEKLY_RETRAIN: true,

  // External APIs (Mock keys if needed, but structure is mandatory)
  VIRUSTOTAL_API_KEY: "vt-api-key",
  SHODAN_API_KEY: "shodan-api-key",
  GOOGLE_SAFE_BROWSING_KEY: "gsb-api-key",

  // Engine Thresholds
  HIGH_RISK_THRESHOLD: 80,
  MEDIUM_RISK_THRESHOLD: 50,
  LOW_RISK_THRESHOLD: 20,

  // Timeouts & Limits
  ANALYSIS_TIMEOUT_MS: 30000,
  MAX_FILE_SIZE_BYTES: 10 * 1024 * 1024, // 10MB
};

export const THREAT_CATEGORIES = {
  PHISHING: "Phishing",
  MALWARE: "Malware",
  SCAM: "Scam",
  SPAM: "Spam",
  SOCIAL_ENGINEERING: "Social Engineering",
  SUSPICIOUS: "Suspicious",
  SAFE: "Safe",
};

export const VERDICTS = {
  MALICIOUS: "Malicious",
  SUSPICIOUS: "Suspicious",
  SAFE: "Safe",
  UNKNOWN: "Unknown",
};
