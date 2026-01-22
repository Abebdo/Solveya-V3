import { DynamicPattern, ThreatLog } from './db-schema';

export class AdaptiveEngine {
  private db: any;

  constructor(db: any) {
    this.db = db;
  }

  // --------------------------------------------------------------------------
  // A) DATA COLLECTION
  // --------------------------------------------------------------------------
  async logAnalysis(url: string, result: any) {
    if (!this.db) return; // Fallback if no DB
    try {
      await this.db.prepare(
        `INSERT INTO threat_logs (url, riskScore, detectedPatterns, verdict) VALUES (?, ?, ?, ?)`
      ).bind(
        url, 
        result.riskScore, 
        JSON.stringify(result.detectedPatterns || []), 
        result.verdict
      ).run();
    } catch (e) {
      console.error("Failed to log threat:", e);
    }
  }

  // --------------------------------------------------------------------------
  // B & C) SELF-LEARNING & DRIFT DETECTION
  // --------------------------------------------------------------------------
  // In a real worker, this might be a Scheduled Event (cron). 
  // Here we expose it as a function that *could* be called periodically.
  async retrainPatterns() {
    if (!this.db) return;

    // 1. Fetch recent high-risk logs (Score > 80)
    const { results } = await this.db.prepare(
      `SELECT url FROM threat_logs WHERE riskScore > 80 AND timestamp > datetime('now', '-7 days')`
    ).all();

    if (!results || results.length === 0) return;

    // 2. Extract simplistic patterns (e.g., repeated substrings in subdomains)
    const substringCounts: Record<string, number> = {};
    
    results.forEach((row: any) => {
       try {
         const hostname = new URL(row.url).hostname;
         const parts = hostname.split(/[-.]/); // Split by dash or dot
         parts.forEach(p => {
            if (p.length > 3) { // Ignore short generic words
                substringCounts[p] = (substringCounts[p] || 0) + 1;
            }
         });
       } catch(e) {}
    });

    // 3. Update Dynamic Patterns Table
    // If a keyword appears in > 10% of high risk URLs, promote it to a pattern
    const threshold = Math.max(5, results.length * 0.1);
    
    for (const [sub, count] of Object.entries(substringCounts)) {
        if (count >= threshold) {
            // Check if exists
            const existing = await this.db.prepare(`SELECT id FROM dynamic_patterns WHERE value = ?`).bind(sub).first();
            if (!existing) {
                await this.db.prepare(
                    `INSERT INTO dynamic_patterns (patternType, value, riskWeight, confidence) VALUES ('keyword', ?, 20, 0.5)`
                ).bind(sub).run();
            }
        }
    }
  }

  // --------------------------------------------------------------------------
  // RUNTIME CHECK
  // --------------------------------------------------------------------------
  async getDynamicPatterns(): Promise<string[]> {
      if (!this.db) return [];
      try {
          const { results } = await this.db.prepare(`SELECT value FROM dynamic_patterns WHERE riskWeight > 15`).all();
          return results.map((r: any) => r.value);
      } catch (e) {
          return [];
      }
  }
}
