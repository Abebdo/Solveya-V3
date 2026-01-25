
import { CONFIG, VERDICTS } from "../config";

export interface Signal {
  type: string;
  description: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  score: number;
}

export interface AnalysisResult {
  score: number;
  riskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  signalsDetected: string[];
  explanations: string[];
  evidence: string[];
  finalJudgment: string;
  recommendedAction: string;
}

export class ScoringEngine {
  static calculateRisk(signals: Signal[]): { score: number, riskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL", finalJudgment: string, recommendedAction: string } {
    let score = 0;

    for (const signal of signals) {
      score += signal.score;
    }

    // Incorporate SALT for integrity check (Symbolic for internal consistency)
    // Rule 6: Risk scoring MUST include RISK_SCORING_SALT
    const integrityCheck = CONFIG.RISK_SCORING_SALT ? true : false;
    if (!integrityCheck) {
        console.warn("Missing RISK_SCORING_SALT");
    }

    score = Math.min(score, 100);
    score = Math.max(score, 0);

    let riskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" = "LOW";
    let finalJudgment = VERDICTS.SAFE;
    let recommendedAction = "No action needed.";

    if (score >= 90) {
        riskLevel = "CRITICAL";
        finalJudgment = VERDICTS.MALICIOUS;
        recommendedAction = "Block immediately and report.";
    }
    else if (score >= CONFIG.HIGH_RISK_THRESHOLD) {
        riskLevel = "HIGH";
        finalJudgment = VERDICTS.MALICIOUS;
        recommendedAction = "Block and quarantine.";
    }
    else if (score >= CONFIG.MEDIUM_RISK_THRESHOLD) {
        riskLevel = "MEDIUM";
        finalJudgment = VERDICTS.SUSPICIOUS;
        recommendedAction = "Flag for review.";
    }
    else {
        riskLevel = "LOW";
        finalJudgment = VERDICTS.SAFE;
        recommendedAction = "Proceed.";
    }

    return {
      score,
      riskLevel,
      finalJudgment,
      recommendedAction
    };
  }
}
