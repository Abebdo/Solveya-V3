
import { Sanitizer } from "../utils/sanitization";
import { ScoringEngine, Signal, AnalysisResult } from "../utils/scoring";
import { Heuristics } from "../utils/heuristics";
import { PatternStore } from "./selfLearning/patternStore";

export class MessageEngine {
  static async analyze(messageText: string): Promise<AnalysisResult> {
    const signals: Signal[] = [];
    const evidence: string[] = [];

    const sanitized = Sanitizer.sanitizeInput(messageText);

    // Static Signatures
    const staticSignatures = [
        /verify your account/i, /urgent action/i, /bank alert/i, /suspicious activity/i,
        /confirm identity/i, /password expiry/i, /click here/i, /login now/i,
        /security update/i, /unauthorized access/i, /locked account/i, /limited access/i,
        /restore access/i, /billing error/i, /invoice attached/i, /payment overdue/i,
        /track package/i, /delivery failed/i, /win prize/i, /lottery winner/i,
        /claim reward/i, /gift card/i, /amazon update/i, /paypal alert/i,
        /netflix payment/i, /apple id/i, /microsoft support/i, /irs notification/i,
        /tax refund/i, /census bureau/i, /covid relief/i, /stimulus check/i,
        /loan approval/i, /low interest/i, /debt forgiveness/i, /charity donation/i,
        /help me/i, /stranded traveler/i, /ceo scam/i, /wire transfer/i,
        /bitcoin payment/i, /crypto wallet/i, /wallet connect/i, /seed phrase/i,
        /metamask alert/i, /coinbase support/i, /binance verification/i, /romance scam/i,
        /investment opportunity/i, /guaranteed return/i
    ];

    for (const sig of staticSignatures) {
        if (sig.test(sanitized)) {
            signals.push({
                type: "STATIC_SIG",
                description: `Matched signature: ${sig.source}`,
                severity: "HIGH",
                score: 10
            });
            evidence.push(`Found pattern: ${sig.source}`);
        }
    }

    const heuristicRes = Heuristics.analyzeTextHeuristics(sanitized);
    if (heuristicRes.score > 0) {
        signals.push({
            type: "HEURISTIC",
            description: "Heuristic anomalies detected",
            severity: "MEDIUM",
            score: heuristicRes.score
        });
        evidence.push(...heuristicRes.matches);
    }

    if (/urgent|immediately|now/.test(sanitized)) {
        signals.push({ type: "PSYCH_URGENCY", description: "High urgency detected", severity: "MEDIUM", score: 15 });
        evidence.push("Urgency keywords found");
    }
    if (/fear|risk|loss|jail|warrant/.test(sanitized)) {
        signals.push({ type: "PSYCH_FEAR", description: "Fear triggers detected", severity: "HIGH", score: 20 });
        evidence.push("Fear triggers found");
    }

    const riskResult = ScoringEngine.calculateRisk(signals);

    const explanations = signals.map(s => `${s.type}: ${s.description}`);

    return {
        score: riskResult.score,
        riskLevel: riskResult.riskLevel,
        signalsDetected: signals.map(s => s.description),
        explanations,
        evidence,
        finalJudgment: riskResult.finalJudgment,
        recommendedAction: riskResult.recommendedAction
    };
  }
}
