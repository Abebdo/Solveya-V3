
import { ScoringEngine, AnalysisResult, Signal } from "../utils/scoring";

export class RiskEngine {
  static fusion(results: AnalysisResult[]): AnalysisResult {
    let maxScore = 0;

    // Aggregation logic
    const allSignals: string[] = [];
    const allExplanations: string[] = [];
    const allEvidence: string[] = [];

    for (const res of results) {
        if (res.score > maxScore) maxScore = res.score;
        allSignals.push(...res.signalsDetected);
        allExplanations.push(...res.explanations);
        allEvidence.push(...res.evidence);
    }

    const fusionSignal: Signal = {
        type: "AGGREGATE",
        description: "Aggregated Risk Score",
        severity: "HIGH",
        score: maxScore
    };

    const riskResult = ScoringEngine.calculateRisk([fusionSignal]);

    return {
        score: maxScore,
        riskLevel: riskResult.riskLevel,
        signalsDetected: [...new Set(allSignals)],
        explanations: [...new Set(allExplanations)],
        evidence: [...new Set(allEvidence)],
        finalJudgment: riskResult.finalJudgment,
        recommendedAction: riskResult.recommendedAction
    };
  }
}
