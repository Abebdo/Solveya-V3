// functions/api/threat/selfLearning/driftDetector.ts

export function detectDrift(recentScans: any[], historicalBaseline: any) {
    // Check if distribution of risk scores has shifted significantly
    const recentAvg = recentScans.reduce((sum, s) => sum + s.risk_score, 0) / recentScans.length;
    const baselineAvg = historicalBaseline.avgScore;

    if (Math.abs(recentAvg - baselineAvg) > 15) {
        return { hasDrift: true, direction: recentAvg > baselineAvg ? 'increasing_risk' : 'decreasing_risk' };
    }
    return { hasDrift: false };
}
