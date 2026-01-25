
import { MessageEngine } from "./internalEngines/messageEngine";
import { URLEngine } from "./internalEngines/urlEngine";
import { FileEngine } from "./internalEngines/fileEngine";
import { RiskEngine } from "./internalEngines/riskEngine";
import { CorrelationEngine } from "./internalEngines/correlationEngine";
import { AdaptiveEngine } from "./internalEngines/adaptiveEngine";
import { AnalysisResult } from "./utils/scoring";

export async function onRequestPost(context: any) {
  try {
    const { message, url, file } = await context.request.json();

    // Explicitly map results to ensure type safety
    let messageResult: AnalysisResult | null = null;
    let urlResult: AnalysisResult | null = null;
    let fileResult: AnalysisResult | null = null; // Assuming file support via JSON if base64 or similar, otherwise null

    const results: AnalysisResult[] = [];

    if (message) {
        messageResult = await MessageEngine.analyze(message);
        results.push(messageResult);
    }
    if (url) {
        urlResult = await URLEngine.analyze(url);
        results.push(urlResult);
    }
    // File via JSON logic (if implemented)

    const correlationScore = await CorrelationEngine.correlate(
        messageResult,
        urlResult ? [urlResult] : [],
        fileResult ? [fileResult] : []
    );

    const finalRisk = RiskEngine.fusion(results);

    if (correlationScore > 0) {
        finalRisk.score = Math.min(100, finalRisk.score + correlationScore);
        if (finalRisk.score >= 80) finalRisk.riskLevel = "CRITICAL";
    }

    context.waitUntil(AdaptiveEngine.runSelfLearningRoutine());

    return new Response(JSON.stringify({
        summary: finalRisk,
        details: results
    }), {
      headers: { "Content-Type": "application/json" }
    });
  } catch (e: any) {
    return new Response(JSON.stringify({ error: e.message }), { status: 500 });
  }
}
