
import { AnalysisResult } from "../utils/scoring";

export class CorrelationEngine {
  static async correlate(message: AnalysisResult | null, urlResults: AnalysisResult[], fileResults: AnalysisResult[]) {
      let boost = 0;

      // Check message signals using string matching on 'signalsDetected'
      const urgency = message?.signalsDetected.some(s => s.toLowerCase().includes("urgency"));

      // Check URL signals
      const badUrl = urlResults.some(r => r.score > 50);

      if (urgency && badUrl) {
          boost = 20;
      }

      return boost;
  }
}
