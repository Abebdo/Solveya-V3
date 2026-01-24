
import { EntropyUtils } from "./entropyUtils";

export class Heuristics {
  static analyzeTextHeuristics(text: string) {
    const urgencyPatterns = [
      /act now/i, /urgent/i, /immediate action/i, /account suspended/i
    ];

    let score = 0;
    const matches: string[] = [];

    urgencyPatterns.forEach(pattern => {
      if (pattern.test(text)) {
        score += 10;
        matches.push(`Urgency detected: ${pattern.source}`);
      }
    });

    const entropy = EntropyUtils.calculateShannonEntropy(text);
    if (entropy > 5.5) {
        score += 20;
        matches.push(`High entropy detected (${entropy.toFixed(2)})`);
    }

    return { score, matches };
  }
}
