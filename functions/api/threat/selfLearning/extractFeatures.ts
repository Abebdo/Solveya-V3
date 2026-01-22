// functions/api/threat/selfLearning/extractFeatures.ts
// Extracts feature vectors from a URL analysis result for future training

export function extractFeatures(analysisResult: any) {
  const features = {
    redirectCount: analysisResult.redirectChain ? analysisResult.redirectChain.length : 0,
    hasHighRiskTLD: analysisResult.detectedPatterns?.includes("High-Risk TLD") ? 1 : 0,
    hasFileExtension: analysisResult.fileType && analysisResult.fileType !== "None" ? 1 : 0,
    domainAgeMonths: parseDomainAge(analysisResult.domainAge),
    aiRiskScore: analysisResult.evidence?.behavioralScore || 0,
    totalRiskScore: analysisResult.riskScore
  };
  return features;
}

function parseDomainAge(ageStr: string): number {
  if (!ageStr) return 0;
  // "Domain Age Risk: < 6 months (2.5 months)" -> 2.5
  const match = ageStr.match(/\((\d+(\.\d+)?)\s*months\)/);
  if (match) return parseFloat(match[1]);
  return 120; // Default to old/safe if unknown
}
