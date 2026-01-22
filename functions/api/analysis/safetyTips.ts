interface SafetyTip {
  warning: string;
  recommendation: string;
  explanation: string;
}

export function generateSafetyTips(verdict: string, riskScore: number, evidence: any): SafetyTip {
  let warning = "Analysis Complete.";
  let recommendation = "Proceed with standard caution.";
  let explanation = "The content appears to be safe based on our current threat database.";

  if (verdict === "Dangerous" || riskScore >= 70) {
    warning = "CRITICAL WARNING: This content is highly likely to be unsafe.";
    
    if (evidence.fileType && evidence.fileType !== "None") {
      recommendation = "Do NOT download or run this file. Delete it immediately if downloaded.";
      explanation = `The file type (${evidence.fileType}) combined with the source reputation matches known malware distribution patterns.`;
    } else if (evidence.suspectedIntent === "Phishing") {
      recommendation = "Do NOT enter any credentials. Close the tab immediately.";
      explanation = "This site exhibits strong indicators of a phishing attack designed to steal your information.";
    } else {
      recommendation = "Do not interact with this content. Block the sender/source.";
      explanation = "Multiple high-risk factors were detected including suspicious domain patterns and threat feed matches.";
    }
  } else if (verdict === "Suspicious" || riskScore >= 40) {
    warning = "Caution: Potential risk factors detected.";
    recommendation = "Verify the source independently before proceeding.";
    explanation = "While not confirmed malware, this content has characteristics often seen in scams or low-reputation sources.";
  }

  return { warning, recommendation, explanation };
}
