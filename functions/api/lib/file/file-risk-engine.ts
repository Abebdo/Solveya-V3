// functions/api/lib/file/file-risk-engine.ts

export interface AggregatedRisk {
    riskScore: number;
    riskLevel: string;
    reasons: string[];
    evidence: any;
    summary: string;
}

export function aggregateFileRisk(
    staticAnalysis: any,
    apkAnalysis: any,
    exeAnalysis: any,
    fileName: string,
    zipAnalysis?: any,
    pdfAnalysis?: any
): AggregatedRisk {
    let score = 0;
    const reasons: string[] = [];

    // 1. Static Factors
    if (staticAnalysis.isPacked) {
        score += 20;
        reasons.push("File appears packed/obfuscated");
    }
    if (staticAnalysis.embeddedUrls.length > 0) {
        score += 10;
        reasons.push("Contains embedded network URLs");
    }

    // 2. Format Specific
    if (apkAnalysis) {
        score += apkAnalysis.score;
        reasons.push(...apkAnalysis.reasons);
    }
    if (exeAnalysis) {
        score += exeAnalysis.score;
        reasons.push(...exeAnalysis.reasons);
    }
    if (zipAnalysis) {
        score += zipAnalysis.score;
        reasons.push(...zipAnalysis.reasons);
    }
    if (pdfAnalysis) {
        score += pdfAnalysis.score;
        reasons.push(...pdfAnalysis.reasons);
    }

    // 3. Filename Intelligence
    const dangerousExts = ['.exe', '.scr', '.bat', '.apk', '.vbs', '.js'];
    const ext = fileName.substring(fileName.lastIndexOf('.')).toLowerCase();
    if (dangerousExts.includes(ext)) {
        score += 30; // Base risk
        if (score > 40) score += 20; 
    }

    // Cap score
    score = Math.min(100, score);

    // Verdict
    let verdict = "SAFE";
    if (score >= 70) verdict = "CRITICAL";
    else if (score >= 40) verdict = "HIGH";
    else if (score >= 20) verdict = "MODERATE";

    return {
        riskScore: score,
        riskLevel: verdict,
        reasons: [...new Set(reasons)],
        summary: `Analysis complete. Risk Level: ${verdict}.`,
        evidence: {
            entropy: staticAnalysis.entropy.toFixed(2),
            hashes: staticAnalysis.hashes,
            imports: staticAnalysis.detectedKeywords,
            urls: staticAnalysis.embeddedUrls
        }
    };
}
