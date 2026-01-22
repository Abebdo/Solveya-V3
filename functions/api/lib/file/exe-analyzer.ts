// functions/api/lib/file/exe-analyzer.ts

export async function analyzeEXE(fileBuffer: ArrayBuffer, staticData: any) {
    const view = new DataView(fileBuffer);
    const reasons: string[] = [];
    let score = 0;

    // 1. PE Header Check
    // MZ signature at 0
    if (view.getUint16(0, true) !== 0x5A4D) { 
        return { score: 0, reasons: ["Not a valid PE file"] };
    }

    // 2. Entropy Check (Packers)
    // If entropy from static analysis is high (> 7.2), likely packed
    if (staticData.entropy > 7.2) {
        score += 30;
        reasons.push("High entropy detected (Likely packed or encrypted)");
    }

    // 3. Suspicious Imports (Heuristic string match)
    const suspiciousImports = [
        "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "ShellExecute", 
        "URLDownloadToFile", "InternetOpen"
    ];

    // Check extracted keywords from static analyzer
    if (staticData.detectedKeywords) {
        const found = staticData.detectedKeywords.filter((k: string) => suspiciousImports.some(si => k.includes(si)));
        if (found.length > 0) {
            score += 40;
            reasons.push(`Suspicious API Import detected: ${found[0]}`);
        }
    }

    // 4. Anomalies
    // e.g. very small file with high entropy
    if (fileBuffer.byteLength < 50000 && staticData.entropy > 7) {
        score += 20;
        reasons.push("Small size + High entropy (Loader signature)");
    }

    return {
        score,
        reasons
    };
}
