export async function analyzeZIP(fileBuffer: ArrayBuffer, staticData: any) {
    const reasons: string[] = [];
    let score = 0;

    // 1. Signature Check
    const view = new Uint8Array(fileBuffer);
    if (view[0] !== 0x50 || view[1] !== 0x4B) {
        return { score: 0, reasons: ["Invalid ZIP signature"] };
    }

    // 2. Suspicious Content Scan (Heuristic via Strings)
    // Parsing ZIP structure (Local File Headers) involves reading offsets.
    // We will use the extracted strings from static analysis to find filenames inside the zip.
    // Valid ZIP filenames often appear in plain text.
    
    const dangerousInnerExts = ['.exe', '.scr', '.bat', '.vbs', '.js'];
    
    if (staticData.extractedStrings) {
        for (const str of staticData.extractedStrings) {
            // Check if string looks like a filename
            const lower = str.toLowerCase();
            for (const ext of dangerousInnerExts) {
                if (lower.endsWith(ext)) {
                    score += 40;
                    reasons.push(`Contains executable file: ${str}`);
                    break;
                }
            }
        }
    }

    // 3. Encrypted/Password Protected
    // Check for bit flag in Local File Header (offset 6) implies encryption
    // Too complex for raw buffer heuristic without parsing relative offsets.
    // We use entropy as a proxy.
    if (staticData.entropy > 7.8) {
        score += 20;
        reasons.push("High entropy ZIP (Password protected or highly compressed)");
    }

    return {
        score,
        reasons
    };
}
