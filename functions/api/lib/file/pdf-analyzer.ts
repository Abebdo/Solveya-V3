export async function analyzePDF(fileBuffer: ArrayBuffer, staticData: any) {
    const reasons: string[] = [];
    let score = 0;

    // 1. Signature Check
    const view = new Uint8Array(fileBuffer);
    const header = new TextDecoder().decode(view.slice(0, 5));
    if (header !== "%PDF-") {
        return { score: 0, reasons: ["Invalid PDF header"] };
    }

    // 2. Keyword Analysis (Malicious Actions)
    const keywords = [
        "/JS", "/JavaScript", "/AA", "/OpenAction", "/Launch", "/SubmitForm", "/RichMedia"
    ];

    if (staticData.extractedStrings) {
        for (const kw of keywords) {
            // Check extracted strings (chunks might break keywords, so simple inclusion check on full buffer string is better if feasible)
            // But we use extracted strings for now as they cover ASCII well.
            const found = staticData.extractedStrings.some((s: string) => s.includes(kw));
            if (found) {
                score += 30;
                reasons.push(`Suspicious PDF Action detected: ${kw}`);
            }
        }
    }

    // 3. Embedded Files
    if (staticData.extractedStrings.some((s: string) => s.includes("/EmbeddedFiles"))) {
        score += 20;
        reasons.push("Contains embedded files");
    }

    return {
        score,
        reasons
    };
}
