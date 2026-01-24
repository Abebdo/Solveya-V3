
import { FileTools } from "../utils/fileTools";
import { ScoringEngine, Signal, AnalysisResult } from "../utils/scoring";
import { CryptoUtils } from "../utils/cryptoUtils";

export class FileEngine {
  static async analyze(fileBuffer: ArrayBuffer, fileName: string, fileType: string): Promise<AnalysisResult> {
    const signals: Signal[] = [];
    const evidence: string[] = [];

    const md5 = await CryptoUtils.md5(fileBuffer);
    const sha256 = await CryptoUtils.sha256(fileBuffer);

    evidence.push(`MD5: ${md5}`);
    evidence.push(`SHA256: ${sha256}`);

    if (fileType.includes("zip")) {
        const files = await FileTools.extractZip(fileBuffer);
        if (files.some(f => f.endsWith(".exe") || f.endsWith(".js") || f.endsWith(".vbs"))) {
            signals.push({ type: "DANGEROUS_ZIP_CONTENT", description: "Zip contains executable/script", severity: "HIGH", score: 80 });
            evidence.push("Found executable content in ZIP");
        }
    }

    if (FileTools.isPE(fileBuffer)) {
        signals.push({ type: "PE_DETECTED", description: "File is a Windows Executable", severity: "MEDIUM", score: 20 });

        const peDetails = await FileTools.analyzePE(fileBuffer);
        if (peDetails.error) {
             signals.push({ type: "PE_PARSE_ERROR", description: "Malformed PE header", severity: "HIGH", score: 50 });
        } else {
            const suspiciousImports = ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"];
            const detectedImports = peDetails.imports?.filter((i: string) => suspiciousImports.some(si => i.includes(si))) || [];

            if (detectedImports.length > 0) {
                signals.push({ type: "SUSPICIOUS_IMPORTS", description: `Suspicious API imports: ${detectedImports.join(', ')}`, severity: "HIGH", score: 75 });
                evidence.push(`Imports: ${detectedImports.join(', ')}`);
            }
        }
    }

    if (fileName.endsWith(".apk")) {
        const apkDetails = await FileTools.analyzeAPK(fileBuffer);
        if (apkDetails.permissions && apkDetails.permissions.some((p: string) => p.includes("SEND_SMS") || p.includes("RECEIVE_SMS"))) {
             signals.push({ type: "DANGEROUS_PERMISSIONS", description: "APK requests SMS permissions", severity: "HIGH", score: 60 });
             evidence.push("SMS permissions found in APK");
        }
    }

    const riskResult = ScoringEngine.calculateRisk(signals);

    return {
        score: riskResult.score,
        riskLevel: riskResult.riskLevel,
        signalsDetected: signals.map(s => s.description),
        explanations: signals.map(s => `${s.type}: ${s.description}`),
        evidence,
        finalJudgment: riskResult.finalJudgment,
        recommendedAction: riskResult.recommendedAction
    };
  }
}
