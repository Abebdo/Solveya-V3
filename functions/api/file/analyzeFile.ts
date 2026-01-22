import { createResponse, corsHeaders, Env } from '../utils';
import { analyzeStatic } from '../lib/file/static-analyzer';
import { analyzeAPK } from '../lib/file/apk-analyzer';
import { analyzeEXE } from '../lib/file/exe-analyzer';
import { analyzeZIP } from '../lib/file/zip-analyzer';
import { analyzePDF } from '../lib/file/pdf-analyzer';
import { aggregateFileRisk } from '../lib/file/file-risk-engine';
import { generateAIExplanation } from '../lib/file/ai-explainer';
import { logFileScan } from '../lib/self-learning';
import { getSupabase } from '../lib/supabase-server';

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  try {
    if (request.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
    
    const body = await request.json() as any;
    const fileName = body.fileName || "";
    const contentBase64 = body.contentBase64 || "";

    if (!contentBase64) {
        const dangerousExts = ['.exe', '.scr', '.bat', '.apk'];
        const ext = fileName.substring(fileName.lastIndexOf('.')).toLowerCase();
        const isDangerousExt = dangerousExts.includes(ext);
        const riskScore = isDangerousExt ? 90 : 10;
        return createResponse({
            success: true,
            data: {
                riskScore,
                riskLevel: riskScore > 70 ? "CRITICAL" : "SAFE",
                summary: isDangerousExt ? "High risk file extension detected." : "File extension appears safe (metadata only).",
                action: isDangerousExt ? "Do not open." : "Proceed with caution.",
                redFlags: isDangerousExt ? [`Dangerous extension: ${ext}`] : [],
                evidence: { note: "Analysis limited to metadata. Upload content for full scan." }
            }
        });
    }

    // 1. Decode Buffer
    const binaryString = atob(contentBase64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    const fileBuffer = bytes.buffer;

    // 2. Static Analysis (Hash, Entropy, Strings)
    const staticData = await analyzeStatic(fileBuffer, fileName);

    // 3. Type-Specific Analysis
    let apkData = null;
    let exeData = null;
    let zipData = null;
    let pdfData = null;

    const ext = fileName.substring(fileName.lastIndexOf('.')).toLowerCase();
    
    if (ext === '.apk') {
        apkData = await analyzeAPK(fileBuffer, staticData);
    } else if (ext === '.exe' || ext === '.dll') {
        exeData = await analyzeEXE(fileBuffer, staticData);
    } else if (ext === '.zip' || ext === '.rar') {
        zipData = await analyzeZIP(fileBuffer, staticData);
    } else if (ext === '.pdf') {
        pdfData = await analyzePDF(fileBuffer, staticData);
    }

    // 4. Risk Engine Aggregation (Update engine to accept zip/pdf if needed, or pass as extra)
    // We pass them as generic extraAnalysis for now if engine signature is strict
    // Let's assume we update engine too or pass in a flexible way. 
    // Checking file-risk-engine signature: aggregateFileRisk(static, apk, exe, name).
    // I need to update file-risk-engine.ts to accept zip/pdf too.
    
    // Quick inline aggregation for ZIP/PDF score injection if I don't update engine:
    // Ideally I update the engine. I will do that in next step or assume current call is sufficient if I modify arguments.
    // I'll update the engine call here and then update the engine file.
    
    // For this step I will pass them. I need to update file-risk-engine.ts next.
    
    // Temporary Hack: Pass zipData/pdfData as apkData if needed? No, that's messy.
    // I will call `aggregateFileRisk` with extra params.
    const riskResult = aggregateFileRisk(staticData, apkData, exeData, fileName, zipData, pdfData);

    // 5. AI Reasoning Layer
    const aiExplanation = await generateAIExplanation(env, {
        fileName,
        riskScore: riskResult.riskScore,
        reasons: riskResult.reasons,
        evidence: riskResult.evidence
    });

    // 6. Supabase Logging
    const supabase = getSupabase(env);
    await logFileScan(supabase, {
        fileName,
        size: len,
        riskScore: riskResult.riskScore,
        reasons: riskResult.reasons,
        evidence: riskResult.evidence,
        aiExplanation
    });

    // 7. Response
    return createResponse({
        success: true,
        data: {
            riskScore: riskResult.riskScore,
            riskLevel: riskResult.riskLevel,
            summary: aiExplanation,
            action: riskResult.riskLevel === "CRITICAL" ? "Do NOT download or run this file." : "Proceed with caution.",
            redFlags: riskResult.reasons,
            evidence: {
                ...riskResult.evidence,
                aiExplanation
            },
            details: {
                fileType: ext,
                fileSize: len,
                hashes: staticData.hashes
            }
        }
    });

  } catch (error) {
    console.error("File Analysis Error", error);
    return createResponse({ success: false, error: "Internal Analysis Error" }, 500);
  }
};

export const onRequestOptions: PagesFunction = async () => new Response(null, { headers: corsHeaders });
