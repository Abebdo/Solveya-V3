import { Env, createResponse, corsHeaders } from '../utils';
import { 
  analyzeUrlPatterns, 
  checkSafeBrowsing, 
  checkDomainAge, 
  traceRedirects 
} from '../lib/url-risk-engine';
import { predictFileRisk } from '../lib/file-risk';
import { getSupabase } from '../lib/supabase-server';
import { generateSafetyTips } from '../analysis/safetyTips';
import { extractFeatures } from '../threat/selfLearning/extractFeatures';

// ----------------------------------------------------------------------------
// HELPER: DEOBFUSCATION (Requirement 3.1)
// ----------------------------------------------------------------------------
function deobfuscateURL(inputUrl: string): string {
  try {
    let processed = inputUrl;
    // 1. Decode generic URL encoding
    processed = decodeURIComponent(processed);
    
    // 2. Extract from known redirect params (e.g. ?url=, ?link=)
    // Simple regex for common open redirect patterns
    const match = processed.match(/[?&](url|link|target|dest)=([^&]+)/i);
    if (match && match[2]) {
        // Recursively decode the target
        return deobfuscateURL(match[2]);
    }
    
    // 3. Handle specific vendor wrappers (e.g. google.com/url?q=...)
    if (processed.includes("google.com/url") || processed.includes("urldefense.proofpoint.com")) {
       const qMatch = processed.match(/[?&](q|u)=([^&]+)/i);
       if (qMatch && qMatch[2]) return deobfuscateURL(qMatch[2]);
    }

    return processed;
  } catch (e) {
    return inputUrl;
  }
}

// ----------------------------------------------------------------------------
// MAIN HANDLER
// ----------------------------------------------------------------------------
export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  try {
    if (request.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

    const body = await request.json() as { url: string };
    if (!body.url) return createResponse({ success: false, error: "URL required" }, 400);

    // 1. Deobfuscation
    const cleanUrl = deobfuscateURL(body.url);

    // 2. Initialize Resources
    const supabase = getSupabase(env);
    
    // 3. Parallel Analysis Layers
    
    // Layer E: Redirects (Trace on CLEAN URL)
    const redirectData = await traceRedirects(cleanUrl);
    const finalUrl = redirectData.finalUrl;
    const finalHostname = new URL(finalUrl).hostname;

    // Layer A: Domain Threat Modeling (Patterns)
    const patternsOriginal = analyzeUrlPatterns(cleanUrl);
    const patternsFinal = analyzeUrlPatterns(finalUrl);
    
    // Layer: Download Intent Prediction (Requirement 3.3)
    const fileRisk = predictFileRisk(finalUrl, redirectData);

    // Layer D: Domain Age
    const ageData = await checkDomainAge(finalHostname);

    // Layer C: Reputation (Safe Browsing)
    const safeBrowsingKey = (env as any).GOOGLE_SAFE_BROWSING_KEY;
    const safeBrowsingData = await checkSafeBrowsing(finalUrl, safeBrowsingKey);

    // Layer F: AI Heuristic & Evidence Engine
    const features = {
        domainAge: ageData.details,
        redirectCount: redirectData.chain.length,
        hasFileRisk: fileRisk.score > 0,
        patterns: [...patternsOriginal.patterns, ...patternsFinal.patterns],
        tld: patternsFinal.tld
    };

    const aiSystemPrompt = `
    You are Solveya's "INSANE" Level Security Engine.
    Analyze this URL Context for advanced threats (Impersonation, Malware, Phishing).
    
    Context:
    - URL: ${finalUrl}
    - Deobfuscated From: ${body.url !== cleanUrl ? body.url : "N/A"}
    - Redirects: ${redirectData.chain.length} hops
    - Domain Age: ${ageData.details}
    - Patterns: ${JSON.stringify(features.patterns)}
    - File Intent: ${fileRisk.score > 0 ? "High Risk Download" : "None"}
    
    Output JSON:
    {
      "aiScore": number (0-100),
      "impersonationScore": number (0-100),
      "intent": "Phishing" | "Malware" | "Legit" | "Scam",
      "humanExplanation": "Clear, direct explanation why this is safe or dangerous.",
      "actionableTip": "Specific user instruction."
    }
    `;

    let aiResult = { aiScore: 0, impersonationScore: 0, intent: "Unknown", humanExplanation: "Analysis pending.", actionableTip: "Verify manually." };

    try {
        const aiResp = await env.AI.run("@cf/meta/llama-3.1-8b-instruct", {
            messages: [ { role: "system", content: aiSystemPrompt }, { role: "user", content: "Analyze." } ]
        });
        const raw = typeof aiResp === 'string' ? aiResp : (aiResp.response || JSON.stringify(aiResp));
        const clean = raw.replace(/```json/g, "").replace(/```/g, "").trim();
        aiResult = JSON.parse(clean);
    } catch (e) {
        console.error("AI Error", e);
    }

    // ------------------------------------------------------------------------
    // SCORING ENGINE (Requirement 3.Scoring)
    // ------------------------------------------------------------------------
    // Total = TLD + patterns + redirects + fileIntent + impersonation + reputation + AI
    
    let baseScore = Math.max(patternsOriginal.riskScore, patternsFinal.riskScore);
    
    // Penalties
    let redirectPenalty = redirectData.score; // Already calculated in engine (20-40 pts)
    let filePenalty = fileRisk.score;
    let reputationPenalty = safeBrowsingData.score;
    let aiPenalty = aiResult.aiScore;
    let impersonationPenalty = aiResult.impersonationScore;

    // Weighted Sum
    // We take the Maximum of specific critical vectors, or a weighted average of soft vectors
    const criticalVectors = [reputationPenalty, filePenalty, patternsFinal.riskScore];
    const maxCritical = Math.max(...criticalVectors);
    
    let finalScore = 0;
    
    if (maxCritical > 80) {
        finalScore = maxCritical; // Critical threat overrides everything
    } else {
        // Soft aggregation
        finalScore = (baseScore + redirectPenalty + aiPenalty + impersonationPenalty) / 2.5; 
        // Boost if multiple indicators align
        if (baseScore > 40 && aiPenalty > 40) finalScore += 20;
    }
    
    finalScore = Math.min(100, Math.round(finalScore));

    // Verdict
    let verdict = "Safe";
    if (finalScore >= 75) verdict = "Dangerous";
    else if (finalScore >= 45) verdict = "Suspicious";
    else if (finalScore >= 20) verdict = "Low Risk";

    // ------------------------------------------------------------------------
    // EVIDENCE & EXPLANATION (Requirement 3.Evidence)
    // ------------------------------------------------------------------------
    const safetyData = generateSafetyTips(verdict, finalScore, {
        fileType: fileRisk.fileType,
        suspectedIntent: aiResult.intent
    });

    const combinedReasons = [
        ...patternsFinal.reasons,
        ...fileRisk.reasons,
        safeBrowsingData.reason,
        redirectData.score > 20 ? `Suspicious redirect chain (${redirectData.chain.length} hops)` : null,
        ageData.ageScore > 20 ? "Domain is very new or hidden" : null,
        aiResult.impersonationScore > 50 ? "High likelihood of Brand Impersonation" : null
    ].filter(Boolean);

    const resultData = {
        riskScore: finalScore,
        verdict,
        summary: aiResult.humanExplanation,
        action: safetyData.recommendation,
        redFlags: combinedReasons,
        evidence: {
            domainAge: ageData.details,
            sslIssuer: "Checked via Browser", // limitation of Worker, implied valid if reachable
            redirectChain: redirectData.chain,
            filenameRisk: fileRisk.score > 0,
            impersonationScore: aiResult.impersonationScore,
            humanExplanation: aiResult.humanExplanation,
            aiHeuristicScore: aiResult.aiScore
        },
        details: {
            finalURL: finalUrl,
            redirectChain: redirectData.chain
        }
    };

    // ------------------------------------------------------------------------
    // SAVING FOR LEARNING (Requirement 3.Save)
    // ------------------------------------------------------------------------
    if (supabase) {
        // Fire and forget (don't await strictly to block response, or await if critical)
        // We'll await safely inside a try/catch block
        try {
            await supabase.from('url_scans').insert({
                url: cleanUrl,
                risk_score: finalScore,
                evidence: resultData.evidence,
                metadata: { aiIntent: aiResult.intent }
            });

            if (finalScore > 75) {
                // Save potential malicious patterns
                const tld = features.tld;
                if (tld) {
                   await supabase.from('malicious_patterns').insert({
                       pattern: tld,
                       type: 'tld',
                       evidence: { source_url: cleanUrl }
                   });
                }
            } else if (finalScore < 10) {
                 // Save safe pattern
                 const host = new URL(cleanUrl).hostname;
                 await supabase.from('safe_patterns').insert({
                     pattern: host,
                     evidence: { score: finalScore }
                 });
            }
        } catch (dbErr) {
            console.error("Supabase Log Error", dbErr);
        }
    }

    return createResponse({ success: true, data: resultData });

  } catch (error) {
    console.error("URL Analyzer Error", error);
    return createResponse({ success: false, error: "Analysis Failed" }, 500);
  }
};

export const onRequestOptions: PagesFunction = async () => new Response(null, { headers: corsHeaders });
