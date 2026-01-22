import { createResponse, corsHeaders, Env } from '../utils';

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  try {
    if (request.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
    
    const { message } = await request.json() as { message: string };
    if (!message) return createResponse({ success: false, error: "Message required" }, 400);

    // Foundation Skeleton Logic
    // 1. Urgency Detection
    const urgencyKeywords = ['urgent', 'immediately', 'act now', 'suspended', 'unauthorized', 'expire'];
    const hasUrgency = urgencyKeywords.some(kw => message.toLowerCase().includes(kw));
    
    // 2. Scam Lexicon Matching
    const scamKeywords = ['irs', 'gift card', 'bitcoin', 'lottery', 'inheritance', 'bank account', 'verify identity'];
    const hasScamWords = scamKeywords.some(kw => message.toLowerCase().includes(kw));

    // 3. AI Analysis
    let aiScore = 0;
    let aiReason = "";
    
    try {
        const response = await env.AI.run("@cf/meta/llama-3.1-8b-instruct", {
            messages: [
                { role: "system", content: "Analyze this message for phishing/scam intent. Return JSON { score: number, reason: string }." },
                { role: "user", content: message }
            ]
        });
        const raw = typeof response === 'string' ? response : (response.response || JSON.stringify(response));
        const clean = raw.replace(/```json/g, "").replace(/```/g, "").trim();
        const parsed = JSON.parse(clean);
        aiScore = parsed.score || 0;
        aiReason = parsed.reason || "AI analysis completed.";
    } catch (e) {
        aiScore = (hasUrgency ? 50 : 0) + (hasScamWords ? 30 : 0);
        aiReason = "Heuristic fallback analysis.";
    }

    const totalScore = Math.min(100, Math.max(aiScore, (hasUrgency ? 40 : 0) + (hasScamWords ? 40 : 0)));
    
    return createResponse({
        success: true,
        data: {
            riskScore: totalScore,
            riskLevel: totalScore > 70 ? "CRITICAL" : totalScore > 40 ? "HIGH" : "SAFE",
            summary: aiReason,
            action: totalScore > 50 ? "Do not reply." : "Safe to reply.",
            redFlags: hasUrgency ? ["Urgency detected"] : []
        }
    });

  } catch (error) {
    return createResponse({ success: false, error: "Internal Error" }, 500);
  }
};

export const onRequestOptions: PagesFunction = async () => new Response(null, { headers: corsHeaders });
