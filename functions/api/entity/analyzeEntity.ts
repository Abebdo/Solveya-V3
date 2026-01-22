import { createResponse, corsHeaders, Env } from '../utils';

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  try {
    if (request.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
    
    const body = await request.json() as any;
    const companyName = body.companyName || "";
    
    // Foundation Skeleton Logic
    
    // 1. Legitimacy Indicators (Heuristic)
    const knownLegit = ['google', 'microsoft', 'apple', 'stripe', 'amazon'];
    const isKnown = knownLegit.some(n => companyName.toLowerCase().includes(n));
    
    // 2. AI Verification
    let aiReason = "Verification pending.";
    let score = 50;

    try {
        const response = await env.AI.run("@cf/meta/llama-3.1-8b-instruct", {
            messages: [
                { role: "system", content: "Verify if this company is a known legitimate entity. Return JSON { score: number, reason: string } (Low score = Safe/Legit, High score = Fake/Scam)." },
                { role: "user", content: `Company: ${companyName}` }
            ]
        });
         const raw = typeof response === 'string' ? response : (response.response || JSON.stringify(response));
        const clean = raw.replace(/```json/g, "").replace(/```/g, "").trim();
        const parsed = JSON.parse(clean);
        score = parsed.score || (isKnown ? 10 : 60);
        aiReason = parsed.reason || "AI check completed.";
    } catch (e) {
        score = isKnown ? 10 : 50;
    }
    
    return createResponse({
        success: true,
        data: {
            riskScore: score,
            riskLevel: score > 70 ? "HIGH" : "SAFE",
            summary: aiReason,
            action: score > 50 ? "Verify registration manually." : "Appears legitimate.",
            redFlags: []
        }
    });

  } catch (error) {
    return createResponse({ success: false, error: "Internal Error" }, 500);
  }
};

export const onRequestOptions: PagesFunction = async () => new Response(null, { headers: corsHeaders });
