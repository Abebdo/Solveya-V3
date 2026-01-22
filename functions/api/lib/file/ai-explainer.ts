// functions/api/lib/file/ai-explainer.ts

export async function generateAIExplanation(env: any, fileContext: any) {
  const prompt = `
  You are Solveya's File Forensics AI.
  Analyze this file report and provide a human-readable explanation.
  
  File Name: ${fileContext.fileName}
  Risk Score: ${fileContext.riskScore}/100
  Findings: ${JSON.stringify(fileContext.reasons)}
  Entropy: ${fileContext.evidence.entropy}
  
  Task:
  1. Summarize WHY this file is dangerous or safe.
  2. Explain technical terms (like 'entropy' or 'packed') simply.
  3. Give a clear recommendation.
  
  Output plain text (max 3 sentences).
  `;

  try {
      const response = await env.AI.run("@cf/meta/llama-3.1-8b-instruct", {
          messages: [
            { role: "system", content: "You are a security expert. Be concise." },
            { role: "user", content: prompt }
          ]
      });
      
      const raw = typeof response === 'string' ? response : (response.response || JSON.stringify(response));
      // Clean generic AI prefixes
      return raw.replace(/Here is the explanation:/i, "").trim();

  } catch (e) {
      return "AI explanation unavailable. Proceed based on risk score.";
  }
}
