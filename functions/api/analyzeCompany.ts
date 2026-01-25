
import { CompanyEngine } from "./internalEngines/companyEngine";
import { AdaptiveEngine } from "./internalEngines/adaptiveEngine";

export async function onRequestPost(context: any) {
  try {
    const { name, domain } = await context.request.json();
    if (!name || !domain) {
      return new Response(JSON.stringify({ error: "Name and Domain required" }), { status: 400 });
    }

    const result = await CompanyEngine.analyze(name, domain);

    context.waitUntil(AdaptiveEngine.runSelfLearningRoutine());

    return new Response(JSON.stringify(result), {
      headers: { "Content-Type": "application/json" }
    });
  } catch (e: any) {
    return new Response(JSON.stringify({ error: e.message }), { status: 500 });
  }
}
