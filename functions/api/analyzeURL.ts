
import { URLEngine } from "./internalEngines/urlEngine";
import { AdaptiveEngine } from "./internalEngines/adaptiveEngine";

export async function onRequestPost(context: any) {
  try {
    const { url } = await context.request.json();
    if (!url) {
      return new Response(JSON.stringify({ error: "URL required" }), { status: 400 });
    }

    const result = await URLEngine.analyze(url);

    context.waitUntil(AdaptiveEngine.runSelfLearningRoutine());

    return new Response(JSON.stringify(result), {
      headers: { "Content-Type": "application/json" }
    });
  } catch (e: any) {
    return new Response(JSON.stringify({ error: e.message }), { status: 500 });
  }
}
