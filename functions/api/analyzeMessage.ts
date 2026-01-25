
import { MessageEngine } from "./internalEngines/messageEngine";
import { AdaptiveEngine } from "./internalEngines/adaptiveEngine";

export async function onRequestPost(context: any) {
  try {
    const { message } = await context.request.json();
    if (!message) {
      return new Response(JSON.stringify({ error: "Message required" }), { status: 400 });
    }

    const result = await MessageEngine.analyze(message);

    context.waitUntil(AdaptiveEngine.runSelfLearningRoutine());

    return new Response(JSON.stringify(result), {
      headers: { "Content-Type": "application/json" }
    });
  } catch (e: any) {
    return new Response(JSON.stringify({ error: e.message }), { status: 500 });
  }
}
