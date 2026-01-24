
import { FileEngine } from "./internalEngines/fileEngine";
import { AdaptiveEngine } from "./internalEngines/adaptiveEngine";

export async function onRequestPost(context: any) {
  try {
    const formData = await context.request.formData();
    const file = formData.get("file");

    if (!file || !(file instanceof File)) {
      return new Response(JSON.stringify({ error: "File required" }), { status: 400 });
    }

    const buffer = await file.arrayBuffer();
    const result = await FileEngine.analyze(buffer, file.name, file.type);

    context.waitUntil(AdaptiveEngine.runSelfLearningRoutine());

    return new Response(JSON.stringify(result), {
      headers: { "Content-Type": "application/json" }
    });
  } catch (e: any) {
    return new Response(JSON.stringify({ error: e.message }), { status: 500 });
  }
}
