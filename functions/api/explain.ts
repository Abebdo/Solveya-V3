
import { MessageEngine } from "./internalEngines/messageEngine";

export async function onRequestPost(context: any) {
  try {
      const { input, type } = await context.request.json();

      let result;
      if (type === 'message') result = await MessageEngine.analyze(input);
      else return new Response(JSON.stringify({ error: "Only message supported for now" }), { status: 400 });

      return new Response(JSON.stringify({
          explanation: result.explanation,
          signals: result.signals
      }), {
          headers: { "Content-Type": "application/json" }
      });

  } catch (e: any) {
    return new Response(JSON.stringify({ error: e.message }), { status: 500 });
  }
}
