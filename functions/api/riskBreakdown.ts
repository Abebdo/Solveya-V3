
import { ScoringEngine } from "./utils/scoring";

export async function onRequestPost(context: any) {
  return new Response(JSON.stringify({
      factors: [
          { name: "Static Signatures", weight: "High" },
          { name: "Heuristics", weight: "Medium" },
          { name: "Behavioral", weight: "High" }
      ],
      thresholds: {
          high: 80,
          medium: 50
      }
  }), {
      headers: { "Content-Type": "application/json" }
  });
}
