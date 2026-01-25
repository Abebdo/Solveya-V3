
import { CONFIG } from "../config";

export type ModelType = "FAST" | "DEEP" | "SCAM" | "CODE";

export class ModelUtils {
  static selectModel(inputType: string, complexity: number): ModelType {
    if (inputType === "code" || complexity > 80) return "CODE";
    if (inputType === "url" && complexity > 50) return "DEEP";
    if (inputType === "message") return "SCAM";
    return "FAST";
  }

  static async runModelInference(model: ModelType, data: any): Promise<any> {
      return {
          modelUsed: model,
          confidence: 0.85,
          prediction: "suspicious"
      };
  }
}
