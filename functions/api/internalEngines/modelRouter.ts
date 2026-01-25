
import { ModelUtils } from "../utils/modelUtils";

export class ModelRouter {
  static async route(input: any, type: "text" | "url" | "file") {
      const model = ModelUtils.selectModel(type, 0);
      return await ModelUtils.runModelInference(model, input);
  }
}
