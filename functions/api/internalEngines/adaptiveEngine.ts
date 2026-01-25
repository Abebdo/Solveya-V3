
import { CONFIG } from "../config";
import { DriftDetector } from "./selfLearning/driftDetector";
import { RetrainScheduler } from "./selfLearning/retrainScheduler";
import { PatternStore } from "./selfLearning/patternStore";

export class AdaptiveEngine {
  static async runSelfLearningRoutine() {
      if (!CONFIG.SELF_LEARNING_ENABLED) return;

      const needsRetrain = await RetrainScheduler.shouldRetrain();
      if (needsRetrain) {
          await RetrainScheduler.triggerRetrain();
      }
  }

  static async logFeedback(id: string, actualVerdict: string, predictedVerdict: string) {
      if (actualVerdict !== predictedVerdict) {
          console.log(`Model drift/error detected for ID ${id}`);
      }
  }
}
