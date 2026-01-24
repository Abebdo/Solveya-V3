
import { CONFIG } from "../../config";

export class RetrainScheduler {
  static async shouldRetrain(): Promise<boolean> {
      if (!CONFIG.WEEKLY_RETRAIN) return false;
      const lastRetrain = Date.now() - (8 * 24 * 60 * 60 * 1000);
      const now = Date.now();
      return (now - lastRetrain) > (7 * 24 * 60 * 60 * 1000);
  }

  static async triggerRetrain() {
      console.log("Triggering weekly model retraining...");
  }
}
