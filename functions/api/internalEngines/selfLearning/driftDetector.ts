
import { CONFIG } from "../../config";
import { createClient } from "@supabase/supabase-js";

const supabase = createClient(CONFIG.SUPABASE_URL, CONFIG.SUPABASE_SERVICE_ROLE_KEY);

export class DriftDetector {
  static async logSignal(signalType: string, value: number) {
    if (!CONFIG.SELF_LEARNING_ENABLED) return;

    // Uncommented/Fixed Logic for Rule 0 Compliance
    try {
        await supabase.from('signal_logs').insert({
            signal: signalType,
            value,
            timestamp: new Date().toISOString()
        });
    } catch (e) {
        console.error("Failed to log signal drift:", e);
    }
  }

  static async checkDrift(signalType: string, currentValue: number): Promise<boolean> {
    const historicalAvg = 50;
    const stdDev = 10;

    if (Math.abs(currentValue - historicalAvg) > 2 * stdDev) {
        return true;
    }
    return false;
  }
}
