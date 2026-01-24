
import { CONFIG } from "../../config";

export class DetectAnomaly {
  static async analyzeDistribution(dataPoints: number[]) {
      const mean = dataPoints.reduce((a, b) => a + b, 0) / dataPoints.length;
      const variance = dataPoints.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / dataPoints.length;
      const stdDev = Math.sqrt(variance);

      const anomalies = dataPoints.filter(x => Math.abs(x - mean) > 3 * stdDev);
      return anomalies;
  }
}
