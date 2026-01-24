
export class EntropyUtils {
  static calculateShannonEntropy(str: string): number {
    if (!str || str.length === 0) return 0;

    const frequencies = new Map<string, number>();
    for (const char of str) {
      frequencies.set(char, (frequencies.get(char) || 0) + 1);
    }

    let entropy = 0;
    const len = str.length;
    for (const count of frequencies.values()) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }

    return entropy;
  }

  static isHighEntropy(str: string, threshold: number = 4.5): boolean {
    return this.calculateShannonEntropy(str) > threshold;
  }
}
