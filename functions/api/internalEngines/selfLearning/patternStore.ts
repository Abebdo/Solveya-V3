
import { CONFIG } from "../../config";

export interface Pattern {
    id: string;
    regex?: string;
    keywords?: string[];
    weight: number;
    category: string;
}

export class PatternStore {
    private static patterns: Pattern[] = [
        { id: "p1", regex: "verify.*account", weight: 10, category: "phishing" },
        { id: "p2", keywords: ["urgent", "suspend"], weight: 5, category: "scam" }
    ];

    static async getPatterns(category?: string): Promise<Pattern[]> {
        if (category) {
            return this.patterns.filter(p => p.category === category);
        }
        return this.patterns;
    }

    static async updatePatternWeight(id: string, newWeight: number) {
        const p = this.patterns.find(x => x.id === id);
        if (p) p.weight = newWeight;
    }
}
