
import { ScoringEngine, Signal, AnalysisResult } from "../utils/scoring";
import { ThreatFeeds } from "../utils/threatFeeds";

export class CompanyEngine {
  static async analyze(companyName: string, domain: string): Promise<AnalysisResult> {
      const signals: Signal[] = [];
      const evidence: string[] = [];

      const threat = await ThreatFeeds.checkDomain(domain);
      if (threat) {
          signals.push({ type: "KNOWN_BAD_DOMAIN", description: "Domain is in threat lists", severity: "HIGH", score: 90 });
          evidence.push(`Threat feed match: ${threat.indicator}`);
      }

      const socialScore = await this.simulateSocialCrawl(companyName);
      if (socialScore < 20) {
          signals.push({ type: "LOW_SOCIAL_PRESENCE", description: "Company has little to no social footprint", severity: "MEDIUM", score: 40 });
          evidence.push(`Social Score: ${socialScore}`);
      }

      const hasSPF = await this.checkSPF(domain);
      if (!hasSPF) {
           signals.push({ type: "MISSING_AUTH_RECORDS", description: "Domain missing SPF records", severity: "MEDIUM", score: 30 });
           evidence.push("SPF check failed");
      }

      const riskResult = ScoringEngine.calculateRisk(signals);
      return {
          score: riskResult.score,
          riskLevel: riskResult.riskLevel,
          signalsDetected: signals.map(s => s.description),
          explanations: signals.map(s => `${s.type}: ${s.description}`),
          evidence,
          finalJudgment: riskResult.finalJudgment,
          recommendedAction: riskResult.recommendedAction
      };
  }

  private static async simulateSocialCrawl(name: string): Promise<number> {
      if (name.length < 4) return 10;
      return 50 + Math.floor(Math.random() * 50);
  }

  private static async checkSPF(domain: string): Promise<boolean> {
      try {
          // DoH for TXT records
          const response = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=TXT`, {
              headers: { 'Accept': 'application/dns-json' }
          });
          const data: any = await response.json();
          if (data.Answer) {
              const txtRecords = data.Answer.map((a: any) => a.data.replace(/"/g, ''));
              return txtRecords.some((r: string) => r.startsWith("v=spf1"));
          }
          return false;
      } catch (e) {
          return false;
      }
  }
}
