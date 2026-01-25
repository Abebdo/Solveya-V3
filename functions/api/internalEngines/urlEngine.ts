
import { URLTools } from "../utils/urlTools";
import { Sanitizer } from "../utils/sanitization";
import { ScoringEngine, Signal, AnalysisResult } from "../utils/scoring";
import { EntropyUtils } from "../utils/entropyUtils";
import { ThreatFeeds } from "../utils/threatFeeds";

export class URLEngine {
  static async analyze(url: string): Promise<AnalysisResult> {
    const signals: Signal[] = [];
    const evidence: string[] = [];

    const normalizedUrl = Sanitizer.normalizeUrl(url);
    const urlInfo = URLTools.parseURL(normalizedUrl);

    if (!urlInfo) {
         return {
             score: 0,
             riskLevel: "LOW",
             signalsDetected: ["Invalid URL"],
             explanations: ["URL could not be parsed"],
             evidence: [],
             finalJudgment: "Safe",
             recommendedAction: "Verify URL format"
         };
    }

    // 1. DNS Resolution
    const ips = await URLTools.resolveDNS(urlInfo.hostname);
    if (ips.length === 0) {
        signals.push({ type: "DNS_FAIL", description: "DNS resolution failed", severity: "LOW", score: 5 });
        evidence.push("No DNS records found");
    } else {
        evidence.push(`Resolved IPs: ${ips.join(', ')}`);
    }

    // 2. WHOIS (RDAP)
    if (urlInfo.domain) {
        const whoisData = await URLTools.getWhois(urlInfo.domain);
        if (whoisData.creationDate && whoisData.creationDate !== "Unknown") {
            const created = new Date(whoisData.creationDate).getTime();
            const ageDays = (Date.now() - created) / (1000 * 60 * 60 * 24);
            if (ageDays < 30) {
                 signals.push({ type: "NEWLY_REGISTERED", description: "Domain registered < 30 days ago", severity: "HIGH", score: 50 });
                 evidence.push(`Domain Age: ${Math.floor(ageDays)} days`);
            }
        }
    }

    // 3. SSL Parsing
    if (urlInfo.protocol === 'https:') {
        try {
            // Attempt to fetch and verify SSL handshake success (Workers handles this implicitly)
            // We can't inspect cert fields easily in Workers, but we can verify connection establishment.
            const res = await fetch(url, { method: 'HEAD' });
            if (res.ok) {
                 evidence.push("SSL Handshake Successful");
            }
        } catch (e) {
             signals.push({ type: "SSL_ERROR", description: "SSL Connection Failed", severity: "HIGH", score: 40 });
        }
    } else {
         signals.push({ type: "INSECURE_PROTOCOL", description: "Not using HTTPS", severity: "MEDIUM", score: 20 });
    }

    // 4. Redirect Chain
    const chain = await URLTools.traceRedirects(normalizedUrl);
    if (chain.length > 3) {
        signals.push({ type: "REDIRECT_CHAIN", description: "Long redirect chain", severity: "MEDIUM", score: 10 });
        evidence.push(`Redirect chain length: ${chain.length}`);
    }

    // 5. Cloaking (Double Fetch)
    try {
        const uaSignal = await URLEngine.checkCloaking(normalizedUrl);
        if (uaSignal) {
            signals.push(uaSignal);
            evidence.push("Cloaking detected via User-Agent variance");
        }
    } catch (e) {
        // Ignore fetch errors for cloaking check
    }

    // 6. Entropy
    if (EntropyUtils.isHighEntropy(urlInfo.path)) {
        signals.push({ type: "HIGH_ENTROPY", description: "High entropy in URL path", severity: "MEDIUM", score: 15 });
        evidence.push(`High entropy path: ${urlInfo.path}`);
    }

    // 7. Suspicious Query
    if (urlInfo.query.includes("redirect") || urlInfo.query.includes("return")) {
        signals.push({ type: "SUSPICIOUS_QUERY", description: "Suspicious query parameters", severity: "LOW", score: 5 });
        evidence.push("Query contains redirect/return");
    }

    // 8. Threat Feeds
    const threat = await ThreatFeeds.checkDomain(urlInfo.hostname);
    if (threat) {
        signals.push({ type: "THREAT_MATCH", description: `Matched threat feed: ${threat.category}`, severity: "CRITICAL", score: 100 });
        evidence.push(`Threat feed match: ${threat.indicator}`);
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

  private static async checkCloaking(url: string): Promise<Signal | null> {
      try {
          const headersNormal = { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36' };
          const headersBot = { 'User-Agent': 'Googlebot/2.1 (+http://www.google.com/bot.html)' };

          const [resNormal, resBot] = await Promise.all([
              fetch(url, { method: 'HEAD', headers: headersNormal }),
              fetch(url, { method: 'HEAD', headers: headersBot })
          ]);

          const lenNormal = parseInt(resNormal.headers.get('content-length') || "0");
          const lenBot = parseInt(resBot.headers.get('content-length') || "0");

          if (lenNormal > 0 && lenBot > 0 && Math.abs(lenNormal - lenBot) > 500) {
              return { type: "CLOAKING_DETECTED", description: "Content varies significantly by User-Agent", severity: "HIGH", score: 70 };
          }
      } catch {
          return null;
      }
      return null;
  }
}
