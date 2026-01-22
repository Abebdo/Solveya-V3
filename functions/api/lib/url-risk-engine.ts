
export interface UrlAnalysisComponents {
  url: string;
  riskScore: number;
  reasons: string[];
  patterns: string[];
  fileType: string | null;
  tld: string | null;
}

// ----------------------------------------------------------------------------
// LAYER A & B: PATTERNS & EXTENSIONS
// ----------------------------------------------------------------------------

export function analyzeUrlPatterns(urlStr: string): UrlAnalysisComponents {
  let score = 0;
  const reasons: string[] = [];
  const patterns: string[] = [];
  let fileType = null;
  let tld = null;

  try {
    const url = new URL(urlStr);
    const hostname = url.hostname.toLowerCase();
    const pathname = url.pathname.toLowerCase();

    // 1. TLD Analysis
    const parts = hostname.split('.');
    if (parts.length > 1) {
      tld = '.' + parts[parts.length - 1];
    }
    
    const highRiskTLDs = ['.ru', '.tk', '.ml', '.info', '.icu', '.xyz'];
    if (tld && highRiskTLDs.includes(tld)) {
      score += 20; // Base risk for TLD, user said "High Risk 70-100" if matching patterns/TLD. 
                   // But let's be additive. If just .xyz, maybe not 100. 
                   // The prompt says "Immediately mark URLs as High Risk (70–100 score) if they match... .xyz"
                   // OK, I will be strict.
      score = Math.max(score, 75); 
      reasons.push(`High-Risk TLD detected (${tld})`);
      patterns.push('High-Risk TLD');
    }

    // 2. Subdomain & Keyword Analysis
    const suspiciousKeywords = [
      'secure', 'update', 'support', 'verify', 'payout', 'claim', 'brand', 'creator', 'hub',
      'portal', 'login', 'dashboard', 'offer', 'contract', 'download',
      'creator-support', 'secure-update', 'login-verify', 'brandkit', 'influencer-support',
      'discord-secure-cdn', 'creatorapp', 'media-cdn'
    ];

    // Check hostname and parts for these keywords
    let keywordFound = false;
    const fullUrlLower = urlStr.toLowerCase();
    
    for (const kw of suspiciousKeywords) {
      // We check if the keyword appears in the hostname OR path (e.g. /brandkit-free)
      if (fullUrlLower.includes(kw)) {
        keywordFound = true;
        patterns.push(`Suspicious keyword: ${kw}`);
      }
    }

    if (keywordFound) {
      score = Math.max(score, 75); // User said 70-100 for these patterns.
      reasons.push("Suspicious domain pattern or keyword detected");
    }

    // 3. File Extension Analysis
    const dangerousExts = ['.apk', '.exe', '.zip', '.rar', '.dmg'];
    for (const ext of dangerousExts) {
      if (pathname.endsWith(ext)) {
        score = Math.max(score, 95); // User said 95 minimum.
        reasons.push(`Dangerous file extension detected (${ext})`);
        patterns.push('Malware Distribution File');
        fileType = ext;
        break; 
      }
    }

  } catch (e) {
    reasons.push("Invalid URL format");
    score += 10;
  }

  return {
    url: urlStr,
    riskScore: score,
    reasons,
    patterns,
    fileType,
    tld
  };
}

// ----------------------------------------------------------------------------
// LAYER C: SAFE BROWSING (GOOGLE)
// ----------------------------------------------------------------------------

export async function checkSafeBrowsing(url: string, apiKey?: string): Promise<{ score: number, reason?: string }> {
  if (!apiKey) return { score: 0 };

  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
  const payload = {
    client: { clientId: "solveya-scanner", clientVersion: "1.0.0" },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url }]
    }
  };

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      body: JSON.stringify(payload),
      headers: { "Content-Type": "application/json" }
    });

    if (!response.ok) return { score: 0 };

    const data: any = await response.json();
    if (data.matches && data.matches.length > 0) {
        return { 
            score: 95, 
            reason: `Flagged by Google Safe Browsing (${data.matches[0].threatType})` 
        };
    }
  } catch (e) {
    console.error("Safe Browsing Error:", e);
  }

  return { score: 0 };
}

// ----------------------------------------------------------------------------
// LAYER D: DOMAIN AGE (RDAP/WHOIS ESTIMATE)
// ----------------------------------------------------------------------------

export async function checkDomainAge(domain: string): Promise<{ ageScore: number, details: string }> {
  // Simple check via RDAP for generic TLDs. This is best-effort.
  // https://rdap.verisign.com/com/v1/domain/
  // https://rdap.org/domain/
  
  try {
    const response = await fetch(`https://rdap.org/domain/${domain}`, {
        headers: { 'Accept': 'application/rdap+json' }
    });

    if (!response.ok) {
        // If 404, might be not found or not supported. 
        // User said "No WHOIS data -> +20"
        if (response.status === 404) return { ageScore: 20, details: "No WHOIS data found" };
        return { ageScore: 0, details: "WHOIS lookup failed" };
    }

    const data: any = await response.json();
    const events = data.events || [];
    
    // Look for 'registration' or 'created'
    const regEvent = events.find((e: any) => e.eventAction === 'registration' || e.eventAction === 'last changed');
    
    if (regEvent) {
        const regDate = new Date(regEvent.eventDate);
        const now = new Date();
        const ageInMonths = (now.getTime() - regDate.getTime()) / (1000 * 60 * 60 * 24 * 30);
        
        if (ageInMonths < 6) {
            return { ageScore: 20, details: `< 6 months (${ageInMonths.toFixed(1)} months)` };
        }
        return { ageScore: 0, details: `> 6 months (${ageInMonths.toFixed(1)} months)` };
    }
    
    return { ageScore: 20, details: "Registration date not found in RDAP" };

  } catch (e) {
      return { ageScore: 0, details: "WHOIS lookup error" };
  }
}

// ----------------------------------------------------------------------------
// LAYER E: REDIRECT CHAIN
// ----------------------------------------------------------------------------

export async function traceRedirects(startUrl: string): Promise<{ chain: string[], finalUrl: string, score: number }> {
  const chain: string[] = [startUrl];
  let currentUrl = startUrl;
  let score = 0;

  try {
    // Limit to 5 hops to prevent infinite loops
    for (let i = 0; i < 5; i++) {
        const response = await fetch(currentUrl, { method: 'HEAD', redirect: 'manual' });
        
        if (response.status >= 300 && response.status < 400) {
            const loc = response.headers.get('location');
            if (loc) {
                // Resolve relative URLs
                const nextUrl = new URL(loc, currentUrl).toString();
                
                // Avoid cycles
                if (chain.includes(nextUrl)) break;
                
                chain.push(nextUrl);
                currentUrl = nextUrl;
            } else {
                break;
            }
        } else {
            break;
        }
    }
  } catch (e) {
     // Fetch failed (maybe invalid URL or network error), just return what we have
  }

  // Scoring
  // If more than 2 -> +20
  if (chain.length > 2) score += 20;

  // If final URL differs strongly (different host) -> +25
  try {
      const startHost = new URL(startUrl).hostname;
      const finalHost = new URL(currentUrl).hostname;
      if (startHost !== finalHost) score += 25;
  } catch(e) {}

  // If ends in file download -> +40
  // We check the final URL for extensions
  const dangerousExts = ['.apk', '.exe', '.zip', '.rar', '.dmg'];
  try {
      const finalPath = new URL(currentUrl).pathname.toLowerCase();
      for (const ext of dangerousExts) {
          if (finalPath.endsWith(ext)) {
              score += 40;
              break;
          }
      }
  } catch(e) {}

  return { chain, finalUrl: currentUrl, score };
}
