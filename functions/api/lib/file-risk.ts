export interface FileRiskResult {
  score: number;
  isMalwarePrediction: boolean;
  reasons: string[];
  fileType: string | null;
}

export function predictFileRisk(urlStr: string, chainDetails?: any): FileRiskResult {
  let score = 0;
  const reasons: string[] = [];
  let fileType = null;

  try {
    const url = new URL(urlStr);
    const pathname = url.pathname.toLowerCase();
    const hostname = url.hostname.toLowerCase();
    
    // ------------------------------------------------------------------------
    // A) FILENAME INTELLIGENCE
    // ------------------------------------------------------------------------
    
    // 1. Extensions
    const dangerousExts = ['.apk', '.exe', '.zip', '.rar', '.dmg', '.scr', '.msi', '.bat'];
    const suspiciousExts = ['.pdf', '.doc', '.docx', '.xls', '.xlsx']; // Macro vectors
    
    for (const ext of dangerousExts) {
      if (pathname.endsWith(ext)) {
         fileType = ext;
         score += 50; // Base risk for dangerous type
         reasons.push(`Dangerous file type detected (${ext})`);
         break;
      }
    }
    
    // 2. Double Extensions (e.g., invoice.pdf.exe)
    // We look for patterns like .[3-4chars].[3-4chars] at the end
    if (pathname.match(/\.[a-z0-9]{3,4}\.[a-z0-9]{3,4}$/)) {
        score += 80;
        reasons.push("Double extension obfuscation detected (e.g. .pdf.exe)");
    }

    // 3. Trojan Naming Structures
    const trojanKeywords = [
        'update', 'setup', 'installer', 'patch', 'hack', 'cheat', 'crack', 
        'free-nitro', 'brand-kit', 'contract', 'invoice', 'statement', 
        'creator-app', 'support-tool', 'verify'
    ];
    
    // Extract filename from path
    const filename = pathname.split('/').pop() || "";
    
    if (fileType || score > 0) { // Only check naming if it looks like a file or we already suspect it
        for (const kw of trojanKeywords) {
            if (filename.includes(kw)) {
                score += 30;
                reasons.push(`Suspicious filename pattern ('${kw}')`);
            }
        }
    }

    // ------------------------------------------------------------------------
    // B & C) SOURCE REPUTATION & INTENT
    // ------------------------------------------------------------------------
    
    // 4. Discord/CDN Abuse Patterns
    // Attackers often use cdn.discordapp.com or similar for hosting malware
    const abuseCDNs = ['cdn.discordapp.com', 'mediafire.com', 'dropbox.com', 'mega.nz', 'drive.google.com'];
    if (abuseCDNs.some(cdn => hostname.includes(cdn))) {
        if (fileType && dangerousExts.includes(fileType)) {
            score += 40;
            reasons.push("High-risk file hosted on public CDN (common malware vector)");
        }
    }

    // 5. Generic "Download" Subdomains
    if (hostname.startsWith('download.') || hostname.includes('-download')) {
        score += 20;
    }

  } catch (e) {
      // invalid url
  }

  return {
    score: Math.min(100, score),
    isMalwarePrediction: score > 70,
    reasons,
    fileType
  };
}
