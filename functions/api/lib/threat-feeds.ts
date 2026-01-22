// Mock implementation of daily feed sync
// In production, this would fetch from OpenPhish, PhishTank, URLHaus, etc.
// Since we are in a sandbox, we will return a static list of "Simulated Fresh Threats"

export async function fetchDailyFeeds(): Promise<string[]> {
    // Simulate async fetch
    // await new Promise(r => setTimeout(r, 100));
    
    return [
        "secure-login-apple.com",
        "verify-account-meta.net",
        "creator-support-tiktok.com",
        "update-discord-nitro.org",
        "brand-collab-manager.xyz"
    ];
}

export function checkGlobalThreats(url: string, feeds: string[]): { found: boolean, threat: string | null } {
    try {
        const hostname = new URL(url).hostname;
        for (const threat of feeds) {
            if (hostname.includes(threat)) {
                return { found: true, threat };
            }
        }
    } catch(e) {}
    
    return { found: false, threat: null };
}
