// functions/api/threat/selfLearning/updatePatterns.ts
// Logic to update patterns in Supabase based on accumulated evidence

import { SupabaseClient } from "@supabase/supabase-js";

export async function updatePatterns(supabase: SupabaseClient, highRiskUrls: any[]) {
    // 1. Extract common substrings from high risk domains
    const substringCounts: Record<string, number> = {};
    
    for (const item of highRiskUrls) {
        try {
            const hostname = new URL(item.url).hostname;
            const parts = hostname.split(/[-.]/);
            parts.forEach(p => {
                if (p.length > 4 && !['com','net','org','www'].includes(p)) {
                    substringCounts[p] = (substringCounts[p] || 0) + 1;
                }
            });
        } catch(e) {}
    }

    // 2. Identify new candidates (drift detection)
    const candidates = Object.entries(substringCounts)
        .filter(([_, count]) => count > 3) // Threshold
        .map(([pattern]) => pattern);

    // 3. Insert into malicious_patterns
    for (const pattern of candidates) {
        // Check if exists
        const { data } = await supabase
            .from('malicious_patterns')
            .select('id')
            .eq('pattern', pattern)
            .single();
            
        if (!data) {
            await supabase.from('malicious_patterns').insert({
                pattern,
                type: 'keyword',
                evidence: { source: 'auto_drift_detection' },
                risk_weight: 20 // Start low, increase with confidence
            });
        }
    }
}
