import { SupabaseClient } from "@supabase/supabase-js";

export async function logFileScan(supabase: SupabaseClient | null, report: any) {
    if (!supabase) return;

    try {
        await supabase.from('file_reports').insert({
            file_hash: report.evidence.hashes.sha256,
            filename: report.fileName,
            size: report.size || 0,
            result_json: report,
            risk_score: report.riskScore,
            reasons: report.reasons
        });
        
        // Add self-learning logic here (e.g. update patterns based on high risk files)
        if (report.riskScore > 80) {
            // Placeholder for pattern extraction update
        }

    } catch (e) {
        console.error("Failed to log file scan", e);
    }
}
