import { createClient, SupabaseClient } from "@supabase/supabase-js";

export function getSupabase(env: any): SupabaseClient | null {
  if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE_KEY) {
    console.warn("Supabase credentials missing in environment");
    return null;
  }
  return createClient(
    env.SUPABASE_URL,
    env.SUPABASE_SERVICE_ROLE_KEY,
    { auth: { persistSession: false } }
  );
}
