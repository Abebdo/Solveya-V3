
import { CONFIG } from "../config";

export function generateId(): string {
  return crypto.randomUUID();
}

export function currentTimestamp(): number {
  return Date.now();
}

export function safeJSONParse(json: string): any | null {
  try {
    return JSON.parse(json);
  } catch {
    return null;
  }
}

export function normalizeString(input: string): string {
  return input.trim().toLowerCase().replace(/\s+/g, " ");
}

export function extractDomainFromUrl(url: string): string | null {
  try {
    const u = new URL(url);
    return u.hostname;
  } catch {
    return null;
  }
}

export async function computeHash(data: string | ArrayBuffer, algorithm: 'SHA-256' | 'MD5' = 'SHA-256'): Promise<string> {
  const buffer = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const hashBuffer = await crypto.subtle.digest(algorithm, buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
