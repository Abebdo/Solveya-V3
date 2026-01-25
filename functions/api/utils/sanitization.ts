
import { normalizeString } from "./helpers";

export class Sanitizer {
  static sanitizeInput(input: string): string {
    if (!input) return "";
    let sanitized = input;

    // 1. Trim whitespace
    sanitized = sanitized.trim();

    // 2. Remove null bytes
    sanitized = sanitized.replace(/\0/g, "");

    // 3. Normalize Unicode (NFKC)
    sanitized = sanitized.normalize("NFKC");

    return sanitized;
  }

  static escapeHtml(str: string): string {
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  static tokenize(text: string): string[] {
    const normalized = normalizeString(text);
    return normalized.split(" ").filter(t => t.length > 0);
  }

  static removePunctuation(text: string): string {
    return text.replace(/[.,\/#!$%\^&\*;:{}=\-_`~()]/g, "");
  }

  static normalizeUrl(url: string): string {
      try {
          if (!url.startsWith('http://') && !url.startsWith('https://')) {
              url = 'http://' + url;
          }
          const u = new URL(url);
          return u.href;
      } catch (e) {
          return url;
      }
  }
}
