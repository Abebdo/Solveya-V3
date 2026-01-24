
import { parse } from 'tldts';

export interface URLInfo {
  url: string;
  protocol: string;
  hostname: string;
  domain: string | null;
  tld: string | null;
  path: string;
  query: string;
}

export interface SSLInfo {
    valid: boolean;
    issuer: string;
    subject: string;
    validFrom: string;
    validTo: string;
}

export interface RedirectHop {
    url: string;
    status: number;
}

export class URLTools {
  static parseURL(urlStr: string): URLInfo | null {
    try {
      const url = new URL(urlStr);
      const parsed = parse(urlStr);
      return {
        url: urlStr,
        protocol: url.protocol,
        hostname: url.hostname,
        domain: parsed.domain,
        tld: parsed.publicSuffix,
        path: url.pathname,
        query: url.search
      };
    } catch {
      return null;
    }
  }

  static async resolveDNS(hostname: string): Promise<string[]> {
    try {
        const response = await fetch(`https://cloudflare-dns.com/dns-query?name=${hostname}&type=A`, {
            headers: { 'Accept': 'application/dns-json' }
        });
        const data: any = await response.json();
        if (data.Answer) {
            return data.Answer.map((a: any) => a.data);
        }
        return [];
    } catch (e) {
        return [];
    }
  }

  static async getWhois(domain: string): Promise<any> {
    // Real implementation using RDAP (Registration Data Access Protocol)
    // This replaces the "mock" mock implementation.
    try {
       const response = await fetch(`https://rdap.org/domain/${domain}`);
       if (response.ok) {
           const data = await response.json();
           return {
               creationDate: data.events?.find((e: any) => e.eventAction === 'registration')?.eventDate || "Unknown",
               registrar: data.entities?.find((e: any) => e.roles?.includes('registrar'))?.vcardArray?.[1]?.[1]?.[3] || "Unknown",
               registrantCountry: "Unknown" // RDAP often redacts this, but field exists in structure
           };
       }
       return { error: "RDAP lookup failed" };
    } catch (e) {
        return { error: "Network error during RDAP lookup" };
    }
  }

  static async traceRedirects(url: string): Promise<RedirectHop[]> {
      const hops: RedirectHop[] = [];
      let currentUrl = url;
      let count = 0;

      while(count < 10) {
          try {
              const res = await fetch(currentUrl, { method: 'HEAD', redirect: 'manual' });
              hops.push({ url: currentUrl, status: res.status });

              if (res.status >= 300 && res.status < 400) {
                  const location = res.headers.get('location');
                  if (location) {
                      currentUrl = new URL(location, currentUrl).href;
                      count++;
                  } else {
                      break;
                  }
              } else {
                  break;
              }
          } catch {
              break;
          }
      }
      return hops;
  }
}
