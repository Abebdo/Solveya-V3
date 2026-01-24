
import { Buffer } from 'node:buffer';

export class CryptoUtils {
  static async sha256(data: string | ArrayBuffer): Promise<string> {
    const buffer = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    return this.bufferToHex(hashBuffer);
  }

  static async md5(data: string | ArrayBuffer): Promise<string> {
    try {
        const crypto = await import('node:crypto');
        const hash = crypto.createHash('md5');
        const buffer = typeof data === 'string' ? Buffer.from(data) : Buffer.from(data);
        hash.update(buffer);
        return hash.digest('hex');
    } catch (e) {
        return "md5-not-supported";
    }
  }

  private static bufferToHex(buffer: ArrayBuffer): string {
    return Array.from(new Uint8Array(buffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }
}
