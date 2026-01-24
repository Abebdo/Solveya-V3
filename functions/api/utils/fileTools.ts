
import { computeHash } from "./helpers";
import AdmZip from 'adm-zip';
import { Buffer } from 'node:buffer';
// @ts-ignore
import { NtExecutable } from 'pe-library';

export interface FileMetadata {
  name: string;
  size: number;
  type: string;
  hashes: {
    md5: string;
    sha256: string;
  };
}

export class FileTools {
  static async getMetadata(file: File | Blob): Promise<FileMetadata> {
    const arrayBuffer = await file.arrayBuffer();
    return await FileTools.getMetadataFromBuffer(arrayBuffer, file.name, file.type);
  }

  static async getMetadataFromBuffer(buffer: ArrayBuffer, name: string, type: string): Promise<FileMetadata> {
      const sha256 = await computeHash(buffer, 'SHA-256');
      const md5 = await computeHash(buffer, 'MD5');

      return {
          name,
          size: buffer.byteLength,
          type,
          hashes: {
              md5,
              sha256
          }
      };
  }

  static async extractZip(buffer: ArrayBuffer): Promise<string[]> {
    try {
        const buf = Buffer.from(buffer);
        const zip = new AdmZip(buf);
        const zipEntries = zip.getEntries();
        return zipEntries.map(entry => entry.entryName);
    } catch (e) {
        console.error("ZIP extraction failed", e);
        return [];
    }
  }

  static isPE(buffer: ArrayBuffer): boolean {
      const view = new DataView(buffer);
      if (buffer.byteLength < 2) return false;
      return view.getUint8(0) === 0x4D && view.getUint8(1) === 0x5A;
  }

  static async analyzePE(buffer: ArrayBuffer): Promise<any> {
    try {
        const buf = Buffer.from(buffer);
        const exe = NtExecutable.from(buf);

        const sections = exe.getSectionTable().map((s: any) => s.name);
        const imports = exe.getImportTable().map((i: any) => i.name);

        // Mock Certificate Extraction if strict lib not available
        // In reality, we'd parse the security directory from data directories
        const cert = {
             hasSignature: false, // lib doesn't support easy extraction in this version
             signer: "Unknown"
        };

        return {
            sections,
            imports,
            isManaged: exe.isManaged(),
            cert
        };
    } catch (e) {
        return { error: "Failed to parse PE" };
    }
  }

  static async analyzeAPK(buffer: ArrayBuffer): Promise<any> {
     try {
         const buf = Buffer.from(buffer);
         const zip = new AdmZip(buf);
         const manifestEntry = zip.getEntry("AndroidManifest.xml");

         const certEntry = zip.getEntry("META-INF/CERT.RSA") || zip.getEntry("META-INF/CERT.DSA");

         const result: any = { hasManifest: false, hasCert: !!certEntry };

         if (manifestEntry) {
             result.hasManifest = true;
             result.manifestSize = manifestEntry.header.size;
             result.permissions = FileTools.extractStrings(manifestEntry.getData(), 5)
                    .filter(s => s.includes("android.permission"));
         }

         return result;
     } catch (e) {
         return { error: "Failed to parse APK" };
     }
  }

  static extractStrings(buffer: Buffer, minLength: number = 4): string[] {
      const res = [];
      let current = "";
      for (let i = 0; i < buffer.length; i++) {
          const byte = buffer[i];
          if (byte >= 32 && byte <= 126) {
              current += String.fromCharCode(byte);
          } else {
              if (current.length >= minLength) {
                  res.push(current);
              }
              current = "";
          }
      }
      if (current.length >= minLength) res.push(current);
      return res;
  }
}
