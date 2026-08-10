export type Algorithm = "SHA1" | "SHA256" | "SHA512";

export interface TotpEntry {
  id: number;
  issuer: string;
  account: string;
  label: string;
  algorithm: Algorithm;
  digits: 6 | 8;
  period: number;
  code: string;
  expiresAt: number;
  createdAt: string;
  updatedAt: string;
}

export interface EntryPayload {
  issuer?: string;
  account?: string;
  label?: string;
  secret?: string;
  algorithm?: Algorithm;
  digits?: 6 | 8;
  period?: number;
  otpauth_uri?: string;
}

export interface ExportEntry {
  issuer: string;
  account: string;
  label: string;
  secret: string;
  algorithm: Algorithm;
  digits: 6 | 8;
  period: number;
}

export interface ExportFile {
  version: 1;
  createdAt: string;
  entries: ExportEntry[];
}

export interface ParsedOtpAuth {
  issuer: string;
  account: string;
  label: string;
  secret: string;
  algorithm: Algorithm;
  digits: 6 | 8;
  period: number;
}
